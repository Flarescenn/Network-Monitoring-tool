# Start button to start the capture. It runs the capture loop. All the packets captured (are stored) are displayed on this window. (Lets call it the "packets area")
# The user can click on any packet. Which would run the parser and depict ideally EVERY info related to it. (Let's call this the "pkt-info area" in the web UI)
# We may even call the reverse DNS and GeoIP function on the said packet (because ofcourse we have their IPs etc)
# We also have a Top talkers which can be displayed in a separate part of the screen (which we will call the top talker screen)

from flask import Flask, jsonify, request, Response
# from flask_cors import CORS
import threading 
import time
from src.protocol_stack import ProtocolStack
from src.analysis.top_talkers import TrafficInsights
import npcap_module
from typing import Tuple

app = Flask(__name__)
# CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})

captured_packets = []
sniffer = None
packet_process_thread = None
is_capturing = False
traffic_analyser = TrafficInsights()

@app.route('/api/start-capture', methods = ['POST'])
def start_capture() -> Response:
    global sniffer, packet_process_thread, is_capturing
    if is_capturing:
        return jsonify({"status": "error", "message":"Capture already running"})
    try:
        sniffer = npcap_module.npcap_wrapper()
        interfaces = sniffer.list_interfaces()

        if len(interfaces) == 0:
            return jsonify({"status": "error", "message": "No interfaces found"})
        sniffer.open_connection(interfaces[4].name)

        sniffer.start_capture_loop()
        is_capturing = True
        packet_processing_thread = threading.Thread(target=process_packets, daemon=True)
        packet_processing_thread.start()

        return jsonify({
            "status": "started", 
            "message": f"Capture started",
            "interface": interfaces[4].name
        })

    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to start capture: {str(e)}"})
    
    
@app.route('/api/stop-capture', methods=['POST'])
def stop_capture() -> Response:
    global is_capturing, sniffer
    
    if not is_capturing:
        return jsonify({"status": "error", "message": "No capture running"})
    
    try:
        is_capturing = False
        
        if sniffer:
            sniffer.stop_capture_loop()
            sniffer.close_connection()
            sniffer = None
        
        return jsonify({"status": "stopped", "message": "Capture stopped successfully"})
        
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to stop capture: {str(e)}"})\
        
def process_packets() -> None:
    global captured_packets, traffic_analyzer, sniffer, is_capturing

    while is_capturing:
        try:
            if sniffer:
                queued_packets = sniffer.get_queued_packets()
                for raw_packet in queued_packets:
                    if not is_capturing:
                        break
                    parsed_packet = ProtocolStack(raw_packet)
                    captured_packets.append(parsed_packet)
                    traffic_analyser.process_packet(parsed_packet)
                    time.sleep(0.1)
            else:
                time.sleep(0.5)
        except Exception as e:
            print(f"Error processing packet {e}")
            time.sleep(1)


@app.route('/api/packets', methods=['GET'])
def get_packet()-> Response:
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 100, type=int)
    start_idx = max(0, len(captured_packets)-(page*per_page))
    end_idx = len(captured_packets) - ((page-1) * per_page) 

    current_page_packets = captured_packets[start_idx : end_idx]
    packets_data = []
    for i, packet in enumerate(current_page_packets):
        packets_data.append({
            "id": start_idx + i,
            "timestamp": packet.timestamp,
            "summary": packet.summary,
            "length": packet.length
        })
    
    return jsonify({
        "packets": packets_data, 
        "total": len(captured_packets),
        "capturing": is_capturing
    })

@app.route('/api/packet-details/<int:packet_id>', methods=['GET'])
def get_packet_details(packet_id) -> Response | Tuple[Response, int]:  
    # packet details for the pkt-info area
    if 0 <= packet_id < len(captured_packets):
        packet = captured_packets[packet_id]
        packet_details = packet.get_json()
        
        return jsonify(packet_details)
    else:
        return jsonify({"error": "Packet not found"}), 404
    

@app.route('/api/top-talkers', methods=['GET'])
def get_top_talkers() -> Response:  # top talkers for the traffic analysis screen
    if not traffic_analyser:
        return jsonify({"error": "No traffic data available"})
    
    summary = traffic_analyser.get_summary()
    return jsonify(summary)


@app.route('/api/status', methods=['GET'])
def get_status(): # capture status

    return jsonify({
        "capturing": is_capturing,
        "total_packets": len(captured_packets),
        "interfaces_available": len(sniffer.list_interfaces()) if sniffer else 0
    })