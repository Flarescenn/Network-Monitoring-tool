# src/my_tool_package/main_app_logic.py
import time
import npcap_module # Your C++ wrapper
from protocol_stack import ProtocolStack
from analysis.top_talkers import TrafficInsights
# from .analysis.geoip_lookup import GeoIPLookup # When you create this
# from .utils.ip_utils import ReverseDNSCache # When you create this

# (Your sniffer setup and packet fetching functions)
# ... setup_sniffer_once(), fetch_next_packet(sniffer) from previous examples ...
sniffer_instance = None

def setup_sniffer():
    global sniffer_instance
    if sniffer_instance is not None:
        return sniffer_instance
    
    sniffer = npcap_module.npcap_wrapper()
    try:
        interfaces = sniffer.list_interfaces()
        if not interfaces:
            print("No network interfaces found.")
            exit(1)

        print("Available Network Interfaces:")
        for i, interface in enumerate(interfaces):
            print(f"{i+1}. Interface: {interface.name}\nDescription: {interface.desc}\nAddress: {interface.addr}\n")

        choice = int(input("Select an interface: "))
        chosen_interface_name = interfaces[choice - 1].name
        sniffer.open_connection(chosen_interface_name)
        print(f"Sniffer opened on {chosen_interface_name}. Listening for packets...")
        sniffer_instance = sniffer
        return sniffer_instance
    except Exception as e:
        print(f"Error setting up sniffer: {e}")
        if sniffer:
            sniffer.close_connection()
        exit(1)

def fetch_next_packet(sniffer):
  
    packet = sniffer.fetch_packet()
    while not (packet and packet.length > 0) :
        print(".", end="", flush=True) 
        time.sleep(0.05) # Small sleep to prevent tight loop on immediate timeouts
        packet = sniffer.fetch_packet()
    return packet

def run_capture_and_analysis(duration_seconds=30):
    global sniffer_instance # From sniffer setup
    sniffer = setup_sniffer()
    if not sniffer:
        return

    analyzer = TrafficInsights()
    # geo_lookup = GeoIPLookup() # Initialize when ready
    # rDNS_cache = ReverseDNSCache() # Initialize when ready

    print(f"Starting capture for {duration_seconds} seconds...")
    start_time = time.monotonic()
    captured_packets = [] # List to hold Packets for UI display

    try:
        while (time.monotonic() - start_time) < duration_seconds:
            raw_packet = fetch_next_packet(sniffer) 
            
            if not raw_packet or not raw_packet.data:
                continue

            # --- Parse the Packet ---
            parsed_packet = ProtocolStack(raw_packet)
            captured_packets.append(parsed_packet) 
            analyzer.process_packet(parsed_packet)
            
            # --- Live Output (Optional) ---
            print(f"\rPackets Processed: {analyzer.packet_count}, Last: {parsed_packet.summary[:100]}", end="")


            # --- Example: Resolve GeoIP/rDNS for newly seen IPs (can be slow) ---
            # if parsed_packet.network_layer and isinstance(parsed_packet.network_layer, (IPv4Packet, IPv6Packet)):
            #     src_ip = parsed_packet.network_layer.src_ip
            #     dest_ip = parsed_packet.network_layer.dest_ip
                # geo_src = geo_lookup.get_country(src_ip)
                # rDNS_src = rDNS_cache.get_hostname(src_ip)
                # print(f"Src: {src_ip} ({rDNS_src}, {geo_src})")

    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")
    finally:
        if sniffer_instance:
            print("\nClosing sniffer connection.")
            sniffer_instance.close_connection()
            sniffer_instance = None
        print("Capture finished.")

    # --- Post-Capture Analysis ---
    print("\n--- Capture Summary ---")
    summary_stats = analyzer.get_summary()
    print(f"Total Packets Captured: {summary_stats['total_packets']}")
    
    print("\nTop Source IPs (by bytes):")
    for ip, byte_count in summary_stats['top_sources']:
        print(f"  {ip}: {byte_count} bytes")

    print("\nProtocol Type Distribution (L3 from EtherType):")
    for proto, count in summary_stats['protocol_types'].items():
        print(f"  {proto}: {count} packets")

    print("\nTransport Protocol Distribution (L4 from IP):")
    for proto, count in summary_stats['transport_protocols'].items():
        print(f"  {proto}: {count} packets")

    # The captured_packets_list now holds all ParsedPacket objects.
    # This list would be the source for your Flask API to serve to React.
    # For example, you could dump it to JSON, or store it in a more persistent way.
    print(f"\nStored {len(captured_packets)} parsed packets for potential UI display.")


if __name__ == "__main__":
    # You might want to add arguments for interface selection, duration, etc.
    run_capture_and_analysis(duration_seconds=20)