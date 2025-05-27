import npcap_module
import time
import datetime
def print_packet(packet):
    print(f"Packet Timestamp: {datetime.datetime.fromtimestamp(packet.timestamp)}")
    print(f"Packet Length: {packet.length} bytes")
    print(f"Packet Data: {packet.data.hex()}")
    print("-" * 40)
def test():
    sniffer = npcap_module.npcap_wrapper()
    interfaces = sniffer.list_interfaces()
    print("Available Network Interfaces:")
    for i, interface in enumerate(interfaces):
        
        print(f"{i+1}. Interface: {interface.name}\nDescription: {interface.desc}\nAddress: {interface.addr}\n")
    choice = int(input("Select an interface: "))
    sniffer.open_connection(interfaces[choice - 1].name)
    print("Listening for packets...")
    sniffer.start_capture_loop()

    capture_duration = 10
    update_interval = 1
    start_time = time.monotonic()
    total_packets = 0
    elapsed_time = 0
    packet_qu = []
    while elapsed_time < capture_duration:
        time.sleep(update_interval)
        elapsed_time = time.monotonic() - start_time
        packets = sniffer.get_queued_packets()
        packet_qu.extend(packets)
        total_packets += len(packets)
        print(f"Captured {len(packets)} packets in the last {update_interval} seconds. Total: {total_packets} packets.")
    print("\nStopping capture loop...")
    sniffer.stop_capture_loop() 
    packets = sniffer.get_queued_packets()
    total_packets += len(packets)
    print(f"Remaining packets in queue: {len(packets)}. Total captured packets: {total_packets}")
    packet_qu.extend(packets)
    print_packet(packet_qu[-1])  # Print the last packet captured
    print("Capture loop stopped.")
    sniffer.close_connection()

test()
