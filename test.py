from wrapper import npcap_wrapper

npcap = npcap_wrapper.npcap_wrapper()


print("Available Interfaces:")
interfaces = npcap.list_interfaces()
for i, interface in enumerate(interfaces):
    print(f"{i + 1}. {interface.name} - {interface.desc} - {interface.addr}")


if interfaces:
    interface_name = interfaces[0].name
    print(f"\nOpening connection to: {interface_name}")

    # Open the selected interface
    npcap.open_connection(interface_name)

   
    npcap.filter_packets("tcp")

    # Fetch packets
    print("\nFetching a packet...")
    try:
        packet = npcap.fetch_packets()
        if packet.length > 0:
            print(f"Packet Captured! Length: {packet.length} bytes")
            print(f"Timestamp: {packet.timestamp}")
            print(f"Data (Hex): {packet.data[:20]}...")  # Print first 20 bytes
        else:
            print("No packet captured (Timeout).")
    except Exception as e:
        print(f"Error: {e}")

    # Close the connection
    npcap.close_connection()
    print("Connection closed.")
