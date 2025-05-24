import npcap_module
import datetime
import time
from parsers.layer2_parsers import EthernetFrame, ARPMessage
from parsers.layer3_parsers import IPv4Packet, ICMPPacket
from parsers.layer4_parsers import TCPSegment, UDPDatagram


ETH_PARSERS = {
    # 1: ICMPPacket,
    0x0800: IPv4Packet,      
    0x0806: ARPMessage,
    #0x86DD: None,  # Placeholder for IPv6, not implemented     
}
PROTOCOL_PARSERS = {
    6: TCPSegment,
    17: UDPDatagram,
    1: ICMPPacket,  # ICMP is a Layer 3 protocol
}

def print_packet(packet):
    print(f"Packet Timestamp: {datetime.datetime.fromtimestamp(packet.timestamp)}")
    print(f"Packet Length: {packet.length} bytes")
    print(f"Packet Data: {packet.data.hex()}")
    print("-" * 40)



def fetch_packet():
    
    sniffer = npcap_module.npcap_wrapper()
    interfaces = sniffer.list_interfaces()
    print("Available Network Interfaces:")
    for i, interface in enumerate(interfaces):
        print(f"{i+1}. Interface: {interface.name}\nDescription: {interface.desc}\nAddress: {interface.addr}\n")
    choice = int(input("Select an interface: "))
    sniffer.open_connection(interfaces[choice - 1].name)
    print("Listening for packets...")
    sniffer.filter_packets("icmp")  # Filter for IP packets
    packet = sniffer.fetch_packet()
    while not packet.length > 0:
        time.sleep(1)  
        print("No packet captured, retrying...")
        packet = sniffer.fetch_packet()
    print("Packet captured successfully.")
    sniffer.close_connection()
    return packet

def test():
    p1 = fetch_packet()
    print_packet(p1)
    try:
        eth_frame = EthernetFrame(p1.data)
        print(eth_frame)
    except ValueError as e:
        print(f"Error parsing Ethernet frame: {e}")
        return
    
    layer3_packet = None
    if eth_frame.ethertype in ETH_PARSERS:
        layer3_parser = ETH_PARSERS[eth_frame.ethertype]
        try:
            layer3_packet = layer3_parser(eth_frame.payload)
            print(layer3_packet)
        except ValueError as e:
            print(f"Error parsing Layer 3 packet: {e}")
            return
    else:
        print(f"Unsupported protocol: {hex(eth_frame.ethertype)}")
    if isinstance(layer3_packet, ARPMessage):
        print("Captured an ARP message, skipping Layer 4 parsing.")
        return
    if layer3_packet.protocol in PROTOCOL_PARSERS:
        layer4_parser = PROTOCOL_PARSERS[layer3_packet.protocol]
        layer4_packet = layer4_parser(layer3_packet.payload)
        print(layer4_packet)
    else:
        print(f"Unsupported Layer 4 protocol: {layer3_packet.protocol}")
    print("Test completed successfully.")
    

if __name__ == "__main__":
    test()
