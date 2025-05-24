import npcap_module
import datetime
import time
from parsers.ethernet import EthernetFrame
from parsers.layer3_parsers import IPv4Packet
from parsers.layer4_parsers import TCPSegment, UDPDatagram

ETH_TYPE_IP = 0x0800  # Ethertype for IPv4
IP_PROTO_TCP  = 6
IP_PROTO_UDP  = 17


PROTOCOL_PARSERS = {
    # 1: ICMPPacket,
    0x0800: IPv4Packet,      
    6: TCPSegment,    
    17: UDPDatagram,     
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
    # sniffer.filter_packets("icmp")  # Filter for IP packets
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
    eth_frame = EthernetFrame(p1.data)
    print(eth_frame)
    if eth_frame.ethertype in PROTOCOL_PARSERS:
        layer3_parser = PROTOCOL_PARSERS[eth_frame.ethertype]
        layer3_packet = layer3_parser(eth_frame.payload)
        print(layer3_packet)
    else:
        print(f"Unsupported protocol: {hex(eth_frame.ethertype)}")
    if layer3_packet.protocol in PROTOCOL_PARSERS:
        layer4_parser = PROTOCOL_PARSERS[layer3_packet.protocol]
        layer4_packet = layer4_parser(layer3_packet.payload)
        print(layer4_packet)
    else:
        print(f"Unsupported Layer 4 protocol: {layer3_packet.protocol}")
    print("Test completed successfully.")
    

if __name__ == "__main__":
    test()
