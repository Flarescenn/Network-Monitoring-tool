import npcap_module
import datetime
import time
import socket
import struct
from parsers.layer2_parsers import EthernetFrame, ARPMessage
from parsers.ip4 import IPv4Packet, ICMPPacket
from parsers.layer4_parsers import TCPSegment, UDPDatagram
from parsers.dns_parser import DNSPacket
ETH_TYPE_IPv6 = 0x86dd
ETH_TYPE_TPID = 0x8100
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

# def send_dns_query(domain="openai.com", dns_server="8.8.8.8"):
#     print(f"Sending DNS query for {domain} to {dns_server}")
#     sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     sock.settimeout(2)

#     # Build a basic DNS query manually
#     query = b'\xaa\xbb'         # Transaction ID
#     query += b'\x01\x00'        # Standard Query
#     query += b'\x00\x01'        # QDCOUNT (1 question)
#     query += b'\x00\x00'        # ANCOUNT
#     query += b'\x00\x00'        # NSCOUNT
#     query += b'\x00\x00'        # ARCOUNT

#     for label in domain.split('.'):
#         query += bytes([len(label)]) + label.encode()
#     query += b'\x00'            # End of domain name
#     query += b'\x00\x01'        # QTYPE = A
#     query += b'\x00\x01'        # QCLASS = IN

#     sock.sendto(query, (dns_server, 53))
#     try:
#         data, _ = sock.recvfrom(512)
#         print(f"Received DNS response of length {len(data)}")
#     except socket.timeout:
#         print("DNS query timed out.")
#     sock.close()

def fetch_packet(sniffer, interfaces, choice):
    sniffer.open_connection(interfaces[choice - 1].name)
    print("Listening for packets...")
    sniffer.filter_packets("ip")  # Filter for IP packets
    sniffer.filter_packets("udp") 
    packet = sniffer.fetch_packet()
    while not packet.length > 0:
        time.sleep(1)  
        print("No packet captured, retrying...")
        packet = sniffer.fetch_packet()
    print("Packet captured successfully.")
    sniffer.close_connection()
    return packet

def test():
    sniffer = npcap_module.npcap_wrapper()
    interfaces = sniffer.list_interfaces()
    print("Available Network Interfaces:")
    for i, interface in enumerate(interfaces):
        print(f"{i+1}. Interface: {interface.name}\nDescription: {interface.desc}\nAddress: {interface.addr}\n")
    choice = int(input("Select an interface: "))
    

    eth_frame = None
    while True:
        p1 = fetch_packet(sniffer, interfaces, choice)
        print("Fetching packet...")
        # print_packet(p1)

        if not p1 or not p1.data:   #If no data, we skip the iteration
            print("No Data retrying.")
            time.sleep(0.2)
            continue

        try:
            eth_frame = EthernetFrame(p1.data)
            print(eth_frame)

        except ValueError as e:
            print(f"Error parsing Ethernet frame: {e}")
            continue

        if eth_frame.ethertype == ETH_TYPE_IPv6 or eth_frame.ethertype == ETH_TYPE_TPID:
            print("IPv6 packet or TPID packet...Skipping..")
            continue
        else:
            #eth_frame = eth_frame # Found a suitable packet
            print_packet(p1) # Print details of the packet we will process
            print(eth_frame)
            break

    #------- Layer 3 parsing -------#

    layer3_packet = None
    
    if eth_frame.ethertype in ETH_PARSERS:
        layer3_parser = ETH_PARSERS[eth_frame.ethertype]
        try:
            layer3_packet = layer3_parser(eth_frame.payload)
            print(f"\n--- Layer 3 ({layer3_parser.__name__}) ---")
            print(layer3_packet)
        except ValueError as e:
            print(f"Error parsing Layer 3 packet: {e}")
            
    else:
        print(f"\n--- Layer 3 ---")
        print(f"Unsupported EtherType for L3 parsing: {hex(eth_frame.ethertype)}")

    #-------- Layer 4 --------- #
    layer4_packet = None 
    if isinstance(layer3_packet, ARPMessage):
        print("Captured an ARP message, skipping Layer 4 parsing.")
        return
    if layer3_packet.protocol in PROTOCOL_PARSERS:
        layer4_parser = PROTOCOL_PARSERS[layer3_packet.protocol]
        try:
            layer4_packet = layer4_parser(layer3_packet.payload)
            print(f"\n--- Layer 4 ({layer4_parser.__name__}) ---")
            print(layer4_packet)
        except ValueError as e_l4:
            print(f"Error parsing Layer 4 packet ({layer4_parser.__name__}): {e_l4}")
    else:
        print(f"Unsupported Layer 4 protocol: {layer3_packet.protocol}")
    
    
    # ----- DNS Parsing ------ #
    known_dns = {53, 5353}
    is_dns = False
    if isinstance(layer4_packet, (UDPDatagram, TCPSegment)):
        # is_dns = False
        if layer4_packet.src_port in known_dns or layer4_packet.dest_port in known_dns:
            is_dns = True
            print(f"Potential DNS: {layer4_packet.src_port if layer4_packet.src_port in known_dns else layer4_packet.dest_port}")
    if is_dns:
            if layer4_packet.payload:
                try:
                    dns_data_to_parse = layer4_packet.payload
                    if isinstance(layer4_packet, TCPSegment): # Handle TCP's 2-byte length prefix
                        if len(dns_data_to_parse) < 2:
                            raise ValueError("TCP DNS data too short for length prefix.")
                        dns_message_length = struct.unpack('!H', dns_data_to_parse[:2])[0]
                        dns_data_to_parse = dns_data_to_parse[2:]
                        if len(dns_data_to_parse) < dns_message_length:
                            print(f"Warning: TCP DNS message data truncated. Expected {dns_message_length}, got {len(dns_data_to_parse)}")
                    dns_packet = DNSPacket(dns_data_to_parse)
                    print(dns_packet)
                    print("Questions: ")
                    for q in dns_packet.questions:
                        print(f"    {q}")
                    for a in dns_packet.answers:
                        print(f"    {a}")
                except ValueError as e_dns:
                    print(f"Could not parse DNS packet: {e_dns}")
    else:
            print("No DNS packet found")
    if not is_dns and isinstance(layer4_packet, (UDPDatagram, TCPSegment)) and layer4_packet.payload:
        # If it was UDP/TCP but not DNS, print generic payload
        print(f"\n--- Application Layer Data (from {type(layer4_packet).__name__} on Dst Port {layer4_packet.dest_port}) ---")
        print(f"  Payload Preview (first 32 bytes hex): {layer4_packet.payload[:32].hex()}")
        
        
    print("Test completed successfully.")

    

if __name__ == "__main__":
    test()
