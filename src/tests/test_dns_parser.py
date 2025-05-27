from typing import Optional
import struct
import datetime
import struct
import npcap_module
import time

from parsers.layer2_parsers import EthernetFrame, ARPMessage
from parsers.ip4 import IPv4Packet, ICMPPacket
from parsers.layer4_parsers import TCPSegment, UDPDatagram
from parsers.dns_parser import DNSPacket
from parsers.ip6 import IPv6Packet  

from parsers import (
    ETH_TYPE_IPV4, ETH_TYPE_ARP, ETH_TYPE_VLAN, ETH_TYPE_IPV6,  IP_PROTO_TCP, IP_PROTO_UDP, IP_PROTO_ICMP, 
)

LAYER3_PARSERS_FROM_ETHERNET = {
    ETH_TYPE_IPV4: IPv4Packet,
    ETH_TYPE_ARP: ARPMessage,
    ETH_TYPE_IPV6: IPv6Packet,  
}

LAYER4_PARSERS_FROM_IP = {
    IP_PROTO_TCP: TCPSegment,
    IP_PROTO_UDP: UDPDatagram, # Ensure class name matches your file
    IP_PROTO_ICMP: ICMPPacket,
}

# --- Helper functions (keep your print_packet and fetch_one_packet_setup) ---
def print_packet_summary(timestamp, length, data_preview_hex):
    dt_object = datetime.datetime.fromtimestamp(timestamp)
    print(f"[{dt_object.strftime('%Y-%m-%d %H:%M:%S.%f')}] Len: {length:4} Data: {data_preview_hex}...")

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
        print(".", end="", flush=True) # Indicate trying
        time.sleep(0.05) # Small sleep to prevent tight loop on immediate timeouts
        packet = sniffer.fetch_packet()
    return packet

def parse_dns_packet() -> Optional[DNSPacket]:
    global sniffer_instance
    sniffer = setup_sniffer()
    if not sniffer:
        return
    found_dns_port_53 = False
    packet_count = 0

    try:
        while not found_dns_port_53:
            packet = fetch_next_packet(sniffer)
            packet_count += 1
            if not packet or not packet.data:
                print("No data in packet, retrying...")
                continue
            
            print_packet_summary(packet.timestamp, packet.length, packet.data.hex()[:32])
            

            #-----ETHERNET FRAME PARSING-----#
            try:
                eth_frame = EthernetFrame(packet.data)
                # print(eth_frame)
            except ValueError:
                continue

            if eth_frame.ethertype == ETH_TYPE_VLAN:
                print("Skipping IPv6 or VLAN packet...")
                continue

            if eth_frame.ethertype not in LAYER3_PARSERS_FROM_ETHERNET:
                print(f"Unsupported Ethertype: {hex(eth_frame.ethertype)}")
                continue

            
            #----- LAYER 3 PARSING -----#
            print(f"Processing packet {packet_count} with Ethertype: {hex(eth_frame.ethertype)}")
            layer3_packet = None
            if eth_frame.ethertype in LAYER3_PARSERS_FROM_ETHERNET:
                parser_class_l3 = LAYER3_PARSERS_FROM_ETHERNET[eth_frame.ethertype]
                try:
                    layer3_packet = parser_class_l3(eth_frame.payload)
                except ValueError:
                    print(f"  Skipping: L3 parsing failed for {parser_class_l3.__name__}.")
                    continue
            else:
                print(f"  Skipping: Unsupported EtherType {hex(eth_frame.ethertype)} for L3.")
                continue

            #----- LAYER 4 PARSING -----#
            layer4_packet = None    
            if isinstance(layer3_packet, IPv4Packet):
                if layer3_packet.protocol in LAYER4_PARSERS_FROM_IP:
                    parser_class_l4 = LAYER4_PARSERS_FROM_IP[layer3_packet.protocol]
                    print(f"Processing packet with Protocol: {layer3_packet.protocol} ({parser_class_l4.__name__})")
                    try:
                        layer4_packet = parser_class_l4(layer3_packet.payload)
                    except ValueError:
                        print(f"  Skipping: L4 parsing failed for {parser_class_l4.__name__}.")
                        continue
                else:
                    print(f"  Skipping: Unsupported IP Protocol {layer3_packet.protocol} for L4.")
                    continue 
            elif isinstance(layer3_packet, IPv6Packet):
                if layer3_packet.final_next_header in LAYER4_PARSERS_FROM_IP:
                    parser_class_l4 = LAYER4_PARSERS_FROM_IP[layer3_packet.final_next_header]
                    print(f"Processing packet with Next Header: {layer3_packet.final_next_header} ({parser_class_l4.__name__})")
                    try:
                        layer4_packet = parser_class_l4(layer3_packet.payload)
                    except ValueError:
                        print(f"  Skipping: L4 parsing failed for {parser_class_l4.__name__}.")
                        continue
            elif isinstance(layer3_packet, ARPMessage):
                print("  ARP Message, no L4 to parse for DNS.")
                continue 
            else:
                print("  Not an IPv4 packet, cannot check for DNS in L4.")
                continue
            # --- DNS Check and Parse ---

            if isinstance(layer4_packet, (UDPDatagram, TCPSegment)):
                unicast_dns_ports = {53}
                
                if layer4_packet.src_port in unicast_dns_ports or layer4_packet.dest_port in unicast_dns_ports:
                   
                    print("\n" + "="*10 + " UNICAST DNS PACKET (Port 53) FOUND! " + "="*10)
                    print_packet_summary(packet.timestamp, packet.length, packet.data[:32].hex()) # Full details of this packet
                    print(eth_frame)
                    if layer3_packet: print(layer3_packet)
                    if layer4_packet: print(layer4_packet)

                    print(f"\n--- Application Layer (Unicast DNS on Port {layer4_packet.dest_port if layer4_packet.dest_port in unicast_dns_ports else layer4_packet.src_port}) ---")
                    
                    if layer4_packet.payload:
                        try:
                            dns_data_to_parse = layer4_packet.payload
                            if isinstance(layer4_packet, TCPSegment):
                                if len(dns_data_to_parse) < 2:
                                    raise ValueError("TCP DNS data too short for 2-byte length prefix.")
                                dns_message_length = struct.unpack('!H', dns_data_to_parse[:2])[0]
                                print(f"  TCP DNS: Message length from prefix = {dns_message_length} bytes")
                                dns_data_to_parse = dns_data_to_parse[2:]
                                if len(dns_data_to_parse) < dns_message_length:
                                    print(f"  Warning: TCP DNS message data is shorter ({len(dns_data_to_parse)} bytes) than indicated ({dns_message_length} bytes).")
                            
                            dns_packet_obj = DNSPacket(dns_data_to_parse)
                            print(dns_packet_obj)
                            print("  Questions:")
                            for q in dns_packet_obj.questions: print(f"    {q}")
                            print("  Answers:")
                            for a in dns_packet_obj.answers: print(f"    {a}")
                            # Add loops for Authority and Additional records

                            found_dns_port_53 = True # Exit the while loop
                        except ValueError as e_dns:
                            print(f"Could not parse identified DNS packet: {e_dns}")
                            # Continue loop to find another one if this one failed parsing
                        except Exception as e_general_dns:
                            print(f"An unexpected error occurred during DNS parsing: {e_general_dns}")
                            # Continue loop
                    else:
                        print("  No payload in UDP/TCP segment for DNS parsing (empty DNS message?).")
                        # found_dns_port_53 = True # Or decide if an empty DNS on port 53 counts
            
            if packet_count % 100 == 0 and not found_dns_port_53: # Periodic update
                print(f"Processed {packet_count} packets, still searching for DNS on port 53...")

    except KeyboardInterrupt:
        print("\nSearch interrupted by user.")
    finally:
        if sniffer_instance:
            print("Closing sniffer connection.")
            sniffer_instance.close_connection()
            sniffer_instance = None # Reset for potential re-runs in an interactive session
        print("Exiting DNS search script.")

if __name__ == "__main__":
    parse_dns_packet()  