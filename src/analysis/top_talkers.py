from collections import Counter, defaultdict

from parsers import (
    EthernetFrame, ARPMessage, IPv4Packet, ICMPPacket,
    TCPSegment, UDPDatagram, DNSPacket, VlanTag, IPv6Packet, ICMPv6Packet,

    ETH_TYPE_IPV4, ETH_TYPE_ARP, ETH_TYPE_IPV6, ETH_TYPE_VLAN,
    IP_PROTO_ICMP, IP_PROTO_TCP, IP_PROTO_UDP, IP_PROTO_ICMPV6
)
from protocol_stack import ProtocolStack


class TrafficInsights:
    def __init__(self):
        self.src_ip_bytes = Counter()
        self.dest_ip_bytes = Counter()
        self.network_protocol = Counter() # L3: IPv4, IPv6, ARP
        self.transport_protocol = Counter() # L4: TCP, UDP, ICMP, ICMPv6
        self.conversation_bytes = Counter() # Tuple: (src_ip, dest_ip, protocol, src_port, dest_port): To keep track of bytes exchanged during a "conversation"
        self.packet_count = 0


    def process_packet(self, packet: ProtocolStack):
        self.packet_count += 1

        # Layer 2: Ethernet
        if packet.ethernet:
            eth_type_str = f"EtherType_{hex(packet.ethernet.final_ethertype)}"
            self.network_protocol[eth_type_str] += 1
            
        src_ip = None
        dest_ip = None
        src_port = None
        dest_port = None    
        transport_proto_num = None
        # Layer 3: Network Protocols
        if isinstance(packet.network_layer, (IPv4Packet, IPv6Packet)):
            ip_packet = packet.network_layer
            src_ip = ip_packet.src_ip # String representation
            dest_ip = ip_packet.dest_ip
            
            self.src_ip_bytes[src_ip] += packet.length
            self.dest_ip_bytes[dest_ip] += packet.length

            if hasattr(ip_packet, 'protocol'): # IPv4
                transport_proto_num = ip_packet.protocol
            elif hasattr(ip_packet, 'final_next_header'): # IPv6
                transport_proto_num = ip_packet.final_next_header
            
            if transport_proto_num is not None:
                self.transport_protocol[f"IP-Proto_{transport_proto_num}"] += 1

        if isinstance(packet.transport_layer, (TCPSegment, UDPDatagram)):
            transport_segment = packet.transport_layer
            src_port = transport_segment.src_port
            dest_port = transport_segment.dest_port
        elif isinstance(packet.transport_layer, (ICMPPacket, ICMPv6Packet)):
            pass # We don't really need ports for ICMP/ICMPv6


        # Conversation tracking for an ip, port, and protocol tuple
        if src_ip and dest_ip and transport_proto_num is not None:
                # This is highly simplified
            if (src_ip, src_port) > (dest_ip, dest_port):
                conv_key = (dest_ip, dest_port, src_ip, src_port, transport_proto_num)
            else:
                conv_key = (src_ip, src_port, dest_ip, dest_port, transport_proto_num)
            self.conversation_bytes[conv_key] += packet.length

    def get_top_n_src_ips(self, n=10):
        return self.src_ip_bytes.most_common(n)

    def get_top_n_dest_ips(self, n=10):
        return self.dest_ip_bytes.most_common(n)

    def get_network_protocol_distribution(self):
        return dict(self.network_protocol)

    def get_transport_protocol_distribution(self):
        return dict(self.transport_protocol)

    def get_top_n_conversations(self, n=10):
        return self.conversation_bytes.most_common(n)

    def get_summary(self):
        return {
            "total_packets": self.packet_count,
            "top_sources": self.get_top_n_src_ips(),
            "top_destinations": self.get_top_n_dest_ips(),
            "protocol_types": self.get_network_protocol_distribution(),
            "transport_protocols": self.get_transport_protocol_distribution(),
            "top_conversations": self.get_top_n_conversations()
        }

    def reset(self):
        self.src_ip_bytes.clear()
        self.dest_ip_bytes.clear()
        self.network_protocol.clear()
        self.transport_protocol.clear()
        self.conversation_bytes.clear()
        self.packet_count = 0