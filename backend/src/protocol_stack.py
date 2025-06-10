from parsers import (
    EthernetFrame, ARPMessage, IPv4Packet, ICMPPacket,
    TCPSegment, UDPDatagram, DNSPacket, VlanTag, IPv6Packet, ICMPv6Packet,

    ETH_TYPE_IPV4, ETH_TYPE_ARP, ETH_TYPE_IPV6, ETH_TYPE_VLAN,
    IP_PROTO_ICMP, IP_PROTO_TCP, IP_PROTO_UDP, IP_PROTO_ICMPV6
)

import npcap_module
import struct

# ETH_PARSERS = {
#     ETH_TYPE_IPV4: IPv4Packet,
#     ETH_TYPE_ARP: ARPMessage,
#     ETH_TYPE_IPV6: IPv6Packet,  
#     ETH_TYPE_VLAN: VlanTag,     # Belongs to Layer 2
# }
# PROTOCOL_PARSERS = {
#     IP_PROTO_TCP: TCPSegment,
#     IP_PROTO_UDP: UDPDatagram,
#     IP_PROTO_ICMP: ICMPPacket,  # ICMP is a Layer 3 protocol
#     IP_PROTO_ICMPV6: ICMPv6Packet,  # ICMPv6 for IPv6, also Layer 3 protocol
# }

class ProtocolStack:
    def __init__(self, raw_packet: npcap_module.packet_info) -> None:
        
        self.timestamp = raw_packet.timestamp
        self.length = raw_packet.length
        self.capture_interface = None

        self.ethernet:  EthernetFrame  | None = None
        self.network_layer: IPv4Packet | IPv6Packet | ARPMessage | None = None
        self.transport_layer: TCPSegment | UDPDatagram | ICMPPacket | ICMPv6Packet | None = None
        self.dns: DNSPacket | None = None

        self.parsing_errors: list[str] = []
        self.summary: str = ""

        self._parse(raw_packet.data)

    def _parse(self, raw_packet_data) -> None:
        #------Layer 2 parsing------#
        try:
            self.ethernet = EthernetFrame(raw_packet_data)
            self.summary = str(self.ethernet).split('\n')[0]  # Get the first line as summary
            # print(self.ethernet)
        except ValueError as e:
            self.parsing_errors.append(f"Error parsing Ethernet frame: {e}")
            return # Cannot proceed without a valid Ethernet
        
        #------- Layer 3 parsing -------#
        l3_payload = self.ethernet.payload
        eth_parse = self.ethernet.final_ethertype # Parse if VLAN

        if eth_parse == ETH_TYPE_IPV4:
            try:
                self.network_layer = IPv4Packet(l3_payload)
                self.summary += f" IPv4: {self.network_layer.src_ip} -> {self.network_layer.dest_ip}"
            except ValueError as e:
                self.parsing_errors.append(f"Error parsing IPv4 packet: {e}")
                return
        elif eth_parse == ETH_TYPE_IPV6:
            try:
                self.network_layer = IPv6Packet(l3_payload)
                self.summary += f" IPv6: {self.network_layer.src_ip} -> {self.network_layer.dest_ip}"
            except ValueError as e:
                self.parsing_errors.append(f"Error parsing IPv6 packet: {e}")
                return
        elif eth_parse == ETH_TYPE_ARP:
            try:
                self.network_layer = ARPMessage(l3_payload)
                self.summary += f" --> ARP ({self.network_layer.operation}: Who has {self.network_layer.target_ip}? Tell {self.network_layer.sender_ip})"
            except ValueError as e:
                self.parsing_errors.append(f"Error parsing ARP message: {e}")
            return
        else:
            self.parsing_errors.append(f"Unsupported EtherType for Layer 3 parsing: {hex(eth_parse)}")
            return

        #-------- Layer 4 parsing ---------#
        if not self.network_layer:
            self.parsing_errors.append("No valid Layer 3 packet found.")
            return
        l4_payload = self.network_layer.payload
        l4_protocol = None

        if isinstance(self.network_layer, IPv4Packet):
            l4_protocol = self.network_layer.protocol
        elif isinstance(self.network_layer, IPv6Packet):
            l4_protocol = self.network_layer.final_next_header

        if l4_protocol == IP_PROTO_TCP:
            try:
                self.transport_layer = TCPSegment(l4_payload)
                self.summary += f" TCP: {self.transport_layer.src_port} -> {self.transport_layer.dest_port}. Flags: {self.transport_layer.flag_str()}"
            except ValueError as e:
                self.parsing_errors.append(f"Error parsing TCP segment: {e}")
                return
        elif l4_protocol == IP_PROTO_UDP:
            try:
                self.transport_layer = UDPDatagram(l4_payload)
                self.summary += f" UDP: {self.transport_layer.src_port} -> {self.transport_layer.dest_port}"
            except ValueError as e:
                self.parsing_errors.append(f"Error parsing UDP datagram: {e}")
                return
        elif l4_protocol == IP_PROTO_ICMP:
            try:
                self.transport_layer = ICMPPacket(l4_payload)
                self.summary += f" ICMP: Type {self.transport_layer.type}"
            except ValueError as e:
                self.parsing_errors.append(f"Error parsing ICMP packet: {e}")
            return #ICMP doesn't have any application layer, so we may stop here
        
        elif l4_protocol == IP_PROTO_ICMPV6:
            try:
                self.transport_layer = ICMPv6Packet(l4_payload)
                self.summary += f" ICMPv6: Type {self.transport_layer.type}"
            except ValueError as e:
                self.parsing_errors.append(f"Error parsing ICMPv6 packet: {e}")
            return
        else:
            if l4_protocol is not None:
                self.parsing_errors.append(f"Unsupported Layer 4 protocol: {l4_protocol}")
            return # Stop if unhandled L4
        
        # ----- DNS Parsing ------ #
        dns_ports = {53, 5353} # 53 = Standard Unicast DNS, 5353 = Multicast DNS
        dns_payload = self.transport_layer.payload if self.transport_layer else None
        is_dns = False

        if isinstance(self.transport_layer, (UDPDatagram, TCPSegment)):
            if (self.transport_layer.src_port in dns_ports or
                self.transport_layer.dest_port in dns_ports):
                is_dns = True
        if is_dns and dns_payload:
            try:
                dns_data_to_parse = dns_payload
                if isinstance(self.transport_layer, TCPSegment):  # TCP's 2-byte length prefix
                    if len(dns_data_to_parse) < 2:
                        raise ValueError("TCP DNS data too short for length prefix.")
                    dns_message_length = struct.unpack('!H', dns_data_to_parse[:2])[0]
                    dns_data_to_parse = dns_data_to_parse[2:]
                    if len(dns_data_to_parse) < dns_message_length:
                        self.parsing_errors.append(f"Expected {dns_message_length}, got {len(dns_data_to_parse)}")

                self.dns = DNSPacket(dns_data_to_parse)
                self.summary += f" DNS: {self.dns.questions[0] if self.dns.questions else 'No Questions'}"
            except ValueError as e:
                self.parsing_errors.append(f"DNS Error: {e}")
            except Exception as e:
                self.parsing_errors.append(f"Unexpected error parsing DNS: {e}")


    def get_json(self) -> dict:

        # JSON for flask
        details = {"timestamp": self.timestamp, "length": self.length, "summary": self.summary}
        if self.ethernet:
            details["ethernet"] = str(self.ethernet)
        if self.network_layer:
            details["network_layer"] = str(self.network_layer)
        if self.transport_layer:
            details["transport_layer"] = str(self.transport_layer)
        if self.dns:
            details["dns"] = str(self.dns)
        if self.parsing_errors:
            details["parsing_errors"] = self.parsing_errors
        return details