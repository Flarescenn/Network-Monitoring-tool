from typing import Optional
import npcap_module
import datetime
import struct
import time

ETH_TYPE_IP = 0x0800  # Ethertype for IPv4
IP_PROTO_TCP  = 6
IP_PROTO_UDP  = 17


class EthernetFrame:
    def __init__(self, data: bytes):
        if len(data) < 14:
            raise ValueError("Data is too short to be a valid Ethernet frame.")
        self.destination_mac = data[0:6]
        self.source_mac = data[6:12]
        self.ethertype = struct.unpack('!H', data[12:14])[0]    # Big-endian format
        self.payload = data[14:]

    def __str__(self) -> str:
        return f"Ethernet Frame:\n  Destination MAC: {self.destination_mac.hex(':')}\n  Source MAC: {self.source_mac.hex(':')}\n  Ethertype: {hex(self.ethertype)}\n  Payload Length: {len(self.payload)} bytes"
        
class IPv4Packet:
    def __init__(self, data: bytes):
        if len(data) < 20:
            raise ValueError("Data is too short to be a valid IPv4 packet.")  
        self.header = data[0:20] # this excludes the options field, which is variable length
        self.ihl = (self.header[0] & 0x0F) * 4  # Internet Header Length in bytes 
        # IHL is the second half of the first byte, multiplied by 4 to get bytes
        self.options = data[20:self.ihl] if self.ihl > 20 else b'' #if no options, empty bytes
        self.payload = data[self.ihl:]
        self._parse_header()
    
    def _parse_header(self):
        # self.version = (self.header[0] >> 4) & 0x0F
        # #self.ihl = self.header[0] & 0x0F
        # self.tos = self.header[1]
        # self.total_length = struct.unpack('!H', self.header[2:4])[0]
        # self.identification = struct.unpack('!H', self.header[4:6])[0]
        # self.flags = (self.header[6] >> 5) & 0x07
        # self.fragment_offset = ((self.header[6] & 0x1F) << 8) | self.header[7]

        # We already have the first byte, so we skip it
        # !B - unsigned char (1 byte)
        # !H - unsigned short (2 bytes)
        # !4s - 4-byte raw string (for IP addresses) 
        (self.tos, self.total_length, self.id,
        self.flags_fragment_short, self.ttl, self.protocol,
        self.header_checksum, src_ip_raw, dest_ip_raw) = struct.unpack('!BHHHBBH4s4s', self.header[1:])

        self.flags_reserved = (self.flags_fragment_short >> 15) & 1 # The first bit is reserved
        self.flags_dont_fragment = (self.flags_fragment_short >> 14) & 1 # Second bit: "Don't Fragment" 
        self.flags_more_fragments = (self.flags_fragment_short >> 13) & 1 # Third bit: "More Fragments" 
        self.fragment_offset = self.flags_fragment_short & 0x1FFF   # Last 13 bits


        self.src_ip = '.'.join(map(str, src_ip_raw))  #join bytes in the dotted format
        self.dest_ip = '.'.join(map(str, dest_ip_raw))  
        
    def __str__(self) -> str:
        return (f"IPv4 Packet:\n"
                f"  Version: 4\n"
                f"  IHL: {self.ihl} bytes\n"
                f"  TOS: {self.tos}\n"
                f"  Total Length: {self.total_length} bytes\n"
                f"  Identification: {self.id}\n"
                f"  Flags: Reserved={self.flags_reserved}, Don't Fragment={self.flags_dont_fragment}, More Fragments={self.flags_more_fragments}\n"
                f"  Fragment Offset: {self.fragment_offset}\n"
                f"  TTL: {self.ttl}\n"
                f"  Protocol: {self.protocol}\n"
                f"  Header Checksum: {self.header_checksum:#04x}\n"
                f"  Source IP: {self.src_ip}\n"
                f"  Destination IP: {self.dest_ip}\n"
                f"  Options Length: {len(self.options)} bytes\n"
                f"  Payload Length: {len(self.payload)} bytes")
        


class TCPSegment:
    def __init__(self, data: bytes):
        if len(data) < 20:
            raise ValueError("Data is too short to be a valid TCP segment.")
        self.offset = (data[12] >> 4)  #First 4 bits of the 13th byte are the header-length
        self.hlength = self.offset * 4
        if len(data) < self.hlength:
            raise ValueError("Data is too short for the specified TCP header length.")
        self.header = data[0:self.hlength]  
        self.payload = data[self.hlength:]  # Payload starts after the header
        self._parse_header()

    def _parse_header(self):
        (self.src_port, self.dest_port, self.seq_num, self.ack_num,
         offset_reserved_ns_flags_short, self.window_size, self.checksum, 
         self.urgentptr) = struct.unpack('!HHIIHHHH', self.header[:20])
        
        self.flag_ns = (offset_reserved_ns_flags_short >> 8) & 0x01 # NS from the high byte (data[12])
        
        # The actual flags (CWR to FIN) are in the lower byte (data[13]) of offset_reserved_ns_flags_short
        flags_byte = offset_reserved_ns_flags_short & 0x00FF
        self.flag_cwr = (flags_byte >> 7) & 1
        self.flag_ece = (flags_byte >> 6) & 1
        self.flag_urg = (flags_byte >> 5) & 1
        self.flag_ack = (flags_byte >> 4) & 1
        self.flag_psh = (flags_byte >> 3) & 1
        self.flag_rst = (flags_byte >> 2) & 1
        self.flag_syn = (flags_byte >> 1) & 1
        self.flag_fin = flags_byte & 1

        if len(self.header) > 20:
            self.options = self.header[20:]
        else:
            self.options = b''

    def flag_str(self) -> Optional[str]:
        flags = []
        if self.flag_fin: flags.append('FIN')
        if self.flag_syn: flags.append('SYN')
        if self.flag_rst: flags.append('RST')
        if self.flag_psh: flags.append('PSH')
        if self.flag_ack: flags.append('ACK')
        if self.flag_urg: flags.append('URG')
        if self.flag_ece: flags.append("ECE")
        if self.flag_cwr: flags.append("CWR")
        if self.flag_ns: flags.append("NS")

        return ','.join(flags) if flags else None
    
    def __str__(self) -> str:
         return (f"TCP Segment:\n"
                f"  Source Port: {self.src_port}, Destination Port: {self.dest_port}\n"
                f"  Sequence Number: {self.seq_num}\n"
                f"  Acknowledgment Number: {self.ack_num}\n"
                f"  Header Length: {self.hlength} bytes (Data Offset: {self.offset} words)\n"
                f"  Flags: {self.flag_str()}\n"
                f"  Window Size: {self.window_size}\n"
                f"  Checksum: {self.checksum:#06x}\n"
                f"  Urgent Pointer: {self.urgentptr}\n"
                f"  Options Length: {len(self.options)} bytes\n"
                f"  Payload Length: {len(self.payload)} bytes")
    


        