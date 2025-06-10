import struct
from typing import Optional
#includes TCP and UDP

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
    

class UDPDatagram:
    def __init__(self, data: bytes):
        if len(data) < 8:
            raise ValueError("Data is too short to be a valid UDP datagram.")
        self._raw_header = data[:8]
        self.payload = data[8:]

        (self.src_port,
         self.dest_port,
         self.length,       # UDP length includes header and payload
         self.checksum) = struct.unpack('!HHHH', self._raw_header)
        
        if self.length < 8:
            raise ValueError("UDP length is too short for a valid datagram.")
        udp_payload_length = self.length - 8

        if self.length > 8: # payload according to UDP length field
             self.payload = self.payload[:udp_payload_length]
        elif self.length == 8: # No payload 
             self.payload = b''

    def __str__(self) -> str:
        return (f"UDP Datagram:\n"
                f"  Source Port: {self.src_port}, Destination Port: {self.dest_port}\n"
                f"  Length: {self.length} bytes (Header + Payload)\n"
                f"  Checksum: {self.checksum:#06x}\n"
                f"  Payload Length: {len(self.payload)} bytes")
