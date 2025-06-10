import struct

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
    

class ICMPPacket:
    def __init__(self, data: bytes):
        if len(data) < 4:
            raise ValueError("Data is too short to be a valid ICMP packet.")
        
        self.type, self.code, self.checksum = struct.unpack('!BBH', data[:4])
        self.rest_of_header = data[4:8] 
        self.payload = data[8:]

        if self.type == 8 and self.code == 0:
            self.identifier, self.sequence = struct.unpack('!HH', self.rest_of_header)
            self.description = "Echo Request"

        elif self.type == 0 and self.code == 0:
            self.identifier, self.sequence = struct.unpack('!HH', self.rest_of_header)
            self.description = "Echo Reply"

        elif self.type == 3:
            self.description = f"Destination Unreachable. Code: {self.code}"

        elif self.type == 11:
            self.description = f"Time Exceeded. Code: {self.code}"

        else:
            self.description = f"Type: {self.type}, Code: {self.code}"
            self.identifier = None
            self.sequence_number = None
        

    def __str__(self) -> str:
        s  =(f"ICMP Packet:\n"
                f"  Type: {self.type}\n"
                f"  Code: {self.code}\n"
                f"  Checksum: {self.checksum:#06x}\n")
        if self.identifier is not None and self.sequence is not None:
            s += f"  Identifier: {self.identifier}\n"
            s += f"  Sequence Number: {self.sequence}\n"
        if self.payload:
            s += f"  Payload Length: {len(self.payload)} bytes\n"
            s += f"  Payload Data: {self.payload.hex()}\n"
        return s + f"  Description: {self.description}\n"