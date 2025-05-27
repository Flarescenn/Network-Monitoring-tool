import struct
import socket
class DNSQuery:
    def __init__(self, name, qtype, qclass):
        self.name = name
        self.qtype = qtype
        self.qclass = qclass
    
    def __str__(self) -> str:
        return f"DNSQuery(name={self.name}, qtype={self.qtype}, qclass={self.qclass})"
    

class DNSResourceRecord:
    def __init__(self, name, rtype, rclass, ttl, rdlength, rdata_raw, full_dns_packet):
        self.name = name
        self.rtype = rtype
        self.rclass = rclass
        self.ttl = ttl
        self.rdlength = rdlength
        self.rdata_raw = rdata_raw
        self.full_dns_packet = full_dns_packet
        self.rdata = self._parse_rdata()

    def _parse_rdata(self)-> str:
        if self.rtype == 1 and self.rclass == 1 and self.rdlength == 4:
            # A record
            return socket.inet_ntoa(self.rdata_raw)
        elif self.rtype == 28 and self.rclass == 1 and self.rdlength == 16:
            # AAAA record
            return socket.inet_ntop(socket.AF_INET6, self.rdata_raw)
        elif self.rtype == 12: # PTR record
            try:
        # RDATA for PTR is a domain name
                name, _ = _parse_dns_name(self.rdata_raw, self.full_dns_packet, 0)
                return name
            except Exception as e:
                return f"Invalid PTR RDATA: {self.rdata_raw.hex()} (Error: {e})"
            
        elif self.rtype == 5:
            # CNAME record
            try:
                name, _ = _parse_dns_name(self.rdata_raw, self.full_dns_packet, 0)
                return name
            except Exception:
                return f"Invalid CNAME data: {self.rdata_raw.hex()}"
            
        return f"RDATA type {self.rtype}, length {self.rdlength}: {self.rdata_raw.hex()}"
    
    def __str__(self) -> str:
        return (f"DNSResourceRecord(name={self.name}, Type={self.rtype}, "
                f"Class={self.rclass}, ttl={self.ttl}, Length={self.rdlength}, "
                f"RDATA={self.rdata})")
    
def _parse_dns_name(data_segment: bytes, full_data: bytes, initial_offset:int=0) -> tuple[str, int]:
    parts = []
    offset = initial_offset # our "cursor"
    max_jumps = 5  #prevents infinite loops
    jumps_done = 0
    while True:
        if offset >= len(data_segment): #quick sanity check
            raise ValueError("DNS name parsing error: Offset out of bounds")
        length = data_segment[offset]  # Read the offset byte
        offset += 1
        if length == 0:  #Null byte indicates end of the name
            break
        elif (length & 0xC0) == 0xC0: # Pointer to other part of the packet
            if jumps_done >= max_jumps:
                raise ValueError("DNS name parsing error: Too many jumps")
            if offset >= len(data_segment):
                raise ValueError("DNS name parsing error: Pointer out of bounds")
            pointer_value = ((length & 0x3F) << 8) | data_segment[offset]
            pointed_name, _ = _parse_dns_name(full_data, full_data, pointer_value)
            parts.append(pointed_name)
            offset += 1
            jumps_done += 1
            break  # Exit after following the pointer
        elif length > 63:  # Length byte should not exceed 63
            raise ValueError(f"DNS name parsing error: Invalid length {length} at offset {offset-1}")
        else:
            if offset + length > len(data_segment):  # Check if length exceeds data segment
                raise ValueError("DNS name parsing error: Length exceeds data segment bounds")
            label_bytes = data_segment[offset:offset + length]
            try:
                label = label_bytes.decode('idna')
            except UnicodeError as e:
                label = label_bytes.decode('ascii', errors='replace')
            parts.append(label)
            offset += length
    return '.'.join(parts) if parts else ".", offset  

class DNSPacket:
    def __init__(self, data: bytes): #data is payload from tcp or udp
        if len(data) < 12:
            raise ValueError("DNS packet too short, must be at least 12 bytes")
        self._raw_data = data
        self._raw_header = data[:12]
        self._post_header = data[12:]

        """qdcount: Number of questions in the question section
        ancount: Number of RRs in the answer section
        nscount: Number of RRs in the authority section
        arcount: Number of Resource Records in the additional section
        """
        (self.id, flags, self.qdcount, self.ancount,
          self.nscount, self.arcount) = struct.unpack('!HHHHHH', self._raw_header)
        """qr: Query/Response flag (1 bit)
        opcode: Operation code (4 bits)
        aa: Authoritative Answer flag (1 bit)
        tc: Truncated flag (1 bit)
        rd: Recursion Desired flag (1 bit)
        ra: Recursion Available flag (1 bit)
        z: Reserved for future use (3 bits)
        rcode: Response code (4 bits)
        """
        self.qr = (flags >> 15) & 0x01  # Query/Response flag
        self.opcode = (flags >> 11) & 0x0F
        self.aa = (flags >> 10) & 0x01
        self.tc = (flags >> 9) & 0x01
        self.rd = (flags >> 8) & 0x01
        self.ra = (flags >> 7) & 0x01
        #self.z = (flags >> 4) & 0x07
        self.rcode = flags & 0x0F

        self.questions: list[DNSQuery] = [] 
        self.answers: list[DNSResourceRecord] = []
        self.authorities: list[DNSResourceRecord] = []
        self.additional_records: list[DNSResourceRecord] = []

        current_offset = 0

        #parse questions
        for _ in range(self.qdcount):
            if current_offset >= len(self._post_header):
                raise ValueError("DNS packet too short for questions section")
            # _parse_dns_name takes:
            # 1. The segment to read the name from (self._post_header)
            # 2. The *full original DNS packet* (self._raw_data) for pointer context
            # 3. The offset within the segment to start reading (current_offset_in_data_after_header)
            qname, post_offset= _parse_dns_name(self._post_header, self._raw_data, current_offset)
            current_offset = post_offset
            if current_offset + 4 > len(self._post_header):
                raise ValueError("DNS packet too short for question type and class")
            qtype, qclass = struct.unpack('!HH', self._post_header[current_offset:current_offset + 4])
            current_offset += 4
            self.questions.append(DNSQuery(qname, qtype, qclass))

        #parse answers
        for _ in range(self.ancount):
            if current_offset >= len(self._post_header):
                raise ValueError("DNS packet too short for answers section")
            name, post_offset = _parse_dns_name(self._post_header, self._raw_data, current_offset)
            current_offset = post_offset
            if current_offset + 10 > len(self._post_header):
                raise ValueError("DNS packet too short for answer type, class, ttl, and rdlength")
            rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', self._post_header[current_offset:current_offset + 10])
            current_offset += 10
            if current_offset + rdlength > len(self._post_header):
                raise ValueError("DNS packet too short for RDATA")
            rdata_raw = self._post_header[current_offset:current_offset + rdlength]
            current_offset += rdlength
            self.answers.append(DNSResourceRecord(name, rtype, rclass, ttl, rdlength, rdata_raw, self._raw_data))

    def __str__(self) -> str:
        return (f"DNSPacket(id={self.id}, qr={self.qr}, opcode={self.opcode}, "
                f"aa={self.aa}, tc={self.tc}, rd={self.rd}, ra={self.ra}, "
                f"rcode={self.rcode}, qdcount={self.qdcount}, ancount={self.ancount}, "
                f"nscount={self.nscount}, arcount={self.arcount})")
        