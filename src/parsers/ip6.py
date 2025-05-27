import socket
import struct
from parsers.init import (
    ETH_TYPE_IPV6, IP_PROTO_TCP, IP_PROTO_UDP, IP_PROTO_ICMP, IP_PROTO_ICMPV6
)
class IPv6Packet:
    def __init__(self, data: bytes):
        if len(data) < 40:
            raise ValueError("IPv6 packet too short")
        self._raw_header = data[:40]
        self.payload_post_header = data[40:]   #may include extension headers
        version_tc_flow = struct.unpack('!I', self._raw_header[:4])[0]

        self.version = (version_tc_flow >> 28) & 0x0F
        self.traffic_class = (version_tc_flow >> 20) & 0xFF
        self.flow_label = version_tc_flow & 0xFFFFF

        (self.payload_length, # Length of payload *after* this 40-byte header
         self.next_header,    # Protocol of the next header (e.g., TCP, UDP, or an Extension Header)
         self.hop_limit) = struct.unpack('!HBB', self._raw_header[4:8])
        

        self.src_ip_raw = self._raw_header[8:24]
        self.src_ip = socket.inet_ntop(socket.AF_INET6, self.src_ip_raw)

        self.dest_ip_raw = self._raw_header[24:40]
        self.dest_ip = socket.inet_ntop(socket.AF_INET6, self.dest_ip_raw)

        self.final_next_header = self.next_header
        self.payload = self.payload_post_header 

        #We need to get to the L4 headers

        current_payload = self.payload_post_header
        current_next_header = self.next_header
        offset_into_payload = 0

        max_ext_headers = 10 
        ext_header_count = 0

        while ext_header_count < max_ext_headers:
            if current_next_header == IP_PROTO_TCP or \
               current_next_header == IP_PROTO_UDP or \
               current_next_header == IP_PROTO_ICMPV6:
                self.final_next_header = current_next_header
                self.payload = current_payload[offset_into_payload:]
                break
            # we just need to get to the L4 headers

            elif current_next_header == 0 or \
                 current_next_header == 43 or \
                 current_next_header == 44 or \
                 current_next_header == 50 or \
                 current_next_header == 51 or \
                 current_next_header == 60 or \
                 current_next_header == 135 or \
                 current_next_header == 139:
                if len(current_payload) < offset_into_payload + 8: # Minimum extension header size
                        # Most IPv6 headers are at least 8 bytes
                    self.payload = current_payload[offset_into_payload:] 
                    break 
                # By convention, the first byte of an IPv6 extension header is its "Next Header" field,
                next_header_in_ext = current_payload[offset_into_payload]
                #The second byte is the "Header Length" field, which is in 8-byte units. 0 = 8 bytes, 1 = 16 bytes, etc.
                hdr_ext_len_field = current_payload[offset_into_payload + 1]
                current_ext_header_total_len = (hdr_ext_len_field + 1) * 8
                # Advance our cursor
                offset_into_payload += current_ext_header_total_len
                # We loop back to check the next header
                current_next_header = next_header_in_ext 
                ext_header_count += 1

                if offset_into_payload >= len(current_payload):
                    self.payload = b'' # No payload left
                    self.final_next_header = current_next_header # Could be "No Next Header" (59)
                    break
            elif current_next_header == 59: # No Next Header
                self.final_next_header = current_next_header
                self.payload = b'' # No payload follows
                break
            else:
               
                print(f"Warning: Unknown IPv6 Next Header type: {current_next_header}")
                self.final_next_header = current_next_header
                self.payload = current_payload[offset_into_payload:] # Pass remaining as payload
                break
        else: 
            print(f"Warning: Exceeded max IPv6 extension headers to parse. Final Next Header: {current_next_header}")
            self.payload = current_payload[offset_into_payload:]
                
    def __str__(self):
        return (f"IPv6 Packet:\n"
                f"  Version: {self.version}\n"
                f"  Traffic Class: {self.traffic_class:#04x}, Flow Label: {self.flow_label:#07x}\n"
                f"  Payload Length (after main header): {self.payload_length} bytes\n"
                f"  Initial Next Header: {self.next_header}\n"
                f"  Final Next Header (after extensions): {self.final_next_header}\n"
                f"  Hop Limit: {self.hop_limit}\n"
                f"  Source IP: {self.src_ip}\n"
                f"  Destination IP: {self.dest_ip}\n"
                f"  Actual Upper-Layer Payload Length: {len(self.payload)} bytes")
                



class ICMPv6Packet:
    def __init__(self, data: bytes):
        if len(data) < 4:
            raise ValueError("ICMPv6 packet too short")
        self._raw_header = data[:8]
        (self.type, self.code, self.checksum) = struct.unpack('!BBH', self._raw_header[:4])
        self.payload = data[4:] 

        match self.type:
            case 1:  
                self.description = "Destination Unreachable"
            case 2:
                self.description = "Packet Too Big"
            case 3:
                self.description = "Time Exceeded"
            case 4:
                self.description = "Parameter Problem"
            case 128:
                self.description = "Echo Request"
            case 129:
                self.description = "Echo Reply"
            case 133:
                self.description = "Router Solicitation"
            case 134:
                self.description = "Router Advertisement"
            case 135:
                self.description = "Neighbor Solicitation"
            case 136:
                self.description = "Neighbor Advertisement"
            case 137:
                self.description = "Redirect Message"
            case _:
                self.description = f"Unknown ICMPv6 Type {self.type}"

    def __str__(self):
        return (f"ICMPv6 Packet:\n"
                f"  Type: {self.type}\n"
                f"  Code: {self.code}\n"
                f"  Description: {self.description}\n"
                f"  Checksum: {self.checksum:#06x}\n"
                f"  Payload Length: {len(self.payload)} bytes")

