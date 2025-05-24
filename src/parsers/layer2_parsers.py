import struct

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
 
    
class ARPMessage:
    def __init__(self, data: bytes):
        if len(data) < 28:
            raise ValueError("Data is too short to be a valid ARP message.")
        (self.hardware_type, #HTYPE (1 for ethernet)
         self.protocol_type, #PTYPE (0x0800 for IPv4)
         self.hardware_addr_len, #HLEN (6 for MAC addresses)
         self.protocol_addr_len,  #PLEN (4 for IPv4 addresses)
         self.operation) = struct.unpack('!HHBBH', data[0:8])
        if self.hardware_type != 1 or self.protocol_type != 0x0800 and \
            self.hardware_addr_len != 6 or self.protocol_addr_len != 4:
            raise ValueError("Unsupported ARP hardware or protocol type.")
        self.sender_mac = data[8:14]
        self.sender_ip = data[14:18]
        self.target_mac = data[18:24]
        self.target_ip = data[24:28]


    def __str__(self) -> str:
        return (f"ARP Message:\n"
                f"  Hardware Type: {self.hardware_type}\n"
                f"  Protocol Type: {hex(self.protocol_type)}\n"
                f"  Hardware Address Length: {self.hardware_addr_len}\n"
                f"  Protocol Address Length: {self.protocol_addr_len}\n"
                f"  Operation: {self.operation}\n"
                f"  Sender MAC: {self.sender_mac.hex(':')}\n"
                f"  Sender IP: {'.'.join(map(str, self.sender_ip))}\n"
                f"  Target MAC: {self.target_mac.hex(':')}\n"
                f"  Target IP: {'.'.join(map(str, self.target_ip))}")