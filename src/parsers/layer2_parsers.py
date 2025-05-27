import struct
from parsers.constants import ETH_TYPE_VLAN

class VlanTag:
    def __init__(self, tci_bytes: bytes):
        tci_value = struct.unpack('!H', tci_bytes)[0]
        self.pcp = (tci_value >> 13) & 0x07
        self.dei = (tci_value >> 12) & 0x01
        self.vid = tci_value & 0x0FFF

    def __str__(self):
        return f"PCP: {self.pcp}, DEI: {self.dei}, VID: {self.vid}"
    
class EthernetFrame:
    def __init__(self, data: bytes):
        if len(data) < 14:
            raise ValueError("Data is too short to be a valid Ethernet frame.")
        self.destination_mac = data[0:6]
        self.source_mac = data[6:12]
        self.ethertype = struct.unpack('!H', data[12:14])[0]    # Big-endian format
        self.vlan_tag = VlanTag | None
        if self.ethertype== ETH_TYPE_VLAN:
            if len(data) < 18:
                raise ValueError("Data is too short to contain VLAN tag.")
            self.vlan_tag = VlanTag(data[14:16])
            self.final_ethertype = struct.unpack('!H', data[16:18])[0]
            self.payload = data[18:]
        else:
            self.final_ethertype = self.ethertype
            self.payload = data[14:]

    def __str__(self) -> str:
        s = f"Ethernet Frame:\n  Destination MAC: {self.destination_mac.hex(':')}\n Source MAC: {self.source_mac.hex(':')}\n"
        if self.vlan_tag:
            s += f"  VLAN Tag: {self.vlan_tag}\n"
            s += f" TPID (EtherType): {hex(self.ethertype)}\n"
            s += f"  Final Ethertype: {hex(self.final_ethertype)}\n"
        else:
            s += f"  Ethertype: {hex(self.final_ethertype)}\n "
        s += f"  Payload Length: {len(self.payload)} bytes"
        return s

 
    
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