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
        