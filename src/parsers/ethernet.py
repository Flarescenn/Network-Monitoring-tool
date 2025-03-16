import struct

ETHERNET_HEADER_SIZE = 14

def formatted_mac(mac_bytes: bytes) -> str:
    return ':'.join(f"{b:02x}" for b in mac_bytes)   


def parse_ethernet(data: bytes) -> tuple[str, str, int]:
    
    # Ethernet frame: Dest-MAC:6B , Src-MAC:6B , Type: 2B, Payload: 46-1500B, CRC: 4B
    dest_mac, src_mac, eth_type = struct.unpack('!6s6sH', data[:ETHERNET_HEADER_SIZE])
    return formatted_mac(dest_mac), formatted_mac(src_mac), eth_type