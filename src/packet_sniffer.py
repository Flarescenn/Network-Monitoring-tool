import socket
# from scapy.all import sniff
import 
def PacketSniffing() -> bytes:
    packets = sniff(count=1)  # Capture only 1 packet
    print(packets[0])
    return packets[0]

        