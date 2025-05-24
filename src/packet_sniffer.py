import npcap_module
import numpy as np
import time
import datetime

def print_packet(packet):
    print(f"Packet Timestamp: {datetime.datetime.fromtimestamp(packet.timestamp)}")
    print(f"Packet Length: {packet.length} bytes")
    print(f"Packet Data: {packet.data.hex()}")
    print("-" * 40)


        