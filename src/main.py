#from protocol_parser import parse_packet
#from analysis import analyze_packet

#def process_packet(raw_data):
import argparse
import sys
import signal
from parsers import PacketSniffing
from parsers import ethernet

def signal_handler(sig, frame):
    print("\nCapture stopped by the user.")
    sys.exit(0)

def main():
    print("Network Monitor Project Initialized.")
    signal.signal(signal.SIGINT, signal_handler) #Interrupt from keyboard (CTRL + C)
    raw_data = PacketSniffing();
    dest_mac, src_mac, eth_type = ethernet.parse_ethernet(raw_data)
    print(f"Destination MAC: {dest_mac}\n Source MAC: {src_mac}\n Ethernet Type: {eth_type}")
if __name__ == "__main__":
    main()
