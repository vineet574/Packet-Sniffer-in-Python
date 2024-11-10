from scapy.all import *

def packet_sniffer(packet):
    if packet.haslayer(IP):
        print(f"Source IP: {packet[IP].src} -> Destination IP: {packet[IP].dst}")

print("Starting packet sniffer...")
sniff(prn=packet_sniffer, count=10)
