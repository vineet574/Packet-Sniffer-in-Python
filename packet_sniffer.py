from scapy.all import *

def packet_sniffer(packet):
    if packet.haslayer(IP):
        print(f"Source IP: {packet[IP].src} -> Destination IP: {packet[IP].dst}")
        if packet.haslayer(TCP):
            print(f"Protocol: TCP -> Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(f"Protocol: UDP -> Source Port: {packet[UDP].sport}, Destination Port: {packet[UDP].dport}")
        elif packet.haslayer(ICMP):
            print(f"Protocol: ICMP")
        print(f"Packet Length: {len(packet)} bytes")
        if Raw in packet:
            print(f"Payload: {bytes(packet[Raw].load).decode('utf-8', errors='ignore')}")
        print("-" * 50)

print("Starting enhanced packet sniffer...")
sniff(prn=packet_sniffer, count=10)
