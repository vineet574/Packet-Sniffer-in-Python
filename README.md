# Packet Sniffer

## Overview
This project is a lightweight packet sniffer built with Python, utilizing the Scapy library. It captures and analyzes network packets, displaying essential details such as source and destination IPs, protocols, ports, packet length, and payload.

## Features
- Capture network packets in real-time.
- Extract and display:
  - Source and destination IPs.
  - Protocols (TCP, UDP, ICMP) and port information.
  - Packet length.
  - Payload data.
- Supports filtering by packet layer type using Scapy.

## Requirements
- Python 3.x
- Scapy library

## Installation
1. Install Python:
   - [Download Python](https://www.python.org/downloads/)
2. Install the Scapy library:
   ```bash
   pip install scapy
Usage
Run the packet sniffer:

bash
python sniffer.py
(Ensure you have administrative privileges to capture packets.)

The sniffer will analyze the first 10 packets and display their details in the console.

Example Output
Starting enhanced packet sniffer...
Source IP: 192.168.0.1 -> Destination IP: 172.217.12.206
Protocol: TCP -> Source Port: 45000, Destination Port: 443
Packet Length: 98 bytes
Payload: GET / HTTP/1.1
--------------------------------------------------
Notes
Requires administrative privileges to sniff packets.

Decoding payloads may exclude unreadable characters for better display.
