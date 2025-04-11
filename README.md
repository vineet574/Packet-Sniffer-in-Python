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
