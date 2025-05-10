# Packet Analyzer 🚀  
A tool for analyzing pcap/pcapng files, filtering specific protocols, and highlighting keywords within packet content.

# Features:
HTTP, DNS, ICMP, TCP, UDP protocol filter
Keyword search


# Installation:
git clone https://github.com/username/PacketAnalyzer.git
cd PacketAnalyzer
pip install -r requirements.txt

# Usage:
python analyzer.py <file_path> -p <protocol> -k <keyword1> <keyword2>

Example: python punch.py traffic.pcapng -p http -k admin password
