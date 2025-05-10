from scapy.all import *
from scapy.layers.inet import UDP, TCP, ICMP
from scapy.layers.dns import DNS
from colorama import Fore, Back, Style, init
import argparse
import pyfiglet

init(autoreset=True)

def write_name(name):
    ascii_art = pyfiglet.figlet_format(name, font="slant")
    print(ascii_art)


def highlight_keywords(packet, keywords):
    packet_str = packet.decode(errors="ignore")

    for keyword in keywords:
        if keyword in packet_str:
            highlighted = f"{Fore.RED}{Back.WHITE}{keyword}{Style.RESET_ALL}"
            packet_str = packet_str.replace(keyword, highlighted)

    return packet_str

def load_file(file_name):
    try:
        packets = rdpcap(file_name)
        return packets
    except Exception as e:
        print(f"[!] Error: {e}")
        return []

def filter_by_protocol(packets, protocol):
    protocol = protocol.lower()
    filtered = []

    for pkt in packets:
        if protocol == "http" and TCP in pkt and Raw in pkt:
            if b"HTTP" in pkt[Raw].load:
                filtered.append(pkt)

        elif protocol == "tcp" and TCP in pkt:
            filtered.append(pkt)

        elif protocol == "udp" and UDP in pkt:
            filtered.append(pkt)

        elif protocol == "icmp" and ICMP in pkt:
            filtered.append(pkt)

        elif protocol == "dns" and DNS in pkt:
            filtered.append(pkt)

    return filtered

def search_keywords(packets, keywords):
    for pkt in packets:
        if Raw in pkt:
            packet = pkt[Raw].load
            highlighted_packet = highlight_keywords(packet, keywords)

            if any(keyword.encode() in packet for keyword in keywords):
                print(f"\n{'='*120}\n{highlighted_packet}\n{'='*120}")

def main():
    parser = argparse.ArgumentParser(description="pcap/pcapng analysis tool")
    parser.add_argument("pcap_file", help="analizi yapılacak dosya")
    parser.add_argument("-p", "--protocol", help="(http, dns, icmp)", default=None)
    parser.add_argument("-k", "--keywords", nargs="*", help="anahtar kelime", default=[])

    args = parser.parse_args()

    packets = load_file(args.pcap_file)

    if args.protocol:
        packets = filter_by_protocol(packets, args.protocol)

    if args.keywords:
        search_keywords(packets, args.keywords)
    else:
        for pkt in packets:
            print(pkt.summary())

if __name__ == "__main__":
    write_name(" PUNCH")
    print("""
    ------------------------------------------------------------------------
    🚀 Packet Analyzer v1.0
    ------------------------------------------------------------------------
    📦 This tool is designed to analyze pcap/pcapng files, 
    filter specific protocols, and highlight specific keywords 
    within the packet content.

    🌐 Supported Protocols: HTTP, DNS, ICMP, TCP, UDP
    🔍 Keyword Search: Keywords are highlighted with custom colors.

    🔥 Usage:
    python analyzer.py <file_path> -p <protocol> -k <keyword_1> <keyword_2>

    Example:
    python analyzer.py traffic.pcapng -p http -k admin password

    ------------------------------------------------------------------------
    """)
    main()
