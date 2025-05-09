from scapy.all import *
from scapy.layers.inet import UDP, TCP, ICMP
from scapy.layers.dns import DNS
from colorama import Fore, Back, Style, init
import argparse


init(autoreset=True)

def highlight_keywords(packets, keywords):
    for packets_str in packets:
        packets_str = packets_str.decode(errors="ignore")

    for keyword in keywords:
        if keyword in packets_str:
            highlighted = f"{Fore.YELLOW}{Back.BLACK}{keyword}{Style.RESET_ALL}"
            packets_str = packets_str.replace(keyword, highlighted)

    return packets_str


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
        if protocol == "http" and pkt.haslayer(TCP) and pkt.haslayer(Raw):
            if b"http" in pkt[Raw].load:
                filtered.append(pkt)

        elif protocol == "tcp" and pkt.haslayer(TCP):
            filtered.append(pkt)

        elif protocol == "udp" and pkt.haslayer(UDP):
            filtered.append(pkt)

        elif protocol == "icmp" and pkt.haslayer(ICMP):
            filtered.append(pkt)

        elif protocol == "dns" and pkt.haslayer(DNS):
            filtered.append(pkt)

    return filtered


def search_keywords(packets, keywords):
    for pkt in packets:
        if Raw in pkt:
            packet = pkt[Raw].load
            highlighted_packet = highlight_keywords(packets, keywords)

            for keyword in keywords:
                if any(keyword.encode()) in packet:
                    print(f"\n{highlighted_packet}\n{'-'*40}")


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
    main()

