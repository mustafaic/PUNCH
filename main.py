from scapy.all import *
from scapy.layers.inet import UDP, TCP, ICMP
from scapy.layers.dns import DNS

def read_file(file_name):
    try:
        packets = rdpcap(file_name)
        return packets

    except:
        print("[!] Error: Could not read the file.")
        return []


def filter():
    print(""""
    
    [1] HTTP
    [2] HTTPS
    [3] UDP
    [4] TCP
    [5] DNS
    [6] ARP
    [7] ICMP
    
    """)

    choice = input("Choose the filters: ")

    if choice == 1:
