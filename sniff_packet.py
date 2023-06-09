# Created By - Harsh Mishra | Github - https://github.com/vmishrasj
# Simple packet capturing and data dumping tool

from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.http import HTTPRequest, TCP
from termcolor import colored

# Python must be installed
# If you want to run this program you should have to install all the libraries, if already installed then feel free to proceed
# To install library you can use the cmd: pip install library_name

output_file = "output.txt"

# sniffing packet at interface
def sniff_packets(iface):
    if iface:
        sniff(prn = process_packet, iface = iface, store = False)
    else:
        sniff(prn = process_packet, store = False)

def process_packet(packet):
    # if packet contains TCP then following will be fetched
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        ver = packet[IP].version
        print(colored("[+] Version is {} Source IP {} sending data from {} to Destination IP {} on {}".format(ver, src_ip, src_port, dst_ip, dst_port), "blue"))
        
    # if packet contains HTTP request then following will be fetched
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        method = packet[HTTPRequest].Method.decode()            
        print(colored("[+] {} is sending HTTP request to {} in which {} through {}".format(src_ip, dst_ip, url, method), "green"))
            
        # if packet contains data
        if packet.haslayer(Raw):
            with open(output_file, "a") as file:
                output = "{}".format(packet.getlayer(Raw).load.decode())
                print(colored("[+] Data Captured:", "red"))
                file.write(output + "\n")

sniff_packets("Wi-Fi")