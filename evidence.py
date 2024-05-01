import argparse
import datetime as dt
import os
import subprocess
from scapy.all import *


def capture_packets(interface, duration, output_file):
    # print(ifaces)
    # start_time = dt.datetime.now()
    # end_time = start_time + dt.timedelta(seconds=duration)

    packets = sniff(iface=interface, count=0, timeout=duration)
    for pkt in packets:
        print(pkt.fields)
    print(packets[0].layers)
    wrpcap(output_file, packets)
    print(f"Captured {len(packets)} packets and stored in {output_file}")


# def analyze_packets(pcap_file):
#     packets = rdpcap(pcap_file)
#
#     print(f"Analyzing {len(packets)} packets from {pcap_file}...")
#
#     # Packet analysis and filtering
#     tcp_packets = [pkt for pkt in packets if pkt.haslayer(TCP)]
#     print(f"TCP packets: {len(tcp_packets)}")
#
#     http_packets = [pkt for pkt in packets if pkt.haslayer(HTTPRequest)]
#     print(f"HTTP requests: {len(http_packets)}")
#
#     for http_pkt in http_packets:
#         print(f"HTTP Request: {http_pkt[HTTPRequest].Host.decode()} {http_pkt[HTTPRequest].Path.decode()}")
#
#     # Additional analysis and filtering as needed


# def main():
#     parser = argparse.ArgumentParser(description="Network Forensic Evidence Collection")
#     parser.add_argument("-i", "--interface", required=True, help="Network interface to capture packets from")
#     parser.add_argument("-d", "--duration", type=int, default=60, help="Duration of packet capture in seconds")
#     parser.add_argument("-o", "--output", default="capture.pcap", help="Output PCAP file name")
# #    parser.add_argument("-a", "--analyze", action="store_true", help="Analyze the captured PCAP file")
#
#     args = parser.parse_args()
#
#     if not os.geteuid() == 0:
#         print("This script requires root privileges.")
#         sys.exit(1)
#
#     # if args.analyze:
#     #     if os.path.exists(args.output):
#     #         analyze_packets(args.output)
#     #     else:
#     #         print(f"PCAP file {args.output} not found.")
#     else:
#         output_file = f"{args.output}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
#         capture_packets(args.interface, args.duration, output_file)


if __name__ == "__main__":
    capture_packets('Intel(R) Dual Band Wireless-AC 8260', 10, 'output.pcap')
