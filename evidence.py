import argparse
import datetime as dt
import multiprocessing
import os
from Crypto.Cipher import AES
import hashlib
import subprocess

import pyshark
import pyshark.capture
from scapy.all import *
from sklearn.ensemble import IsolationForest
from nfstream import NFStreamer, NFPlugin

import pandas as pd
from joblib import load

pd.set_option('display.width', None)


def model_predict(flow):
    model = load('unsup_anom_mod.joblib')
    pred = model.predict(flow.values.reshape(1, -1))
    return pred


class PacketMetrics(NFPlugin):
    def on_init(self, packet: Packet, flow):
        """
        Initialize any required variables or statistics at the start of a flow.
        """
        flow.udps.total_len_fwd_packets = 0
        flow.udps.total_len_bwd_packets = 0
        flow.udps.total_fwd_iat = 0
        flow.udps.total_bwd_iat = 0
        flow.udps.fwd_act_data_pkts = 0
        flow.udps.bwd_act_data_pkts = 0
        flow.udps.fwd_header_length = 0
        flow.udps.bwd_header_length = 0
        flow.udps.flow_bytes_sec = 0
        flow.udps.flow_pkts_sec = 0
        flow.udps.fwd_pkts_sec = 0
        flow.udps.bwd_pkts_sec = 0
        flow.udps.pkt_size_avg = 0
        flow.udps.fwd_seg_siz_avg = 0
        flow.udps.bwd_seg_siz_avg = 0
        flow.udps.tot_fwd_pkts = 0
        flow.udps.tot_bwd_pkts = 0
        flow.udps.last_seen_fwd = packet.time
        flow.udps.last_seen_bwd = packet.time

    def on_update(self, packet: Packet, flow):
        """
        Update metrics for each packet in a flow.
        """
        if packet.direction == 0:  # Forward packet
            flow.udps.total_len_fwd_packets += packet.ip_size
            ip_header_length = packet.ip_size - packet.payload_size if (hasattr(packet, 'ip_size') and
                                                                        hasattr(packet, 'payload_size')) else 0

            if flow.udps.last_seen_fwd:
                flow.udps.total_fwd_iat += packet.time - flow.udps.last_seen_fwd
            flow.udps.last_seen_fwd = packet.time
            flow.udps.fwd_header_length += ip_header_length
            flow.udps.fwd_act_data_pkts += 1 if packet.payload_size > 0 else 0
            if flow.bidirectional_duration_ms > 0:
                flow.udps.fwd_pkts_sec = flow.udps.fwd_act_data_pkts / flow.bidirectional_duration_ms
            else:
                flow.udps.fwd_pkts_sec = 0
            if packet.payload_size > 0:
                flow.udps.tot_fwd_pkts += 1
        elif packet.direction == 1:  # Backward packet
            flow.udps.total_len_bwd_packets += packet.ip_size
            ip_header_length = packet.ip_size - packet.payload_size if (hasattr(packet, 'ip_size') and
                                                                        hasattr(packet, 'payload_size')) else 0
            if flow.udps.last_seen_bwd:
                flow.udps.total_bwd_iat += packet.time - flow.udps.last_seen_bwd
            flow.udps.last_seen_bwd = packet.time
            flow.udps.bwd_header_length += ip_header_length
            flow.udps.bwd_act_data_pkts += 1 if packet.payload_size > 0 else 0
            if flow.bidirectional_duration_ms > 0:
                flow.udps.bwd_pkts_sec = flow.udps.total_len_bwd_packets / flow.bidirectional_duration_ms
            else:
                flow.udps.bwd_pkts_sec = 0
            if packet.payload_size > 0:
                flow.udps.tot_bwd_pkts += 1

    def on_expire(self, flow):
        """
        When the flow expires, finalize any statistics that need calculation at the end of the flow.
        This could include averages or other metrics that need the complete flow to be calculated.
        """
        if flow.udps.fwd_act_data_pkts > 0:
            flow.udps.fwd_seg_siz_avg = flow.udps.total_len_fwd_packets / flow.udps.fwd_act_data_pkts
        else:
            flow.udps.fwd_seg_siz_avg = 0
        if flow.udps.bwd_act_data_pkts > 0:
            flow.udps.bwd_seg_siz_avg = flow.udps.total_len_bwd_packets / flow.udps.bwd_act_data_pkts
        else:
            flow.udps.fwd_seg_siz_avg = 0
        if flow.bidirectional_packets > 0:
            flow.udps.avg_packet_size_fwd = flow.udps.total_len_fwd_packets / flow.bidirectional_packets
            flow.udps.avg_packet_size_bwd = flow.udps.total_len_bwd_packets / flow.bidirectional_packets
            flow.udps.pkt_size_avg = flow.udps.avg_packet_size_fwd + flow.udps.avg_packet_size_bwd
        else:
            flow.udps.pkt_size_avg = 0

        if flow.bidirectional_duration_ms > 0:
            flow.udps.flow_bytes_sec = flow.bidirectional_bytes / flow.bidirectional_duration_ms
            flow.udps.flow_pkts_sec = flow.bidirectional_packets / flow.bidirectional_duration_ms
        else:
            flow.udps.flow_bytes_sec = 0
            flow.udps.flow_pkts_sec = 0


def capture_traffic(eth):
    col = ['id', 'expiration_id', 'src_ip', 'src_mac', 'src_oui', 'src_port', 'dst_ip', 'dst_mac', 'dst_oui',
           'dst_port', 'protocol', 'ip_version', 'vlan_id', 'tunnel_id', 'bidirectional_first_seen_ms',
           'bidirectional_last_seen_ms', 'bidirectional_duration_ms', 'bidirectional_packets', 'bidirectional_bytes',
           'src2dst_first_seen_ms',
           'src2dst_last_seen_ms', 'src2dst_duration_ms', 'src2dst_packets', 'src2dst_bytes', 'dst2src_first_seen_ms',
           'dst2src_last_seen_ms', 'dst2src_duration_ms', 'dst2src_packets', 'dst2src_bytes', 'bidirectional_min_ps',
           'bidirectional_mean_ps', 'bidirectional_stddev_ps', 'bidirectional_max_ps', 'src2dst_min_ps',
           'src2dst_mean_ps', 'src2dst_stddev_ps', 'src2dst_max_ps', 'dst2src_min_ps', 'dst2src_mean_ps',
           'dst2src_stddev_ps',
           'src2dst_rst_packets', 'src2dst_fin_packets', 'dst2src_syn_packets', 'dst2src_cwr_packets',
           'dst2src_ece_packets',
           'dst2src_urg_packets', 'dst2src_ack_packets', 'dst2src_psh_packets', 'dst2src_rst_packets',
           'dst2src_fin_packets',
           'application_name', 'application_category_name', 'application_is_guessed', 'application_confidence',
           'requested_server_name',
           'client_fingerprint', 'server_fingerprint', 'user_agent', 'content_type', 'dst2src_max_ps',
           'bidirectional_min_piat_ms',
           'bidirectional_mean_piat_ms', 'bidirectional_stddev_piat_ms', 'bidirectional_max_piat_ms',
           'src2dst_min_piat_ms', 'src2dst_mean_piat_ms',
           'src2dst_stddev_piat_ms', 'src2dst_max_piat_ms', 'dst2src_min_piat_ms', 'dst2src_mean_piat_ms',
           'dst2src_stddev_piat_ms', 'dst2src_max_piat_ms',
           'bidirectional_syn_packets', 'bidirectional_cwr_packets', 'bidirectional_ece_packets',
           'bidirectional_urg_packets', 'bidirectional_ack_packets',
           'bidirectional_psh_packets', 'bidirectional_rst_packets', 'bidirectional_fin_packets', 'src2dst_syn_packets',
           'src2dst_cwr_packets',
           'src2dst_ece_packets', 'src2dst_urg_packets', 'src2dst_ack_packets', 'src2dst_psh_packets']
    plugin_instance = PacketMetrics()
    streamer = NFStreamer(eth, udps=[plugin_instance], statistical_analysis=True)

    for flow in streamer:
        flow_data = {'Tot Fwd Pkts': flow.udps.tot_fwd_pkts,
                     'Tot Bwd Pkts': flow.udps.tot_bwd_pkts,
                     'TotLen Fwd Pkts': flow.udps.total_len_fwd_packets,
                     'TotLen Bwd Pkts': flow.udps.total_len_bwd_packets,
                     'Flow Byts/s': flow.udps.flow_bytes_sec,
                     'Flow Pkts/s': flow.udps.flow_pkts_sec,
                     'Fwd IAT Tot': flow.udps.total_fwd_iat,
                     'Bwd IAT Tot': flow.udps.total_fwd_iat,
                     'Fwd Header Len': flow.udps.fwd_header_length,
                     'Bwd Header Len': flow.udps.bwd_header_length,
                     'Fwd Pkts/s': flow.udps.fwd_pkts_sec,
                     'Bwd Pkts/s': flow.udps.bwd_pkts_sec,
                     'Fwd Act Data Pkts': flow.udps.fwd_act_data_pkts,
                     'Fwd Seg Size Avg': flow.udps.fwd_seg_siz_avg,
                     'Bwd Seg Size Avg': flow.udps.bwd_seg_siz_avg,
                     'Pkt Size Avg': flow.udps.pkt_size_avg}

        flow_df = pd.DataFrame([flow_data])
        flow_df = flow_df.drop(columns=col, errors='ignore')
        prediction = model_predict(flow_df)
        if prediction == -1:
            process = multiprocessing.Process(target=capture_packets(flow), args=(flow,))
            process.start()
            process.join()


def encrypt_packet(packt, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(packt)
    return ciphertext, tag


def capture_packets(flow, encryption_key):
    capture_filter = f"src {flow.src_ip} and dst {flow.dst_ip}"
    captured_packets = sniff(filter=capture_filter, count=10)

    # Encrypt and calculate integrity for each packet
    encrypted_packets = []
    integrity_hashes = []
    for packet in captured_packets:
        ciphertext, tag = encrypt_packet(bytes(packet), encryption_key)
        encrypted_packets.append(ciphertext)
        integrity_hashes.append(hashlib.sha256(ciphertext + tag).digest())

    # Save encrypted packets and integrity hashes to PCAP file
    pcap_filename = f"captured_packets_flow_{flow.id}.pcap"
    with open(pcap_filename, "wb") as pcap_file:
        for encrypted_packet, integrity_hash in zip(encrypted_packets, integrity_hashes):
            pcap_file.write(encrypted_packet)
            pcap_file.write(integrity_hash)

    print(f"Captured packets saved to '{pcap_filename}'")


# def capture_packets(flow):
#     capture_filter = f"src {flow.src_ip} and dst {flow.dst_ip}"
#     captured_packets = sniff(filter=capture_filter, count=10)
#
#     pcap_filename = f"captured_packets_flow_{flow.id}.pcap"
#     wrpcap(pcap_filename, captured_packets)
#     print(f"Captured packets saved to '{pcap_filename}'")


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
    # capture_traffic('Intel(R) Dual Band Wireless-AC 8260')
    capture_traffic('Intel(R) Dual Band Wireless-AC 8260')
