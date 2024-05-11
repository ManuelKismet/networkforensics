import argparse
import datetime as dt
import os
import subprocess

import pyshark
from scapy.all import *
from sklearn.ensemble import IsolationForest
from nfstream import NFStreamer, NFPlugin

import pandas as pd
from joblib import load

pd.set_option('display.width', None)


def load_model():
    model = load('unsup_anom_mod.joblib')
    return model


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
           'bidirectional_last_seen_ms', 'bidirectional_duration_ms', 'bidirectional_packets', 'bidirectional_bytes', 'src2dst_first_seen_ms',
           'src2dst_last_seen_ms', 'src2dst_duration_ms', 'src2dst_packets', 'src2dst_bytes', 'dst2src_first_seen_ms',
           'dst2src_last_seen_ms', 'dst2src_duration_ms', 'dst2src_packets', 'dst2src_bytes', 'bidirectional_min_ps',
           'bidirectional_mean_ps', 'bidirectional_stddev_ps', 'bidirectional_max_ps', 'src2dst_min_ps',
           'src2dst_mean_ps', 'src2dst_stddev_ps', 'src2dst_max_ps', 'dst2src_min_ps', 'dst2src_mean_ps', 'dst2src_stddev_ps',
           'src2dst_rst_packets', 'src2dst_fin_packets', 'dst2src_syn_packets', 'dst2src_cwr_packets', 'dst2src_ece_packets',
           'dst2src_urg_packets', 'dst2src_ack_packets', 'dst2src_psh_packets', 'dst2src_rst_packets', 'dst2src_fin_packets',
           'application_name', 'application_category_name', 'application_is_guessed', 'application_confidence', 'requested_server_name',
           'client_fingerprint', 'server_fingerprint', 'user_agent', 'content_type', 'dst2src_max_ps',  'bidirectional_min_piat_ms',
           'bidirectional_mean_piat_ms',  'bidirectional_stddev_piat_ms',  'bidirectional_max_piat_ms',  'src2dst_min_piat_ms',  'src2dst_mean_piat_ms',
           'src2dst_stddev_piat_ms',  'src2dst_max_piat_ms',  'dst2src_min_piat_ms',  'dst2src_mean_piat_ms',  'dst2src_stddev_piat_ms',  'dst2src_max_piat_ms',
           'bidirectional_syn_packets',  'bidirectional_cwr_packets',  'bidirectional_ece_packets',  'bidirectional_urg_packets',  'bidirectional_ack_packets',
           'bidirectional_psh_packets',  'bidirectional_rst_packets',  'bidirectional_fin_packets',  'src2dst_syn_packets',  'src2dst_cwr_packets',
           'src2dst_ece_packets',  'src2dst_urg_packets',  'src2dst_ack_packets',  'src2dst_psh_packets']
    plugin_instance = PacketMetrics()
    streamer = NFStreamer(eth, udps=[plugin_instance], statistical_analysis=True)
    my_dataframe = streamer.to_pandas()
    print(my_dataframe.drop(col, axis=1))


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

#
# import numpy as np
# import pandas as pd
# from sklearn.ensemble import IsolationForest
#
# # Load the trained Isolation Forest model
# def load_model(model_path):
#     # Load the trained model from file
#     model = IsolationForest()
#     model.load_model(model_path)
#     return model
#
# # Preprocess incoming packet data
# def preprocess_packet(packet):
#     # Extract relevant features from the packet
#     # Preprocess the packet data to match the format used during model training
#     features = extract_features(packet)
#     return features
#
# # Perform real-time anomaly detection
# def detect_anomalies(packet, model):
#     # Preprocess the incoming packet data
#     features = preprocess_packet(packet)
#     # Predict the anomaly score for the packet using the loaded model
#     anomaly_score = model.predict(features)
#     return anomaly_score
#
# # Define a threshold for anomaly detection
# THRESHOLD = -0.5
#
# # Function to trigger alert based on anomaly score
# def trigger_alert(anomaly_score):
#     if anomaly_score < THRESHOLD:
#         print("Anomaly detected! Triggering alert...")
#
# # Main function to simulate real-time packet analysis
# def main():
#     # Load the trained Isolation Forest model
#     model_path = 'trained_model.pkl'
#     model = load_model(model_path)
#
#     # Simulate incoming packet data (replace with actual data source)
#     packet_stream = generate_packet_stream()
#
#     # Process incoming packets and perform real-time anomaly detection
#     for packet in packet_stream:
#         # Perform anomaly detection on the current packet
#         anomaly_score = detect_anomalies(packet, model)
#         # Trigger alert if anomaly score exceeds threshold
#         trigger_alert(anomaly_score)
#
# # Function to generate simulated packet stream (replace with actual data source)
# def generate_packet_stream():
#     # Simulate generation of packet data
#     packet_stream = [np.random.rand(61) for _ in range(1000)]  # Example: 1000 packets with 61 features each
#     return packet_stream
#
# if __name__ == "__main__":
#     main()
