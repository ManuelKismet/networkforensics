import argparse
import datetime as dt
import os
import subprocess

import pyshark
from scapy.all import *
from sklearn.ensemble import IsolationForest
from nfstream import NFStreamer
import pandas as pd

pd.set_option('display.width', None)


# def capture_traffic(eth):
#     streamer = NFStreamer(eth, statistical_analysis=True)
#     my_dataframe = streamer.to_pandas(columns_to_anonymize=[])
#     print(my_dataframe.head())


def capture_packets(interface, duration):
    # print(ifaces)
    # start_time = dt.datetime.now()
    # end_time = start_time + dt.timedelta(seconds=duration)

    packets = sniff(iface=interface, count=0, timeout=duration)
    # df = packets.to_pandas()
    print(packets[0].fields)
    # for pkt in packets:
    #     print(pkt.fields)
    # print(packets[0].show())
    # wrpcap(output_file, packets)
    # print(f"Captured {len(packets)} packets and stored in {output_file}")


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
    capture_packets('Intel(R) Dual Band Wireless-AC 8260', 10,)

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
