import argparse
import datetime as dt
import json
import multiprocessing
import os
import time
import win32evtlog
import win32con
import re

from Crypto.Cipher import AES
import hashlib

from scapy.all import *
from scapy.layers.inet import *
from nfstream import NFStreamer, NFPlugin

import pandas as pd
from joblib import load

pd.set_option('display.width', None)


def model_predict(flow):
    model = load('unsup_anom_mod.joblib')
    pred = model.predict(flow.values.reshape(1, -1))
    print(pred)
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
    server = 'localhost'
    logtype = 'Security'
    # log_queue = multiprocessing.Queue()
    key = os.urandom(16)
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
    try:
        streamer = NFStreamer(eth, udps=[plugin_instance], statistical_analysis=True)
        print('streamer pass')
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
            print('flow data to pandas done')
            flow_df = flow_df.drop(columns=col, errors='ignore')
            print('columns dropped')
            prediction = model_predict(flow_df)
            print('predict pass')
            if prediction == -1:
                log_data = forensic_data(get_forensic_logs(server, logtype))
                # process_log = multiprocessing.Process(target=get_forensic_logs, args=(server, logtype, log_queue))
                # process_log.start()
                # process_log.join()
                print('log process ends')
                # log_data = log_queue.get()
                # print('retrieved queued data')
                process = multiprocessing.Process(target=capture_packets, args=(flow, key, log_data))
                process.start()
                print('process started')
    except Exception as e:
        print('streamer failed', e)


def encrypt_packet(packt, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(packt)
    return ciphertext, tag


def capture_packets(flow, key, logdata):
    capture_filter = f"src {flow.src_ip} and dst {flow.dst_ip}"
    captured_packets = sniff(filter=capture_filter, count=10)
    print('packets captureds')

    analyze_packet(captured_packets, logdata)
    print('analysing packet')

    pcap_filename = f"captured_packets_flow_{flow.id}.pcap"
    wrpcap(pcap_filename, captured_packets)
    print(f"Captured packets saved to '{pcap_filename}'")

    packet_bytes = b''.join(bytes(pkt) for pkt in captured_packets)

    ciphertext, tag = encrypt_packet(bytes_encode(packet_bytes), key)
    print('encryption of packet done')
    _hash = hashlib.sha256(ciphertext).digest()
    print('hash generated')

    en_file = f"encrypted_{flow.id}.enc"
    with open(en_file, "wb") as ef:
        ef.write(ciphertext + tag + _hash)
    print(f"Captured packets saved to '{en_file}'")


def analyze_packet(capture, logdat):
    evidence = []
    for pkt in capture:
        print('packet recieved extracting evidence')
        packet_info = {
            "src_ip": pkt[IP].src if IP in pkt else "No IP Layer",
            "dst_ip": pkt[IP].dst if IP in pkt else "No IP Layer",
            "src_port": pkt[IP].sport if TCP in pkt or UDP in pkt else "N/A",
            "dst_port": pkt[IP].dport if TCP in pkt or UDP in pkt else "N/A",
            "protocol": pkt.proto if IP in pkt else "No Protocol Info",
            "timestamp": pkt.time,
            "tcp_flags": pkt[TCP].flags if TCP in pkt else "No TCP",
            "payload": bytes(pkt[TCP].payload) if TCP in pkt and Raw in pkt[TCP] else "No Payload",
            "packet_size": len(pkt)
        }
        evidence.append(packet_info)
        print('evidence appended')
    generate_forensic_report(evidence, logdat)
    print('generating report')
    print(type(evidence))
    return evidence


def get_forensic_logs(server, logtype):
    print('getting forensic logs')
    hand = win32evtlog.OpenEventLog(server, logtype)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    forensic_data_ = []

    try:
        while True:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events:
                break
            for event in events:
                if event.EventID in [4663, 4688, 5156, 4104]:  # Handling multiple event types
                    event_info = {
                        "Time Generated": event.TimeGenerated.strftime('%Y-%m-%d %H:%M:%S'),
                        "Event ID": event.EventID,
                        "Source": event.SourceName,
                        "Category": event.EventCategory,
                        "Strings": event.StringInserts,
                        "Computer": event.ComputerName
                    }
                    forensic_data_.append(event_info)
    finally:
        win32evtlog.CloseEventLog(hand)
    print('logs queued')
    # all_entries = forensic_data(forensic_data_)
    return forensic_data_  # og_queue.put(all_entries) all_entries


def analyze_powershell_script(script_text):
    # Look for common malicious patterns
    patterns = ['Invoke-Mimikatz', 'Invoke-Shellcode', 'DownloadString', 'Net.WebClient', 'Start-Process']
    findings = [pattern for pattern in patterns if re.search(pattern, script_text, re.IGNORECASE)]
    return findings


def parse_details(strings, event_id):
    if event_id == 4663:
        return {
            "Object Name": strings[5],
            "Access Mask": strings[6],
            "Process Name": strings[8]
        }
    elif event_id == 4688:
        return {
            "New Process Name": strings[4],
            "Creator Process Name": strings[8],
            "Process Command Line": strings[9] if len(strings) > 9 else "Not Available"
        }
    elif event_id == 5156:
        return {
            "Source IP": strings[2],
            "Source Port": strings[3],
            "Dest IP": strings[4],
            "Dest Port": strings[5],
            "Protocol": strings[6]
        }
    elif event_id == 4104:
        findings = analyze_powershell_script(strings[1]) if len(strings) > 1 else []
        print('analysing for mal behavior in powershell')
        return {
            "Script Block Text": strings[1] if len(strings) > 1 else "No Script Available",
            "User": strings[0],
            "Potential Malicious Activities": findings
        }
    return {}


def forensic_data(data):
    print('analysinz logs for forensic data')
    all_entries = []
    for entry in data:
        details = parse_details(entry["Strings"], entry["Event ID"])
        detail_entries = []
        for key, value in details.items():
            detail_entries.append({key: value})
        log_evidence = {
            "Time Generated": entry["Time Generated"],
            "Event ID": entry["Event ID"],
            "Source": entry["Source"],
            "Category": entry["Category"],
            "Computer": entry["Computer"],
            "Details": detail_entries
        }
        all_entries.append(log_evidence)
    print('data entries appended')
    return all_entries


def generate_forensic_report(evidence_, log_findings):
    print(type(evidence_), 'report evidence')
    report_content = {
        "Executive Summary": "Network traffic revealed potential security anomalies that warrant further examination.",
        "Background": "Automated monitoring system detected unusual traffic patterns, prompting this forensic analysis.",
        "Detailed Findings": evidence_,
        "Log Findings": log_findings,
        "Conclusion and Recommendations": "Further analysis of the attached PCAP file is recommended "
    }

    # Save the report to a text file
    rfile = f'report_file{time.time()}.json'
    with open(rfile, 'w') as report_file:
        json.dump(report_content, report_file, indent=4)
    print(f"Forensic report generated:{rfile}")


# def capture_packets(flow):
#     capture_filter = f"src {flow.src_ip} and dst {flow.dst_ip}"
#     captured_packets = sniff(filter=capture_filter, count=10)
#
#     pcap_filename = f"captured_packets_flow_{flow.id}.pcap"
#     wrpcap(pcap_filename, captured_packets)
#     print(f"Captured packets saved to '{pcap_filename}'")


if __name__ == "__main__":
    # capture_traffic('Intel(R) Dual Band Wireless-AC 8260')
    capture_traffic('Intel(R) Dual Band Wireless-AC 8260')
