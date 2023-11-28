import pyshark
from datetime import datetime
import numpy as np

# Define a dictionary to store flow information
flow_info = {}

# Function to update flow information


def update_flow_info(packet):
    flow_key = f"{packet.ip.src}:{packet[packet.transport_layer].srcport} - {packet.ip.dst}:{packet[packet.transport_layer].dstport}"

    if flow_key not in flow_info:
        flow_info[flow_key] = {
            "start_time": float(packet.sniff_timestamp),
            "end_time": float(packet.sniff_timestamp),
            "tot_fwd_pkts": 0,
            "tot_bwd_pkts": 0,
            "pkt_len_max": 0,
            "pkt_len_min": float('inf'),
            "pkt_len_sum": 0,
            "flow_duration": 0,
            "fwd_pkt_len_sum": 0,
            "fwd_iat_sum": 0,
            "cwe_flag_count": 0,
            "active_times": [],
            "ece_flag_count": 0,
            "fwd_seg_size_min": float('inf'),
        }
    else:
        flow_info[flow_key]["end_time"] = float(packet.sniff_timestamp)

    # Update flow parameters
    # flow_info[flow_key]["tot_fwd_pkts"] += int(
    #     packet[packet.transport_layer].flags_fin) if "F" in packet[packet.transport_layer].flags else 0
    # flow_info[flow_key]["tot_bwd_pkts"] += int(
    #     packet[packet.transport_layer].flags_fin) if "F" in packet[packet.transport_layer].flags else 0
    # pkt_len = int(packet.length)
    # flow_info[flow_key]["pkt_len_max"] = max(
    #     flow_info[flow_key]["pkt_len_max"], pkt_len)
    # flow_info[flow_key]["pkt_len_min"] = min(
    #     flow_info[flow_key]["pkt_len_min"], pkt_len)
    # flow_info[flow_key]["pkt_len_sum"] += pkt_len
    # flow_info[flow_key]["flow_duration"] = flow_info[flow_key]["end_time"] - \
    #     flow_info[flow_key]["start_time"]
    # flow_info[flow_key]["fwd_pkt_len_sum"] += pkt_len if pkt_len > 0 else 0

    # if "C" in packet[packet.transport_layer].flags:
    #     flow_info[flow_key]["cwe_flag_count"] += 1

    # if "E" in packet[packet.transport_layer].flags:
    #     flow_info[flow_key]["ece_flag_count"] += 1

    # flow_info[flow_key]["fwd_seg_size_min"] = min(flow_info[flow_key]["fwd_seg_size_min"], int(
    #     packet[packet.transport_layer].window_size_value))

# Function to calculate and print flow statistics


    for packet in capture:
            # Count forward and backward packets
            if 'IP' in packet and 'tcp' in packet:
                if packet.ip.src == capture[0].ip.src:
                    flow_info[flow_key]["tot_fwd_pkts"] += 1
                else:
                    flow_info[flow_key]["tot_bwd_pkts"] += 1

            # Calculate Packet Length Max and Min
            if 'IP' in packet and 'tcp' in packet and 'data' in packet:
                pkt_len = int(packet.data.len)
                flow_info[flow_key]["pkt_len_max"] = max(flow_info[flow_key]["pkt_len_max"], pkt_len)
                flow_info[flow_key]["pkt_len_min"] = min(flow_info[flow_key]["pkt_len_min"], pkt_len)

                # Calculate Fwd Pkts/s
                if flow_info[flow_key]["flow_duration"] > 0:
                    fwd_pkts_per_s = flow_info[flow_key]["end_time"] - flow_info[flow_key]["start_time"]

            # Count CWE Flag (You may need to adapt this based on your data)
            if 'TCP' in packet and hasattr(packet.tcp, 'flags_cwe'):
                flow_info[flow_key]["cwe_flag_count"] += 1

            # Calculate ECE Flag Count (You may need to adapt this based on your data)
            if 'TCP' in packet and hasattr(packet.tcp, 'flags_ecn_echo'):
                flow_info[flow_key]["ece_flag_count"] += 1

            # Calculate Fwd Seg Size Min
            if 'TCP' in packet and hasattr(packet.tcp, 'options_wscale'):
                flow_info[flow_key]["fwd_seg_size_min"] = min(flow_info[flow_key]["fwd_seg_size_min"], int(packet.tcp.options_wscale))

            # Calculate Packet Length Standard Deviation and Mean
            if 'IP' in packet and 'tcp' in packet and 'data' in packet:
                pkt_len = int(packet.data.len)
                fwd_pkt_len_mean = ((fwd_pkt_len_mean * (flow_info[flow_key]["tot_fwd_pkts"] - 1)) + pkt_len) / flow_info[flow_key]["tot_fwd_pkts"]
                pkt_len_std += (pkt_len - fwd_pkt_len_mean) ** 2
                
            # Calculate Flow IAT Max and Fwd IAT Tot
            if 'IP' in packet and 'tcp' in packet:
                timestamp = float(packet.sniff_timestamp)
                flow_iat = timestamp - float(flow_info[flow_key]["start_time"])
                flow_iat_max = max(flow_iat_max, flow_iat)
                
                if flow_info[flow_key]["tot_fwd_pkts"] > 1:
                    fwd_iat = timestamp - float(capture[-2].sniff_timestamp)
                    fwd_iat_tot += fwd_iat

            # Calculate Active Std (You may need to adapt this based on your data)
            if flow_info[flow_key]["tot_fwd_pkts"] > 1: 
                active_std = 0 if not flow_info["active_times"] else (sum((t - flow_duration) ** 2 for t in info["active_times"]) / len(info["active_times"])) ** 0.5

# def calculate_and_print_stats():
#     for flow_key, info in flow_info.items():
#         flow_duration = info["flow_duration"]
#         active_std = 0 if not info["active_times"] else (sum(
#             (t - flow_duration) ** 2 for t in info["active_times"]) / len(info["active_times"])) ** 0.5
#         fwd_pkts_per_sec = info["tot_fwd_pkts"] / \
#             flow_duration if flow_duration > 0 else 0
#         fwd_pkt_len_mean = info["fwd_pkt_len_sum"] / \
#             info["tot_fwd_pkts"] if info["tot_fwd_pkts"] > 0 else 0
#         fwd_iat_tot = sum(info["active_times"]) if info["active_times"] else 0

#         print(f"Flow: {flow_key}")
#         print(f"Flow Duration: {flow_duration} seconds")
#         print(f"Active Std: {active_std}")
#         print(f"Tot Fwd Pkts: {info['tot_fwd_pkts']}")
#         print(f"Pkt Len Max: {info['pkt_len_max']}")
#         print(f"CWE Flag Count: {info['cwe_flag_count']}")
#         print(f"Pkt Len Min: {info['pkt_len_min']}")
#         print(f"Fwd Pkts/s: {fwd_pkts_per_sec}")
#         print(f"ECE Flag Cnt: {info['ece_flag_count']}")
#         print(f"Fwd Seg Size Min: {info['fwd_seg_size_min']}")
#         print(f"Tot Bwd Pkts: {info['tot_bwd_pkts']}")
#         # Placeholder, as PyShark doesn't provide standard deviation directly
#         print(f"Pkt Len Std: {0}")
#         print(f"Fwd Pkt Len Mean: {fwd_pkt_len_mean}")
#         print(
#             f"Flow IAT Max: {max(info['active_times']) if info['active_times'] else 0}")
#         print(f"Fwd IAT Tot: {fwd_iat_tot}")
#         print()



# Process each packet in the .pcap file
for packet in capture:
    if 'IP' in packet and 'tcp' in packet:
        # Determine the flow key based on source and destination IP and ports
        flow_key = (packet.ip.src, packet.ip.dst, packet.tcp.srcport, packet.tcp.dstport)

        # If the flow key changes, calculate features for the previous flow
        if flow_key != current_flow_key and current_flow_packets:
            flow_features = calculate_features(current_flow_packets)
            all_features.append(flow_features)

            # Reset for the next flow
            current_flow_packets = []

        # Append the packet to the current flow
        current_flow_packets.append(packet)
        current_flow_key = flow_key

# Calculate features for the last flow in the pcap file
if current_flow_packets:
    flow_features = calculate_features(current_flow_packets)
    all_features.append(flow_features)

# Convert the list of feature dictionaries to a DataFrame
feature_df = pd.DataFrame(all_features)



# Capture packets in real-time
if __name__ == "__main__":
    capture = pyshark.LiveCapture(interface='Wi-Fi', display_filter='tcp')
    capture.set_debug()
    try:
        # Start packet capture
        capture.sniff(timeout=5)

    finally:
        # Ensure cleanup is done even if an exception occurs
        capture.close()
    count = 0
    print("Fuck you" , len(capture))
    for packet in capture:
        # print(packet)
        print("Fuck you" , len(capture))
        try:
            update_flow_info(packet)
        except Exception as e:
            print(f"Error processing packet: {e}")
        count += 1
        print(count)

        # Print flow statistics periodically
        # if float(packet.sniff_timestamp) % 1 == 0:
        calculate_and_print_stats()
    print('completed')
