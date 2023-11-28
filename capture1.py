import pyshark
from datetime import datetime
import numpy as np
import joblib

# Define a dictionary to store flow information
# flow_info = {}

# Function to update flow information


# def update_flow_info(packet):
#     flow_key = f"{packet.ip.src}:{packet[packet.transport_layer].srcport} - {packet.ip.dst}:{packet[packet.transport_layer].dstport}"

#     if flow_key not in flow_info:
#         flow_info[flow_key] = {
#             "start_time": float(packet.sniff_timestamp),
#             "end_time": float(packet.sniff_timestamp),
#             "tot_fwd_pkts": 0,
#             "tot_bwd_pkts": 0,
#             "pkt_len_max": 0,
#             "pkt_len_min": float('inf'),
#             "pkt_len_sum": 0,
#             "flow_duration": 0,
#             "fwd_pkt_len_sum": 0,
#             "fwd_iat_sum": 0,
#             "cwe_flag_count": 0,
#             "active_times": [],
#             "ece_flag_count": 0,
#             "fwd_seg_size_min": float('inf'),
#         }
#     else:
#         flow_info[flow_key]["end_time"] = float(packet.sniff_timestamp)

    # Function to calculate features for a flow
def calculate_features(flow_packets):
    features = {}
    
    # Extract Flow Duration
    start_time = flow_packets[0].sniff_timestamp
    end_time = flow_packets[-1].sniff_timestamp
    flow_duration = float(end_time) - float(start_time)
    features['Flow Duration'] = flow_duration

    # Initialize variables for other features
    active_std = 0.0
    tot_fwd_pkts = 0
    pkt_len_max = 0
    cwe_flag_count = 0
    pkt_len_min = float('inf')
    fwd_pkts_per_s = 0.0
    ece_flag_count = 0
    fwd_seg_size_min = float('inf')
    tot_bwd_pkts = 0
    pkt_len_std = 0.0
    fwd_pkt_len_mean = 0.0
    flow_iat_max = 0.0
    fwd_iat_tot = 0.0

    # Calculate other features
    for packet in flow_packets:
        # Count forward and backward packets
        if 'IP' in packet and 'tcp' in packet:
            if packet.ip.src == flow_packets[0].ip.src:
                tot_fwd_pkts += 1
            else:
                tot_bwd_pkts += 1

        # Calculate Packet Length Max and Min
        if 'IP' in packet and 'tcp' in packet and 'data' in packet:
            pkt_len = int(packet.data.len)
            pkt_len_max = max(pkt_len_max, pkt_len)
            pkt_len_min = min(pkt_len_min, pkt_len)

            # Calculate Fwd Pkts/s
            if flow_duration > 0:
                fwd_pkts_per_s = tot_fwd_pkts / flow_duration

        # Count CWE Flag (You may need to adapt this based on your data)
        if 'TCP' in packet and hasattr(packet.tcp, 'flags_cwe'):
            cwe_flag_count += 1

        # Calculate ECE Flag Count (You may need to adapt this based on your data)
        if 'TCP' in packet and hasattr(packet.tcp, 'flags_ecn_echo'):
            ece_flag_count += 1

        # Calculate Fwd Seg Size Min
        if 'TCP' in packet and hasattr(packet.tcp, 'options_wscale'):
            fwd_seg_size_min = min(fwd_seg_size_min, packet.tcp.options_wscale)

        # Calculate Packet Length Standard Deviation and Mean
        if 'IP' in packet and 'tcp' in packet and 'data' in packet:
            pkt_len = int(packet.data.len)
            pkt_len_std += (pkt_len - fwd_pkt_len_mean) ** 2
            fwd_pkt_len_mean = ((fwd_pkt_len_mean * (tot_fwd_pkts - 1)) + pkt_len) / tot_fwd_pkts

        # Calculate Flow IAT Max and Fwd IAT Tot
        if 'IP' in packet and 'tcp' in packet:
            timestamp = float(packet.sniff_timestamp)
            flow_iat = timestamp - float(start_time)
            flow_iat_max = max(flow_iat_max, flow_iat)
            
            if tot_fwd_pkts > 1:
                fwd_iat = timestamp - float(flow_packets[-2].sniff_timestamp)
                fwd_iat_tot += fwd_iat

    # Calculate Active Std (You may need to adapt this based on your data)
    if tot_fwd_pkts > 1:
        active_std = np.std([float(packet.sniff_timestamp) for packet in flow_packets])

    features['Active Std'] = active_std
    features['Tot Fwd Pkts'] = tot_fwd_pkts
    features['Pkt Len Max'] = pkt_len_max
    features['CWE Flag Count'] = cwe_flag_count
    features['Pkt Len Min'] = pkt_len_min
    features['Fwd Pkts/s'] = fwd_pkts_per_s
    features['ECE Flag Cnt'] = ece_flag_count
    features['Fwd Seg Size Min'] = fwd_seg_size_min
    features['Tot Bwd Pkts'] = tot_bwd_pkts
    features['Pkt Len Std'] = np.sqrt(pkt_len_std / tot_fwd_pkts) if tot_fwd_pkts > 1 else 0.0
    features['Fwd Pkt Len Mean'] = fwd_pkt_len_mean
    features['Flow IAT Max'] = flow_iat_max
    features['Fwd IAT Tot'] = fwd_iat_tot

    return features

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



current_flow_packets = []
current_flow_key =[]

# Process each packet in the .pcap file
for packet in capture:
    if 'IP' in packet and 'tcp' in packet:
        # Determine the flow key based on source and destination IP and ports
        flow_key = (packet.ip.src, packet.ip.dst, packet.tcp.srcport, packet.tcp.dstport)

        # If the flow key changes, calculate features for the previous flow
        if flow_key != current_flow_key and current_flow_packets:
            flow_features = calculate_features(current_flow_packets)
            grad_classifier = joblib.load("grad_boost.pkl")
            grad_classifier.predict(flow_features)



            # Reset for the next flow
           

        # Append the packet to the current flow
        current_flow_packets.append(packet)
        current_flow_key = flow_key



# # Calculate features for the last flow in the pcap file
# if current_flow_packets:
#     flow_features = calculate_features(current_flow_packets)
#     all_features.append(flow_features)

# # Convert the list of feature dictionaries to a DataFrame
# feature_df = pd.DataFrame(all_features)



    # for packet in capture:
    #     # print(packet)
    #     try:
    #         calculate_features(packet)
    #     except Exception as e:
    #         print(f"Error processing packet: {e}")

    #     # Print flow statistics periodically
    #     # if float(packet.sniff_timestamp) % 1 == 0:
    #     calculate_and_print_stats()
    # print('completed')
