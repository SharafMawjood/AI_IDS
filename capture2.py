import pyshark
import time

def calculate_flow_parameters(packet_list):
    # Initialize variables for flow parameters
    flow_start_time = None
    flow_end_time = None
    fwd_pkt_count = 0
    bwd_pkt_count = 0
    pkt_len_sum = 0
    fwd_pkt_len_sum = 0
    cwe_flag_count = 0
    ece_flag_count = 0
    pkt_lens = []

    # Iterate over the packets
    for pkt in packet_list:
        # Check if the packet is IPv4 and contains TCP
        if "IP" in pkt and "TCP" in pkt:
            # Extract relevant fields
            pkt_len = int(pkt.length)
            fwd_pkt_len = int(pkt.tcp.len)
            cwe_flags = int(pkt.cwe_flag_count)
            ece_flags = int(pkt.tcp.flags_ecn)

            # Update flow parameters
            if flow_start_time is None:
                flow_start_time = float(pkt.sniff_timestamp)
            flow_end_time = float(pkt.sniff_timestamp)
            fwd_pkt_count += 1
            pkt_len_sum += pkt_len
            fwd_pkt_len_sum += fwd_pkt_len
            cwe_flag_count += cwe_flags
            ece_flag_count += ece_flags
            pkt_lens.append(pkt_len)

    # Calculate derived parameters
    flow_duration = flow_end_time - flow_start_time
    active_std = calculate_std(pkt_lens)
    fwd_pkts_per_sec = fwd_pkt_count / flow_duration
    fwd_seg_size_min = min(pkt_lens) if pkt_lens else 0
    tot_bwd_pkts = bwd_pkt_count
    pkt_len_std = calculate_std(pkt_lens)
    fwd_pkt_len_mean = fwd_pkt_len_sum / fwd_pkt_count
    flow_iat_max = flow_end_time - flow_start_time
    fwd_iat_tot = flow_duration / fwd_pkt_count if fwd_pkt_count != 0 else 0

    return {
        "Flow Duration": flow_duration,
        "Active Std": active_std,
        "Tot Fwd Pkts": fwd_pkt_count,
        "Pkt Len Max": max(pkt_lens) if pkt_lens else 0,
        "CWE Flag Count": cwe_flag_count,
        "Pkt Len Min": min(pkt_lens) if pkt_lens else 0,
        "Fwd Pkts/s": fwd_pkts_per_sec,
        "ECE Flag Cnt": ece_flag_count,
        "Fwd Seg Size Min": fwd_seg_size_min,
        "Tot Bwd Pkts": tot_bwd_pkts,
        "Pkt Len Std": pkt_len_std,
        "Fwd Pkt Len Mean": fwd_pkt_len_mean,
        "Flow IAT Max": flow_iat_max,
        "Fwd IAT Tot": fwd_iat_tot
    }

def calculate_std(values):
    n = len(values)
    if n <= 1:
        return 0
    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / (n - 1)
    std_dev = variance ** 0.5
    return std_dev

def live_capture(interface, num_packets=100):
    # Start live capture
    capture = pyshark.LiveCapture(interface=interface)

    # Initialize list to store packets
    packet_list = []

    # Capture packets
    for pkt in capture.sniff_continuously(packet_count=num_packets):
        packet_list.append(pkt)

    # Calculate flow parameters
    flow_params = calculate_flow_parameters(packet_list)

    return flow_params

if __name__ == "__main__":
    # Specify the network interface for live capture
    network_interface = "Wi-Fi"

    # Specify the number of packets to capture
    num_packets_to_capture = 100

    # Perform live capture and calculate flow parameters
    result = live_capture(network_interface, num_packets=num_packets_to_capture)

    # Print the calculated flow parameters
    for param, value in result.items():
        print(f"{param}: {value}")
