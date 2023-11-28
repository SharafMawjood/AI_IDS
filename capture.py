# from scapy.all import sniff
# import admin

# if not admin.isUserAdmin():
#     admin.runAsAdmin()

# def process_packet(packet):
#     # Process and print the details of each captured packet
#     print(packet.show())

# # Start capturing packets on the network interface
# # You may need administrative privileges to capture on some interfaces
# sniff(prn=process_packet)

import pyshark

# import psutil

# addrs = psutil.net_if_addrs()
# print(addrs.keys())

# while True:
capture = pyshark.LiveCapture(interface="Wi-Fi")
capture.set_debug()
capture.sniff(timeout=100)
for packet in capture:
    if "IP" in packet and "TCP" in packet:
    # Check if the TCP stream exists
        if hasattr(packet.tcp, 'time_relative') and hasattr(packet.tcp, 'stream'):
            # Extract the TCP stream and time since the first frame
            tcp_stream = packet.tcp.stream
            time_since_first_frame = packet.tcp.time_relative
            print(time_since_first_frame)

capture.close()