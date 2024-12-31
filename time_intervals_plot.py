from scapy.all import rdpcap
import matplotlib.pyplot as plt
from pathlib import Path

# Add file paths for all devices
pcap_files = [
    Path(r'ThesisData\indiv_pcap_dir\att_sent_uprint_15_1_84_f3_eb_0d_7f_2e.pcap'),  # Sentry
    Path(r'ThesisData\indiv_pcap_dir\att_sent_uprint_15_1_84_f3_eb_0d_7f_2e.pcap'),  # Uprint
    Path(r'ThesisData\indiv_pcap_dir\att_sent_uprint_15_1_9c_9c_1f_0c_88_68.pcap'),  # Online Attendance
    Path(r'ThesisData\indiv_pcap_dir\smart_plug_software_40_4c_ca_f9_83_fc.pcap'),   # Smart Plug
    # Path(r'ThesisData\indiv_pcap_dir\Amazon Alexa Eco Dot 1 BT_1c_fe_2b_98_16_dd.pcap'),  # Alexa Eco Dot
    # Path(r'ThesisData\indiv_pcap_dir\Amazon plug BT1_b8_5f_98_d0_76_e6.pcap'),  # Amazon Plug
    # Path(r'ThesisData\indiv_pcap_dir\AMCREST WIFI CAMERA BT_9c_8e_cd_1d_ab_9f.pcap'),  # Baby Monitor
    # Path(r'ThesisData\indiv_pcap_dir\Gosund Bulb BT_3c_18_a0_41_c3_a0.pcap'),  # Breast Cancer Detector
    # Path(r'ThesisData\indiv_pcap_dir\Smart Board  BT_00_02_75_f6_e3_cb.pcap'),  # Smart Board
    # Path(r'ThesisData\indiv_pcap_dir\LG SMART TV BT_ac_f1_08_4e_00_82.pcap'),  # Smart TV
    # Path(r'ThesisData\indiv_pcap_dir\Surveillance_Camera_b0_c5_54_59_2e_99.pcap'),  # Surveillance Camera
    Path(r'ThesisData\indiv_pcap_dir\Netatmo Weather Station BT1_70_ee_50_6b_a8_1a.pcap'),  # Weather Station
    # Path(r'ThesisData\indiv_pcap_dir\Atomic Coffee maker BT_68_57_2d_56_ac_47.pcap')  # Coffee Maker
]

# Device labels corresponding to the files
device_labels = [
    'Sentry',
    'Uprint',
    'Online Attendance',
    'Smart Plug',
    # 'Alexa Eco Dot',
    # 'Amazon Plug',
#     'Baby Monitor',
#     'Breast Cancer Detector',
#     'Smart Board',
#     'Smart TV',
#     'Surveillance Camera',
    'Weather Station',
#     'Coffee Maker'
]

# Function to calculate time intervals from a PCAP file
def calculate_time_intervals(pcap_file):
    packets = rdpcap(str(pcap_file))  # Convert Path object to string
    packets = packets[50:250]  # Take packets 10 to 500
    time_intervals = []
    packet_numbers = []
    last_time = None

    for index, packet in enumerate(packets):
        if hasattr(packet, 'time'):
            current_time = packet.time
            if last_time is not None:
                interval = current_time - last_time
                if interval < 20:  # Slice out intervals that are 20 seconds or more
                    time_intervals.append(interval)
                    packet_numbers.append(index)
            last_time = current_time

    return packet_numbers, time_intervals

# Create the main figure
fig = plt.figure(figsize=(8, 6 * len(pcap_files)))
grid = plt.GridSpec(len(pcap_files), 1, height_ratios=[1] * len(pcap_files), wspace=0.4, hspace=0.6)

# Plot for each device
for i, (pcap_file, label) in enumerate(zip(pcap_files, device_labels)):
    # Calculate time intervals
    packet_numbers, time_intervals = calculate_time_intervals(pcap_file)
    
    # Plot the time intervals on the right
    ax = fig.add_subplot(grid[i])
    ax.plot(packet_numbers, time_intervals, marker='.', linestyle='', label=label)
    ax.grid(True)
    ax.legend(loc='upper right', fontsize=10)

# Add X and Y labels centered for the entire plot
fig.text(0.5, 0.04, 'Packet Number', ha='center', fontsize=14)
fig.text(0.04, 0.5, 'Time Interval Between Two Packets (Sec)', va='center', rotation='vertical', fontsize=14)

# Adjust layout manually
plt.subplots_adjust(left=0.1, right=0.9, top=0.98, bottom=0.12)

# Save the plot and show
plt.savefig("all_devices_time_intervals_with_legend.png")
plt.show()

print("Combined plot saved as 'all_devices_time_intervals_with_legend.png'")
