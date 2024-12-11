from scapy.all import rdpcap
import matplotlib.pyplot as plt
from pathlib import Path

# Correct the file path
pcap_file = Path(r'Thesis Data\attendence 30min.pcap')

# Load the PCAP file
packets = rdpcap(str(pcap_file))

# Extract timestamps and calculate time intervals
time_intervals = []
packet_numbers = []

last_time = None  # Store the last packet timestamp

for index, packet in enumerate(packets):
    if hasattr(packet, 'time'):  # Check if the packet has a timestamp
        current_time = packet.time  # Current packet timestamp
        if last_time is not None:
            time_intervals.append(current_time - last_time)  # Calculate time interval
            packet_numbers.append(index)  # Packet number
        last_time = current_time  # Update the last time

# Plot the time intervals between packets
plt.figure(figsize=(10, 6))
plt.plot(packet_numbers, time_intervals, marker='o', linestyle='-', label="Time Interval (s)")

# Add labels, title, and legend
plt.xlabel("Packet Number")
plt.ylabel("Time Interval (seconds)")
plt.title("Time Intervals Between Packets")
plt.legend()
plt.grid(True)

# Save and show the plot
plt.savefig("time_intervals_plot.png")
plt.show()

print("Plot saved as 'time_intervals_plot.png'")
