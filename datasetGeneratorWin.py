import os
import pandas as pd
from scapy.all import rdpcap, wrpcap, Ether, IP, TCP, UDP

def split_pcap_by_mac(input_pcap, basename, output_dir, excluded_mac=None):
    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Read packets from the input PCAP file
    packets = rdpcap(input_pcap)

    # Dictionary to group packets by MAC address
    mac_packets = {}
    individual_pcaps = []

    for packet in packets:
        if Ether in packet:
            src_mac = packet[Ether].src
            if excluded_mac and src_mac == excluded_mac:
                continue  # Skip packets with the excluded MAC
            if src_mac not in mac_packets:
                mac_packets[src_mac] = []
            mac_packets[src_mac].append(packet)

    # Write each group of packets to a separate PCAP file
    for mac, packet_list in mac_packets.items():
        output_file = os.path.join(output_dir, f"{basename}_{mac.replace(':', '_')}.pcap")
        wrpcap(output_file, packet_list)
        individual_pcaps.append(output_file)
        print(f"Saved {len(packet_list)} packets for MAC {mac} to {output_file}")
    
    print("PCAP splitting complete!")
    return individual_pcaps

def pcap_to_csv(pcap_file, csv_file):
    try:
        packets = rdpcap(pcap_file)
        data = []

        for packet in packets:
            if Ether in packet:
                # Initialize a row with default values
                row = {
                    "Timestamp": packet.time if hasattr(packet, 'time') else 0.0,
                    "Source MAC": packet[Ether].src if hasattr(packet[Ether], 'src') else "0.0",
                    "Destination MAC": packet[Ether].dst if hasattr(packet[Ether], 'dst') else "0.0",
                    "Packet Length": len(packet) if packet else 0.0,
                    "Source IP": "0.0",
                    "Destination IP": "0.0",
                    "Protocol": 0.0,
                    "Source Port": 0.0,
                    "Destination Port": 0.0,
                    "TTL": 0.0,  # Time-to-live
                    "Window Size": 0.0,  # TCP Window Size
                    "Checksum": 0.0,  # IP/TCP/UDP checksum
                }

                # Check for IP layer and associated fields
                if IP in packet:
                    row["Source IP"] = packet[IP].src
                    row["Destination IP"] = packet[IP].dst
                    row["Protocol"] = packet[IP].proto
                    row["TTL"] = packet[IP].ttl if hasattr(packet[IP], 'ttl') else 0.0
                    row["Checksum"] = packet[IP].chksum if hasattr(packet[IP], 'chksum') else 0.0

                # Check for TCP or UDP and extract ports and specific fields
                if TCP in packet:
                    row["Source Port"] = packet[TCP].sport
                    row["Destination Port"] = packet[TCP].dport
                    row["Window Size"] = packet[TCP].window if hasattr(packet[TCP], 'window') else 0.0
                    row["Checksum"] = packet[TCP].chksum if hasattr(packet[TCP], 'chksum') else 0.0
                elif UDP in packet:
                    row["Source Port"] = packet[UDP].sport
                    row["Destination Port"] = packet[UDP].dport
                    row["Checksum"] = packet[UDP].chksum if hasattr(packet[UDP], 'chksum') else 0.0

                # Add the row to the data list
                data.append(row)

        # Save extracted data to a CSV file
        df = pd.DataFrame(data)
        df.to_csv(csv_file, index=False)
        print(f"Converted {pcap_file} to {csv_file}")

    except Exception as e:
        print(f"Error processing {pcap_file}: {e}")

def batch_convert_pcap_to_csv(pcap_files, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for pcap_file in pcap_files:
        output_path = os.path.join(output_dir, os.path.basename(pcap_file).replace(".pcap", ".csv"))
        pcap_to_csv(pcap_file, output_path)

def main(input_pcap, individual_pcap_directory, csv_directory, excluded_mac=None):
    # Split the input PCAP file by MAC address and get the list of individual PCAP files
    basename = os.path.splitext(os.path.basename(input_pcap))[0]
    individual_pcaps = split_pcap_by_mac(input_pcap, basename, individual_pcap_directory, excluded_mac)

    # Batch convert the individual PCAP files to CSV
    batch_convert_pcap_to_csv(individual_pcaps, csv_directory)

if __name__ == "__main__":
    # Change these paths as needed
    input_pcap_file = r"ThesisData\fahim\dec_8_sentry.pcap"  # Replace with your main PCAP file path
    individual_pcap_directory = r"ThesisData\indiv_pcap_dir"  # Replace with the folder containing PCAP files
    csv_directory = r"ThesisData\csv_files"  # Replace with the folder for saving output files
    excluded_mac_address = "d4:6e:0e:76:ef:10"  # Replace with MAC to exclude, if any

    print("Starting batch conversion of PCAP files to CSV and splitting by MAC address...")
    main(input_pcap_file, individual_pcap_directory, csv_directory, excluded_mac_address)
    print("Process completed.")
