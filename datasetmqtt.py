import os
import pandas as pd
import pyshark

def extract_mqtt_tcp_features(pcap_file, csv_file):
    try:
        cap = pyshark.FileCapture(pcap_file, display_filter="mqtt or tcp")
        data = []

        for packet in cap:
            row = {
                "Timestamp": packet.sniff_time.strftime("%Y-%m-%d %H:%M:%S.%f"),
                "TCP Time Delta": packet.tcp.time_delta if hasattr(packet, "tcp") and hasattr(packet.tcp, "time_delta") else "N/A",
                "TCP Flags": packet.tcp.flags if hasattr(packet, "tcp") and hasattr(packet.tcp, "flags") else "N/A",
                "TCP Segment Length": packet.tcp.len if hasattr(packet, "tcp") and hasattr(packet.tcp, "len") else "N/A",
                "MQTT Message": packet.mqtt.msg if hasattr(packet, "mqtt") and hasattr(packet.mqtt, "msg") else "N/A",
                "MQTT DUP Flag": packet.mqtt.dupflag if hasattr(packet, "mqtt") and hasattr(packet.mqtt, "dupflag") else "N/A",
                "MQTT Message Length": packet.mqtt.len if hasattr(packet, "mqtt") and hasattr(packet.mqtt, "len") else "N/A",
                "MQTT Header Flags": packet.mqtt.hdrflags if hasattr(packet, "mqtt") and hasattr(packet.mqtt, "hdrflags") else "N/A",
                "MQTT Message ID": packet.mqtt.msgid if hasattr(packet, "mqtt") and hasattr(packet.mqtt, "msgid") else "N/A",
                "MQTT QoS": packet.mqtt.qos if hasattr(packet, "mqtt") and hasattr(packet.mqtt, "qos") else "N/A",
                "MQTT ConnAck Flags": packet.mqtt.conack_flags if hasattr(packet, "mqtt") and hasattr(packet.mqtt, "conack_flags") else "N/A",
            }
            data.append(row)

        cap.close()

        df = pd.DataFrame(data)
        df.to_csv(csv_file, index=False)
        print(f"Extracted MQTT & TCP features from {pcap_file} to {csv_file}")

    except Exception as e:
        print(f"Error processing {pcap_file}: {e}")

def batch_extract_mqtt_tcp_features(pcap_files, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for pcap_file in pcap_files:
        output_path = os.path.join(output_dir, os.path.basename(pcap_file).replace(".pcap", "_mqtt_tcp.csv"))
        extract_mqtt_tcp_features(pcap_file, output_path)

if __name__ == "__main__":
    input_pcap_file = r"ThesisData\indiv_pcap_dir\att_sent_uprint_dec_15_2_84_f3_eb_0d_7f_2e.pcap"
    csv_output_dir = r"ThesisData\csv_mqtt_tcp_files"

    print("Extracting MQTT and TCP features from PCAP files...")
    batch_extract_mqtt_tcp_features([input_pcap_file], csv_output_dir)
    print("Feature extraction complete!")
