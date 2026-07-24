from datetime import datetime

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

from flows.flow_manager import FlowManager
from flows.feature_extractor import FeatureExtractor
from detection.prediction import Predictor
from database.db import Database
import os
import logging

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/capture.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)


# ==========================================================
# Initialize Components
# ==========================================================

flow_manager = FlowManager()
predictor = Predictor()
database = Database()


# ==========================================================
# Process Each Packet
# ==========================================================

def process_packet(packet):

    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = packet[IP].proto

    packet_length = len(packet)
    timestamp = datetime.fromtimestamp(float(packet.time))

    # IP header length (ihl is in 32-bit words)
    header_length = packet[IP].ihl * 4

    src_port = 0
    dst_port = 0
    tcp_flags = ""
    window_size = None
    payload_size = 0

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        tcp_flags = str(packet[TCP].flags)

        # dataofs is the TCP header length in 32-bit words
        header_length += packet[TCP].dataofs * 4 if packet[TCP].dataofs else 20

        window_size = int(packet[TCP].window)

        if packet[TCP].payload:
            payload_size = len(packet[TCP].payload)

    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

        header_length += 8  # fixed UDP header size

        if packet[UDP].payload:
            payload_size = len(packet[UDP].payload)

    # --------------------------------------------------
    # Add Packet to Flow Manager
    # --------------------------------------------------

    flow_manager.process_packet(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        packet_length,
        timestamp,
        tcp_flags,
        header_length=header_length,
        window_size=window_size,
        payload_size=payload_size
    )

    # --------------------------------------------------
    # Get Completed Flows
    # --------------------------------------------------

    completed_flows = flow_manager.get_completed_flows()

    for flow in completed_flows:

        # Ignore tiny flows
        if flow.total_packets() < 2:
            continue

        if flow.total_bytes() < 100:
            continue

        # --------------------------------------------------
        # Extract Features
        # --------------------------------------------------

        features = FeatureExtractor.extract(flow)

        # --------------------------------------------------
        # Predict
        # --------------------------------------------------

        result = predictor.predict(features)

        logging.info(
            "Detection | Time=%s | Src=%s:%s | Dst=%s:%s | Protocol=%s | Attack=%s | "
            "Confidence=%.4f | Anomaly=%s | Score=%.4f | ""Duration=%.4f | Packets=%d | Bytes=%d",
            flow.end_time,
            flow.src_ip,
            flow.src_port,
            flow.dst_ip,
            flow.dst_port,
            flow.protocol,
            result["Attack"],
            result["Confidence"],
            result["Anomaly"],
            result["Anomaly Score"],
            flow.duration(),
            flow.total_packets(),
            flow.total_bytes()
        )
        # --------------------------------------------------
        # Print Result
        # --------------------------------------------------

        print("\n" + "=" * 80)
        print("AI NETWORK INTRUSION DETECTION RESULT")
        print("=" * 80)

        print(f"Time             : {flow.end_time}")
        print(f"Source IP        : {flow.src_ip}")
        print(f"Destination IP   : {flow.dst_ip}")
        print(f"Source Port      : {flow.src_port}")
        print(f"Destination Port : {flow.dst_port}")
        print(f"Protocol         : {flow.protocol}")

        print("-" * 80)

        print(f"Attack           : {result['Attack']}")
        print(f"Confidence       : {result['Confidence']:.4f}")
        print(f"Anomaly          : {result['Anomaly']}")
        print(f"Anomaly Score    : {result['Anomaly Score']:.4f}")

        if result.get("Missing Features"):
            print("-" * 80)
            print(
                "WARNING: model expected features not produced by "
                "the live extractor:", result["Missing Features"]
            )

        print("-" * 80)

        print(f"Duration         : {flow.duration():.4f} sec")
        print(f"Packets          : {flow.total_packets()}")
        print(f"Bytes            : {flow.total_bytes()}")

        print("=" * 80)

        # --------------------------------------------------
        # Save to MySQL
        # --------------------------------------------------

        try:

            database.insert_detection(

                timestamp=flow.end_time,

                source_ip=flow.src_ip,
                destination_ip=flow.dst_ip,

                source_port=flow.src_port,
                destination_port=flow.dst_port,

                protocol=flow.protocol,

                attack=result["Attack"],

                confidence=float(result["Confidence"]),

                anomaly=int(result["Anomaly"]),

                anomaly_score=float(result["Anomaly Score"]),

                duration=float(flow.duration()),

                total_packets=int(flow.total_packets()),

                total_bytes=int(flow.total_bytes())

            )

        except Exception as e:

            logging.error("Database Error: %s", e)
            print("\nDatabase Error:", e)


# ==========================================================
# Start IDS
# ==========================================================

print("=" * 80)
print(" AI-BASED NETWORK INTRUSION DETECTION SYSTEM ")
print("=" * 80)
print("Listening for live network traffic...")
print("Press Ctrl + C to stop.\n")

logging.info("AI-Based Network Intrusion Detection System started.")
logging.info("Packet capture started.")

try:

    sniff(
        prn=process_packet,
        store=False
    )

except KeyboardInterrupt:

    logging.info("Stopping IDS...")
    print("\nStopping IDS...")

finally:

    database.close()

    logging.info("MySQL connection closed.")
    logging.info("IDS stopped successfully.")

    print("MySQL connection closed.")
    print("IDS stopped successfully.")