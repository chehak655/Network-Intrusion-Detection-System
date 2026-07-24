from datetime import datetime
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

from flows.flow_manager import FlowManager

flow_manager = FlowManager()


def process_packet(packet):

    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = packet[IP].proto

    packet_length = len(packet)

    # Use packet capture time instead of datetime.now()
    timestamp = datetime.fromtimestamp(packet.time)

    src_port = None
    dst_port = None
    tcp_flags = ""

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        tcp_flags = str(packet[TCP].flags)

    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    flow_manager.process_packet(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        packet_length,
        timestamp,
        tcp_flags
    )

    total_packets = sum(
        flow.total_packets()
        for flow in flow_manager.get_active_flows().values()
    )

    if total_packets % 20 == 0:
        flow_manager.print_summary()


def start_capture():

    print("\nStarting Packet Capture...\n")

    sniff(
        prn=process_packet,
        store=False,
        timeout=30
    )


if __name__ == "__main__":
    start_capture()