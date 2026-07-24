from statistics import mean, stdev, variance
from datetime import datetime


# Flows are considered "active" if the gap between consecutive packets is
# below this threshold. A bigger gap starts an "idle" period. This mirrors
# the Active/Idle logic CICFlowMeter uses when it built the CIC-IDS2017
# dataset, which is what the models were trained on.
ACTIVE_TIMEOUT = 5.0  # seconds


class Flow:
    """
    Represents one bidirectional network flow and accumulates every
    statistic needed to reproduce CICFlowMeter-style features live,
    so the trained models see the same feature space at inference
    time as they did during training.
    """

    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):

        # Flow Information
        self.src_ip = src_ip
        self.dst_ip = dst_ip

        self.src_port = src_port
        self.dst_port = dst_port

        self.protocol = protocol

        # Used by FlowManager to determine packet direction
        self.initiator = None

        # Timing
        self.start_time = None
        self.end_time = None
        self.last_packet_time = None

        # Packet lengths
        self.packet_lengths = []

        self.forward_packet_lengths = []
        self.backward_packet_lengths = []

        # Packet timestamps
        self.timestamps = []

        self.forward_timestamps = []
        self.backward_timestamps = []

        # Packet counters
        self.forward_packets = 0
        self.backward_packets = 0

        # Byte counters
        self.forward_bytes = 0
        self.backward_bytes = 0

        # Header bytes (IP header + TCP/UDP header, per packet)
        self.forward_header_bytes = 0
        self.backward_header_bytes = 0

        # TCP window size of the very first packet in each direction
        self.init_win_bytes_forward = -1
        self.init_win_bytes_backward = -1

        # TCP flags - overall
        self.syn_count = 0
        self.ack_count = 0
        self.fin_count = 0
        self.psh_count = 0
        self.rst_count = 0
        self.urg_count = 0
        self.cwe_count = 0
        self.ece_count = 0

        # TCP flags - per direction (only PSH/URG are tracked per-direction
        # in CICFlowMeter's original feature set)
        self.fwd_psh_count = 0
        self.bwd_psh_count = 0
        self.fwd_urg_count = 0
        self.bwd_urg_count = 0

        # Count of forward packets that carry a data payload
        # (used for act_data_pkt_fwd)
        self.fwd_data_packet_count = 0

        # Smallest forward segment size seen (min_seg_size_forward)
        self.min_seg_size_forward = None

        # Active / Idle period tracking
        self.active_periods = []
        self.idle_periods = []
        self._current_period_start = None
        self._current_period_last = None

    # --------------------------------------------------------------
    # Packet ingestion
    # --------------------------------------------------------------

    def add_packet(
        self,
        packet_length,
        direction,
        timestamp,
        tcp_flags="",
        header_length=0,
        window_size=None,
        payload_size=0
    ):

        if self.start_time is None:
            self.start_time = timestamp

        self._update_active_idle(timestamp)

        self.end_time = timestamp
        self.last_packet_time = timestamp

        self.packet_lengths.append(packet_length)
        self.timestamps.append(timestamp)

        if direction == "forward":

            self.forward_packets += 1
            self.forward_bytes += packet_length
            self.forward_header_bytes += header_length

            self.forward_packet_lengths.append(packet_length)
            self.forward_timestamps.append(timestamp)

            if self.init_win_bytes_forward == -1 and window_size is not None:
                self.init_win_bytes_forward = window_size

            if payload_size > 0:
                self.fwd_data_packet_count += 1

            if self.min_seg_size_forward is None:
                self.min_seg_size_forward = header_length
            else:
                self.min_seg_size_forward = min(
                    self.min_seg_size_forward, header_length
                )

        else:

            self.backward_packets += 1
            self.backward_bytes += packet_length
            self.backward_header_bytes += header_length

            self.backward_packet_lengths.append(packet_length)
            self.backward_timestamps.append(timestamp)

            if self.init_win_bytes_backward == -1 and window_size is not None:
                self.init_win_bytes_backward = window_size

        flags = str(tcp_flags)

        if "S" in flags:
            self.syn_count += 1

        if "A" in flags:
            self.ack_count += 1

        if "F" in flags:
            self.fin_count += 1

        if "P" in flags:
            self.psh_count += 1

            if direction == "forward":
                self.fwd_psh_count += 1
            else:
                self.bwd_psh_count += 1

        if "R" in flags:
            self.rst_count += 1

        if "U" in flags:
            self.urg_count += 1

            if direction == "forward":
                self.fwd_urg_count += 1
            else:
                self.bwd_urg_count += 1

        if "C" in flags:
            self.cwe_count += 1

        if "E" in flags:
            self.ece_count += 1

    def _update_active_idle(self, timestamp):
        """
        Splits the flow's lifetime into "active" bursts and "idle" gaps,
        the same way CICFlowMeter does, so Active/Idle Mean/Std/Max/Min
        can be reproduced.
        """

        if self._current_period_start is None:
            self._current_period_start = timestamp
            self._current_period_last = timestamp
            return

        gap = (timestamp - self._current_period_last).total_seconds()

        if gap <= ACTIVE_TIMEOUT:
            # still within the same active burst
            self._current_period_last = timestamp
            return

        # Gap exceeds the threshold: close out the active burst, log an
        # idle period, and start a new active burst.
        active_duration = (
            self._current_period_last - self._current_period_start
        ).total_seconds()

        self.active_periods.append(active_duration)
        self.idle_periods.append(gap)

        self._current_period_start = timestamp
        self._current_period_last = timestamp

    # --------------------------------------------------------------
    # Derived statistics
    # --------------------------------------------------------------

    def duration(self):

        if self.start_time is None or self.end_time is None:
            return 0

        return max(
            (self.end_time - self.start_time).total_seconds(),
            0
        )

    def total_packets(self):
        return self.forward_packets + self.backward_packets

    def total_bytes(self):
        return self.forward_bytes + self.backward_bytes

    def average_packet_size(self):

        if not self.packet_lengths:
            return 0

        return mean(self.packet_lengths)

    def packet_length_std(self):

        if len(self.packet_lengths) < 2:
            return 0

        return stdev(self.packet_lengths)

    def packet_length_variance(self):

        if len(self.packet_lengths) < 2:
            return 0

        return variance(self.packet_lengths)

    def packets_per_second(self):

        duration = self.duration()

        if duration <= 0:
            return 0

        return self.total_packets() / duration

    def bytes_per_second(self):

        duration = self.duration()

        if duration <= 0:
            return 0

        return self.total_bytes() / duration

    def forward_packet_mean(self):

        if not self.forward_packet_lengths:
            return 0

        return mean(self.forward_packet_lengths)

    def backward_packet_mean(self):

        if not self.backward_packet_lengths:
            return 0

        return mean(self.backward_packet_lengths)

    def forward_packet_std(self):

        if len(self.forward_packet_lengths) < 2:
            return 0

        return stdev(self.forward_packet_lengths)

    def backward_packet_std(self):

        if len(self.backward_packet_lengths) < 2:
            return 0

        return stdev(self.backward_packet_lengths)

    def max_packet_length(self):

        if not self.packet_lengths:
            return 0

        return max(self.packet_lengths)

    def min_packet_length(self):

        if not self.packet_lengths:
            return 0

        return min(self.packet_lengths)

    @staticmethod
    def _inter_arrival_times(timestamps):

        if len(timestamps) < 2:
            return []

        return [
            (t2 - t1).total_seconds()
            for t1, t2 in zip(timestamps[:-1], timestamps[1:])
        ]

    def flow_iat(self):
        return self._inter_arrival_times(self.timestamps)

    def forward_iat(self):
        return self._inter_arrival_times(self.forward_timestamps)

    def backward_iat(self):
        return self._inter_arrival_times(self.backward_timestamps)

    def down_up_ratio(self):

        if self.forward_packets == 0:
            return 0

        return self.backward_packets / self.forward_packets

    def flow_summary(self):

        return {
            "Source IP": self.src_ip,
            "Destination IP": self.dst_ip,
            "Source Port": self.src_port,
            "Destination Port": self.dst_port,
            "Protocol": self.protocol,
            "Duration": self.duration(),
            "Forward Packets": self.forward_packets,
            "Backward Packets": self.backward_packets,
            "Forward Bytes": self.forward_bytes,
            "Backward Bytes": self.backward_bytes,
            "Total Packets": self.total_packets(),
            "Total Bytes": self.total_bytes(),
            "Average Packet Size": self.average_packet_size(),
            "Packet Length Std": self.packet_length_std(),
            "Packets/sec": self.packets_per_second(),
            "Bytes/sec": self.bytes_per_second(),
            "SYN Flags": self.syn_count,
            "ACK Flags": self.ack_count,
            "FIN Flags": self.fin_count,
            "PSH Flags": self.psh_count,
            "RST Flags": self.rst_count
        }

    def is_finished(self, timeout=30):
        """
        Returns True if the flow has been inactive long enough.
        This prevents splitting a TCP connection into multiple flows.
        """

        if self.end_time is None:
            return False

        inactive_time = (
            datetime.now() - self.end_time
        ).total_seconds()

        return inactive_time >= timeout