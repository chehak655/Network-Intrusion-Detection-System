from statistics import mean, stdev, variance


class FeatureExtractor:
    """
    Produces the same named features CICFlowMeter generates for the
    CIC-IDS2017 CSVs (after column-name stripping), so the live feature
    vector lines up 1:1 with whatever columns train_final_xgboost.py
    selected. If a selected feature is missing here, prediction.py will
    silently zero-fill it and quietly degrade accuracy - so any new
    column added to feature_selection.py's whitelist must be added here
    too.
    """

    # The exact set of feature names this extractor can compute live.
    # feature_selection.py filters against this list so that whatever
    # gets chosen as "selected_features" is guaranteed to be
    # available at inference time (see main.py / prediction.py).
    LIVE_FEATURE_NAMES = [
        "Flow Duration", "Protocol", "Destination Port",
        "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets",
        "Fwd Packet Length Max", "Fwd Packet Length Min",
        "Fwd Packet Length Mean", "Fwd Packet Length Std",
        "Bwd Packet Length Max", "Bwd Packet Length Min",
        "Bwd Packet Length Mean", "Bwd Packet Length Std",
        "Flow Bytes/s", "Flow Packets/s",
        "Fwd Packets/s", "Bwd Packets/s",
        "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
        "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std",
        "Fwd IAT Max", "Fwd IAT Min",
        "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std",
        "Bwd IAT Max", "Bwd IAT Min",
        "Fwd PSH Flags", "Bwd PSH Flags",
        "Fwd URG Flags", "Bwd URG Flags",
        "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
        "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
        "CWE Flag Count", "ECE Flag Count",
        "Fwd Header Length", "Bwd Header Length",
        "Min Packet Length", "Max Packet Length",
        "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
        "Down/Up Ratio", "Average Packet Size",
        "Avg Fwd Segment Size", "Avg Bwd Segment Size",
        "Init_Win_bytes_forward", "Init_Win_bytes_backward",
        "act_data_pkt_fwd", "min_seg_size_forward",
        "Active Mean", "Active Std", "Active Max", "Active Min",
        "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
    ]

    @staticmethod
    def safe_mean(values):
        return mean(values) if values else 0

    @staticmethod
    def safe_std(values):
        return stdev(values) if len(values) > 1 else 0

    @staticmethod
    def safe_var(values):
        return variance(values) if len(values) > 1 else 0

    @staticmethod
    def extract(flow):

        duration = flow.duration()

        # CICFlowMeter reports Flow Duration in microseconds.
        duration_us = duration * 1_000_000

        safe_duration = duration if duration > 0 else 0.000001

        flow_iat = flow.flow_iat()
        fwd_iat = flow.forward_iat()
        bwd_iat = flow.backward_iat()

        features = {}

        # --------------------------------------------------
        # Basic flow info
        # --------------------------------------------------

        features["Flow Duration"] = duration_us
        features["Protocol"] = flow.protocol
        features["Destination Port"] = flow.dst_port

        # --------------------------------------------------
        # Packet counts / totals
        # --------------------------------------------------

        features["Total Fwd Packets"] = flow.forward_packets
        features["Total Backward Packets"] = flow.backward_packets

        features["Total Length of Fwd Packets"] = flow.forward_bytes
        features["Total Length of Bwd Packets"] = flow.backward_bytes

        # --------------------------------------------------
        # Per-direction packet length stats
        # --------------------------------------------------

        features["Fwd Packet Length Max"] = (
            max(flow.forward_packet_lengths)
            if flow.forward_packet_lengths else 0
        )
        features["Fwd Packet Length Min"] = (
            min(flow.forward_packet_lengths)
            if flow.forward_packet_lengths else 0
        )
        features["Fwd Packet Length Mean"] = FeatureExtractor.safe_mean(
            flow.forward_packet_lengths
        )
        features["Fwd Packet Length Std"] = FeatureExtractor.safe_std(
            flow.forward_packet_lengths
        )

        features["Bwd Packet Length Max"] = (
            max(flow.backward_packet_lengths)
            if flow.backward_packet_lengths else 0
        )
        features["Bwd Packet Length Min"] = (
            min(flow.backward_packet_lengths)
            if flow.backward_packet_lengths else 0
        )
        features["Bwd Packet Length Mean"] = FeatureExtractor.safe_mean(
            flow.backward_packet_lengths
        )
        features["Bwd Packet Length Std"] = FeatureExtractor.safe_std(
            flow.backward_packet_lengths
        )

        # --------------------------------------------------
        # Flow-level rate features
        # --------------------------------------------------

        features["Flow Bytes/s"] = flow.total_bytes() / safe_duration
        features["Flow Packets/s"] = flow.total_packets() / safe_duration

        features["Fwd Packets/s"] = flow.forward_packets / safe_duration
        features["Bwd Packets/s"] = flow.backward_packets / safe_duration

        # --------------------------------------------------
        # Inter-arrival times (microseconds, matching CICFlowMeter)
        # --------------------------------------------------

        flow_iat_us = [v * 1_000_000 for v in flow_iat]
        fwd_iat_us = [v * 1_000_000 for v in fwd_iat]
        bwd_iat_us = [v * 1_000_000 for v in bwd_iat]

        features["Flow IAT Mean"] = FeatureExtractor.safe_mean(flow_iat_us)
        features["Flow IAT Std"] = FeatureExtractor.safe_std(flow_iat_us)
        features["Flow IAT Max"] = max(flow_iat_us) if flow_iat_us else 0
        features["Flow IAT Min"] = min(flow_iat_us) if flow_iat_us else 0

        features["Fwd IAT Total"] = sum(fwd_iat_us)
        features["Fwd IAT Mean"] = FeatureExtractor.safe_mean(fwd_iat_us)
        features["Fwd IAT Std"] = FeatureExtractor.safe_std(fwd_iat_us)
        features["Fwd IAT Max"] = max(fwd_iat_us) if fwd_iat_us else 0
        features["Fwd IAT Min"] = min(fwd_iat_us) if fwd_iat_us else 0

        features["Bwd IAT Total"] = sum(bwd_iat_us)
        features["Bwd IAT Mean"] = FeatureExtractor.safe_mean(bwd_iat_us)
        features["Bwd IAT Std"] = FeatureExtractor.safe_std(bwd_iat_us)
        features["Bwd IAT Max"] = max(bwd_iat_us) if bwd_iat_us else 0
        features["Bwd IAT Min"] = min(bwd_iat_us) if bwd_iat_us else 0

        # --------------------------------------------------
        # TCP flags
        # --------------------------------------------------

        features["Fwd PSH Flags"] = flow.fwd_psh_count
        features["Bwd PSH Flags"] = flow.bwd_psh_count
        features["Fwd URG Flags"] = flow.fwd_urg_count
        features["Bwd URG Flags"] = flow.bwd_urg_count

        features["FIN Flag Count"] = flow.fin_count
        features["SYN Flag Count"] = flow.syn_count
        features["RST Flag Count"] = flow.rst_count
        features["PSH Flag Count"] = flow.psh_count
        features["ACK Flag Count"] = flow.ack_count
        features["URG Flag Count"] = flow.urg_count
        features["CWE Flag Count"] = flow.cwe_count
        features["ECE Flag Count"] = flow.ece_count

        # --------------------------------------------------
        # Header lengths
        # --------------------------------------------------

        features["Fwd Header Length"] = flow.forward_header_bytes
        features["Bwd Header Length"] = flow.backward_header_bytes

        # --------------------------------------------------
        # Overall packet length stats
        # --------------------------------------------------

        features["Min Packet Length"] = flow.min_packet_length()
        features["Max Packet Length"] = flow.max_packet_length()
        features["Packet Length Mean"] = FeatureExtractor.safe_mean(
            flow.packet_lengths
        )
        features["Packet Length Std"] = flow.packet_length_std()
        features["Packet Length Variance"] = flow.packet_length_variance()

        # --------------------------------------------------
        # Ratios / averages
        # --------------------------------------------------

        features["Down/Up Ratio"] = flow.down_up_ratio()
        features["Average Packet Size"] = flow.average_packet_size()
        features["Avg Fwd Segment Size"] = FeatureExtractor.safe_mean(
            flow.forward_packet_lengths
        )
        features["Avg Bwd Segment Size"] = FeatureExtractor.safe_mean(
            flow.backward_packet_lengths
        )

        # --------------------------------------------------
        # TCP window / segment features
        # --------------------------------------------------

        features["Init_Win_bytes_forward"] = (
            flow.init_win_bytes_forward
            if flow.init_win_bytes_forward != -1 else 0
        )
        features["Init_Win_bytes_backward"] = (
            flow.init_win_bytes_backward
            if flow.init_win_bytes_backward != -1 else 0
        )

        features["act_data_pkt_fwd"] = flow.fwd_data_packet_count

        features["min_seg_size_forward"] = (
            flow.min_seg_size_forward
            if flow.min_seg_size_forward is not None else 0
        )

        # --------------------------------------------------
        # Active / Idle timing
        # --------------------------------------------------

        features["Active Mean"] = FeatureExtractor.safe_mean(
            [v * 1_000_000 for v in flow.active_periods]
        )
        features["Active Std"] = FeatureExtractor.safe_std(
            [v * 1_000_000 for v in flow.active_periods]
        )
        features["Active Max"] = (
            max(flow.active_periods) * 1_000_000
            if flow.active_periods else 0
        )
        features["Active Min"] = (
            min(flow.active_periods) * 1_000_000
            if flow.active_periods else 0
        )

        features["Idle Mean"] = FeatureExtractor.safe_mean(
            [v * 1_000_000 for v in flow.idle_periods]
        )
        features["Idle Std"] = FeatureExtractor.safe_std(
            [v * 1_000_000 for v in flow.idle_periods]
        )
        features["Idle Max"] = (
            max(flow.idle_periods) * 1_000_000
            if flow.idle_periods else 0
        )
        features["Idle Min"] = (
            min(flow.idle_periods) * 1_000_000
            if flow.idle_periods else 0
        )

        return features