from flows.flow_manager import FlowManager
from flows.feature_extractor import FeatureExtractor
from datetime import datetime, timedelta

fm = FlowManager()

t1 = datetime.now()
t2 = t1 + timedelta(milliseconds=50)   # 50 ms later
t3 = t2 + timedelta(milliseconds=20)

# Forward packet: client -> server (SYN)
fm.process_packet(
    "192.168.1.2",
    "8.8.8.8",
    50000,
    443,
    6,
    500,
    t1,
    "S",
    header_length=40,
    window_size=64240,
    payload_size=0
)

# Backward packet: server -> client (SYN-ACK)
fm.process_packet(
    "8.8.8.8",
    "192.168.1.2",
    443,
    50000,
    6,
    800,
    t2,
    "SA",
    header_length=40,
    window_size=29200,
    payload_size=0
)

# Forward packet with payload: client -> server (ACK + data)
fm.process_packet(
    "192.168.1.2",
    "8.8.8.8",
    50000,
    443,
    6,
    250,
    t3,
    "PA",
    header_length=32,
    window_size=64240,
    payload_size=196
)

flow = list(fm.get_active_flows().values())[0]

features = FeatureExtractor.extract(flow)

print("\nExtracted Features\n")

for k, v in features.items():
    print(f"{k:32}: {v}")

# --------------------------------------------------------------
# Sanity check: every feature the training pipeline is allowed to
# select from must actually be produced here. If this list is ever
# non-empty, feature_selection.py and this extractor have drifted
# out of sync.
# --------------------------------------------------------------

missing = set(FeatureExtractor.LIVE_FEATURE_NAMES) - set(features.keys())

print("\nLive-computable features declared :", len(FeatureExtractor.LIVE_FEATURE_NAMES))
print("Features actually produced        :", len(features))
print("Missing (should be empty)         :", missing if missing else "None - OK")