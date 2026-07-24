from detection.prediction import Predictor
from flows.flow_manager import FlowManager
from flows.feature_extractor import FeatureExtractor
from datetime import datetime, timedelta

fm = FlowManager()

t1 = datetime.now()
t2 = t1 + timedelta(milliseconds=50)
t3 = t2 + timedelta(milliseconds=20)

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

predictor = Predictor()

result = predictor.predict(features)

print("\nPrediction\n")

for k, v in result.items():
    if k == "Missing Features":
        continue
    print(f"{k:15}: {v}")

if result["Missing Features"]:
    print(
        "\nWARNING: the model expects features this extractor didn't "
        "produce (defaulted to 0):", result["Missing Features"]
    )
else:
    print("\nAll model features were computed live - no gaps. OK")