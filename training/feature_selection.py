import os
import sys
import pandas as pd
import matplotlib.pyplot as plt

# Make the "flows" package importable from the training/ folder so we
# can reuse the extractor's whitelist of live-computable feature names.
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from flows.feature_extractor import FeatureExtractor

print("=" * 80)
print("FEATURE SELECTION")
print("=" * 80)

# -------------------------------------------------------
# Load Feature Importance
# -------------------------------------------------------

feature_importance = pd.read_csv(
    "models/feature_importance.csv"
)

print("\nTotal Features (from training data)")

print(len(feature_importance))

# -------------------------------------------------------
# Restrict to features the live packet-capture pipeline can
# actually compute. This is the fix for the training/inference
# mismatch: without it, top-ranked features like flags that only
# CICFlowMeter computed offline would get selected, then silently
# zero-filled at inference time.
# -------------------------------------------------------

live_computable = feature_importance[
    feature_importance["Feature"].isin(FeatureExtractor.LIVE_FEATURE_NAMES)
]

dropped = set(feature_importance["Feature"]) - set(live_computable["Feature"])

if dropped:
    print(f"\nDropping {len(dropped)} features not computable live:")
    for name in sorted(dropped):
        print(" -", name)

# -------------------------------------------------------
# Sort Features
# -------------------------------------------------------

live_computable = live_computable.sort_values(
    by="Importance",
    ascending=False
)

# -------------------------------------------------------
# Select Top Features
# -------------------------------------------------------

TOP_FEATURES = 25

selected = live_computable.head(TOP_FEATURES)

print("\nTop Features (guaranteed available at inference time)\n")

print(selected)

# -------------------------------------------------------
# Save Feature List
# -------------------------------------------------------

os.makedirs("models", exist_ok=True)

selected.to_csv(
    "models/selected_features.csv",
    index=False
)

with open(
    "models/selected_feature_names.txt",
    "w"
) as file:

    for feature in selected["Feature"]:

        file.write(feature + "\n")

print("\nSelected Features Saved.")

# -------------------------------------------------------
# Plot
# -------------------------------------------------------

plt.figure(figsize=(12, 8))

plt.barh(
    selected["Feature"],
    selected["Importance"]
)

plt.gca().invert_yaxis()

plt.title("Top 25 Selected Features (Live-Computable Only)")

plt.tight_layout()

plt.savefig(
    "models/selected_features.png"
)

plt.close()

print("\nFeature Selection Completed.")