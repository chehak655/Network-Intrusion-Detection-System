import os
import joblib
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.ensemble import IsolationForest

print("=" * 80)
print("TRAINING ISOLATION FOREST")
print("=" * 80)

# -------------------------------------------------------
# Load Dataset
# -------------------------------------------------------

df = pd.read_csv("preprocessing/balanced_dataset.csv")

# -------------------------------------------------------
# Load Selected Features
# -------------------------------------------------------

selected = pd.read_csv(
    "models/selected_features.csv"
)

feature_names = selected["Feature"].tolist()

# -------------------------------------------------------
# Keep Only Benign Traffic
# -------------------------------------------------------

benign = df[df["Label"] == 0]

print("\nBenign Samples")

print(len(benign))

X = benign[feature_names]

# -------------------------------------------------------
# Train Isolation Forest
# -------------------------------------------------------

model = IsolationForest(

    n_estimators=200,

    contamination=0.01,

    random_state=42,

    n_jobs=-1

)

print("\nTraining Isolation Forest...")

model.fit(X)

print("Training Completed.")

# -------------------------------------------------------
# Save Model
# -------------------------------------------------------

joblib.dump(

    model,

    "models/isolation_forest.pkl"

)

# -------------------------------------------------------
# Calculate Anomaly Scores
# -------------------------------------------------------

scores = model.decision_function(X)

plt.figure(figsize=(10,6))

plt.hist(scores, bins=50)

plt.title("Isolation Forest Anomaly Scores")

plt.xlabel("Score")

plt.ylabel("Frequency")

plt.tight_layout()

plt.savefig(

    "models/anomaly_score_distribution.png"

)

plt.close()

print("\nIsolation Forest Saved Successfully.")