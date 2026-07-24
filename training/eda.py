import os
import joblib
import pandas as pd
import matplotlib.pyplot as plt

print("=" * 80)
print("NETWORK INTRUSION DETECTION - EXPLORATORY DATA ANALYSIS")
print("=" * 80)

# -------------------------------------------------------
# Create graphs folder
# -------------------------------------------------------

os.makedirs("preprocessing/graphs", exist_ok=True)

# -------------------------------------------------------
# Load cleaned dataset
# -------------------------------------------------------

df = pd.read_csv("preprocessing/clean_dataset.csv")

print("\nDataset Shape")

print(df.shape)

# -------------------------------------------------------
# Dataset Summary
# -------------------------------------------------------

summary_file = open("preprocessing/graphs/dataset_summary.txt", "w")

summary_file.write("Dataset Shape\n")
summary_file.write(str(df.shape))
summary_file.write("\n\n")

summary_file.write("Columns\n")

for col in df.columns:

    summary_file.write(col + "\n")

summary_file.write("\n")

summary_file.write(str(df.describe()))

summary_file.close()

print("Dataset summary saved.")

# -------------------------------------------------------
# Load Label Encoder
# -------------------------------------------------------

encoder = joblib.load("models/label_encoder.pkl")

# -------------------------------------------------------
# Attack Distribution
# -------------------------------------------------------

attack_counts = df["Label"].value_counts().sort_index()

attack_names = encoder.inverse_transform(attack_counts.index)

attack_df = pd.DataFrame({

    "Attack": attack_names,

    "Samples": attack_counts.values

})

attack_df.to_csv(

    "preprocessing/graphs/class_distribution.csv",

    index=False

)

plt.figure(figsize=(15,6))

plt.bar(attack_names, attack_counts.values)

plt.xticks(rotation=45, ha="right")

plt.ylabel("Number of Samples")

plt.title("Attack Distribution")

plt.tight_layout()

plt.savefig("preprocessing/graphs/attack_distribution.png")

plt.close()

print("Attack distribution graph saved.")

# -------------------------------------------------------
# Top Correlated Features
# -------------------------------------------------------

numeric = df.select_dtypes(include="number")

correlation = numeric.corr()["Label"].abs().sort_values(ascending=False)

top = correlation.head(15)

plt.figure(figsize=(10,6))

plt.barh(top.index, top.values)

plt.title("Top Features Correlated With Label")

plt.tight_layout()

plt.savefig("preprocessing/graphs/top_correlated_features.png")

plt.close()

print("Correlation graph saved.")

# -------------------------------------------------------
# Histogram
# -------------------------------------------------------

features = [

    "Flow Duration",

    "Total Fwd Packets",

    "Total Backward Packets",

    "Flow Bytes/s"

]

for feature in features:

    plt.figure(figsize=(6,4))

    df[feature].hist(bins=40)

    plt.title(feature)

    plt.tight_layout()

    safe_feature_name = (
    feature.replace("/", "_")
           .replace("\\", "_")
           .replace(" ", "_")
    )

    plt.savefig(
        f"preprocessing/graphs/{safe_feature_name}.png"
    )

    plt.close()

print("Feature histograms saved.")

print("\nEDA Completed Successfully")