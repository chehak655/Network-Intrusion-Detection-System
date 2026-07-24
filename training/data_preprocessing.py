import os
import glob
import joblib
import numpy as np
import pandas as pd

from sklearn.preprocessing import LabelEncoder

print("=" * 80)
print("NETWORK INTRUSION DETECTION - DATA PREPROCESSING")
print("=" * 80)

# -------------------------------------------------------
# Load all CSV files
# -------------------------------------------------------

dataset_path = "dataset"

csv_files = glob.glob(os.path.join(dataset_path, "*.csv"))

dataframes = []

for file in csv_files:

    print(f"Reading {os.path.basename(file)}")

    df = pd.read_csv(file, low_memory=False)

    # Remove extra spaces from column names
    df.columns = df.columns.str.strip()

    dataframes.append(df)

print("\nMerging datasets...")

data = pd.concat(dataframes, ignore_index=True)

print("Merged Shape :", data.shape)

# -------------------------------------------------------
# Replace Infinite values
# -------------------------------------------------------

print("\nReplacing Infinite values...")

data.replace([np.inf, -np.inf], np.nan, inplace=True)

# -------------------------------------------------------
# Remove Missing values
# -------------------------------------------------------

print("Removing Missing values...")

before = len(data)

data.dropna(inplace=True)

after = len(data)

print("Rows Removed :", before - after)

print("Current Shape :", data.shape)

# -------------------------------------------------------
# Remove Negative Flow Duration
# -------------------------------------------------------

print("\nRemoving Invalid Flow Duration...")

before = len(data)

data = data[data["Flow Duration"] >= 0]

after = len(data)

print("Rows Removed :", before - after)

print("Current Shape :", data.shape)

# -------------------------------------------------------
# Normalize attack names
# -------------------------------------------------------

print("\nFixing attack names...")

data["Label"] = (
    data["Label"]
    .astype(str)
    .str.replace("�", "-", regex=False)
    .str.replace("Web Attack - Sql Injection", "Web Attack - SQL Injection")
)

# -------------------------------------------------------
# Remove duplicate rows
# -------------------------------------------------------

print("\nRemoving Duplicate Rows...")

before = len(data)

data.drop_duplicates(inplace=True)

after = len(data)

print("Rows Removed :", before - after)

print("Current Shape :", data.shape)

# -------------------------------------------------------
# Encode labels
# -------------------------------------------------------

print("\nEncoding Labels...")

encoder = LabelEncoder()

data["Label"] = encoder.fit_transform(data["Label"])

os.makedirs("models", exist_ok=True)

joblib.dump(encoder, "models/label_encoder.pkl")

print("\nAttack Classes")

mapping = []

for index, attack in enumerate(encoder.classes_):

    print(f"{index} --> {attack}")

    mapping.append([index, attack])

mapping_df = pd.DataFrame(mapping, columns=["Encoded Label", "Attack"])

mapping_df.to_csv("models/label_mapping.csv", index=False)

print("\nLabel mapping saved.")

# -------------------------------------------------------
# Save Clean Dataset
# -------------------------------------------------------

os.makedirs("preprocessing", exist_ok=True)

output = "preprocessing/clean_dataset.csv"

data.to_csv(output, index=False)

print("\nClean Dataset Saved")

print(output)

print("\nFinal Shape :", data.shape)

print("\nPreprocessing Completed Successfully")