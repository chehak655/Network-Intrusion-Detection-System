import os
import glob
import pandas as pd
import numpy as np

# ----------------------------
# Load all CSV files
# ----------------------------

path = "dataset"

files = glob.glob(os.path.join(path, "*.csv"))

print("=" * 80)
print("CIC IDS 2017 DATASET ANALYSIS")
print("=" * 80)

total_rows = 0
total_classes = {}

for file in files:

    print("\n")
    print("=" * 80)
    print("FILE :", os.path.basename(file))
    print("=" * 80)

    df = pd.read_csv(file, low_memory=False)

    print("Rows :", df.shape[0])
    print("Columns :", df.shape[1])

    total_rows += df.shape[0]

    # Remove spaces from column names
    df.columns = df.columns.str.strip()

    print("\nFirst Five Columns")

    print(df.columns[:5].tolist())

    print("\nLast Five Columns")

    print(df.columns[-5:].tolist())

    print("\nMissing Values")

    print(df.isnull().sum().sum())

    print("\nInfinite Values")

    numeric = df.select_dtypes(include=[np.number])

    inf_count = np.isinf(numeric).sum().sum()

    print(inf_count)

    print("\nAttack Distribution")

    attack_count = df["Label"].value_counts()

    print(attack_count)

    for attack, count in attack_count.items():

        if attack not in total_classes:

            total_classes[attack] = count

        else:

            total_classes[attack] += count

print("\n")
print("=" * 80)
print("OVERALL DATASET SUMMARY")
print("=" * 80)

print("Total Rows :", total_rows)

print("\nAttack Summary")

for attack, count in sorted(total_classes.items()):

    print(f"{attack:30} {count}")