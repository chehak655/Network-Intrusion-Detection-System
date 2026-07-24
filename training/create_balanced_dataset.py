import os
import pandas as pd

print("=" * 80)
print("CREATING BALANCED DATASET")
print("=" * 80)

df = pd.read_csv("preprocessing/clean_dataset.csv")

print("\nOriginal Shape")

print(df.shape)

# ------------------------------------------------
# Separate Benign and Attack Traffic
# ------------------------------------------------

benign = df[df["Label"] == 0]

attack = df[df["Label"] != 0]

print("\nBenign Samples :", len(benign))
print("Attack Samples :", len(attack))

# ------------------------------------------------
# Randomly Sample Benign Traffic
# ------------------------------------------------

sample_size = 300000

sampled_benign = benign.sample(

    n=sample_size,

    random_state=42

)

print("\nSampled Benign :", len(sampled_benign))

# ------------------------------------------------
# Merge
# ------------------------------------------------

balanced = pd.concat(

    [

        sampled_benign,

        attack

    ],

    ignore_index=True

)

# ------------------------------------------------
# Shuffle
# ------------------------------------------------

balanced = balanced.sample(

    frac=1,

    random_state=42

).reset_index(drop=True)

print("\nBalanced Shape")

print(balanced.shape)

os.makedirs(

    "preprocessing",

    exist_ok=True

)

balanced.to_csv(

    "preprocessing/balanced_dataset.csv",

    index=False

)

print("\nBalanced dataset saved.")