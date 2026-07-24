import os
import glob

path = "dataset"

files = glob.glob(os.path.join(path, "*.csv"))

print("Number of CSV files:", len(files))

for file in files:
    print(os.path.basename(file))