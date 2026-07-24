import os
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay
)

from xgboost import XGBClassifier

print("="*80)
print("INITIAL XGBOOST TRAINING")
print("="*80)

# -------------------------------------------------------
# Load Dataset
# -------------------------------------------------------

df = pd.read_csv("preprocessing/balanced_dataset.csv")

print("\nDataset Shape")

print(df.shape)

# -------------------------------------------------------
# Features and Labels
# -------------------------------------------------------

X = df.drop("Label", axis=1)

y = df["Label"]

# -------------------------------------------------------
# Train Test Split
# -------------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining Samples :", len(X_train))
print("Testing Samples  :", len(X_test))

# -------------------------------------------------------
# Scaling
# -------------------------------------------------------

scaler = StandardScaler()

X_train = scaler.fit_transform(X_train)

X_test = scaler.transform(X_test)

os.makedirs("models", exist_ok=True)

joblib.dump(scaler, "models/scaler.pkl")

# -------------------------------------------------------
# Model
# -------------------------------------------------------

model = XGBClassifier(
    n_estimators=200,
    max_depth=8,
    learning_rate=0.1,
    objective="multi:softprob",
    num_class=len(np.unique(y)),
    random_state=42,
    tree_method="hist",
    eval_metric="mlogloss",
    n_jobs=-1
)

print("\nTraining Model...")

model.fit(X_train, y_train)

print("Training Completed.")

# -------------------------------------------------------
# Prediction
# -------------------------------------------------------

prediction = model.predict(X_test)

# -------------------------------------------------------
# Accuracy
# -------------------------------------------------------

accuracy = accuracy_score(y_test, prediction)

print("\nAccuracy")

print(accuracy)

# -------------------------------------------------------
# Classification Report
# -------------------------------------------------------

report = classification_report(y_test, prediction)

print("\nClassification Report")

print(report)

with open(
    "models/classification_report.txt",
    "w"
) as f:

    f.write(report)

# -------------------------------------------------------
# Confusion Matrix
# -------------------------------------------------------

cm = confusion_matrix(y_test, prediction)

disp = ConfusionMatrixDisplay(cm)

plt.figure(figsize=(10,10))

disp.plot()

plt.tight_layout()

plt.savefig("models/confusion_matrix.png")

plt.close()

# -------------------------------------------------------
# Feature Importance
# -------------------------------------------------------

importance = model.feature_importances_

feature_importance = pd.DataFrame({

    "Feature": X.columns,

    "Importance": importance

})

feature_importance = feature_importance.sort_values(
    by="Importance",
    ascending=False
)

feature_importance.to_csv(
    "models/feature_importance.csv",
    index=False
)

plt.figure(figsize=(12,8))

plt.barh(
    feature_importance["Feature"][:25],
    feature_importance["Importance"][:25]
)

plt.gca().invert_yaxis()

plt.title("Top 25 Important Features")

plt.tight_layout()

plt.savefig(
    "models/feature_importance.png"
)

plt.close()

# -------------------------------------------------------
# Save Model
# -------------------------------------------------------

joblib.dump(
    model,
    "models/initial_xgboost.pkl"
)

print("\nModel Saved Successfully")