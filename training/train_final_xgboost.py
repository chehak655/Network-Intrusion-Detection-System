import os
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay
)

from xgboost import XGBClassifier

print("=" * 80)
print("FINAL XGBOOST TRAINING")
print("=" * 80)

# -------------------------------------------------------
# Load Balanced Dataset
# -------------------------------------------------------

df = pd.read_csv("preprocessing/balanced_dataset.csv")

print("\nDataset Shape:", df.shape)

# -------------------------------------------------------
# Load Selected Features
# -------------------------------------------------------

selected_features = pd.read_csv(
    "models/selected_features.csv"
)

feature_names = selected_features["Feature"].tolist()

print("\nUsing", len(feature_names), "selected features.")

# -------------------------------------------------------
# Prepare Data
# -------------------------------------------------------

X = df[feature_names]

y = df["Label"]

# -------------------------------------------------------
# Train-Test Split
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
# Train Model
# -------------------------------------------------------

model = XGBClassifier(
    n_estimators=300,
    max_depth=8,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    objective="multi:softprob",
    num_class=len(np.unique(y)),
    random_state=42,
    tree_method="hist",
    eval_metric="mlogloss",
    n_jobs=-1
)

print("\nTraining Final Model...")

model.fit(X_train, y_train)

print("Training Completed.")

# -------------------------------------------------------
# Prediction
# -------------------------------------------------------

predictions = model.predict(X_test)

# -------------------------------------------------------
# Accuracy
# -------------------------------------------------------

accuracy = accuracy_score(y_test, predictions)

print("\nAccuracy:", accuracy)

# -------------------------------------------------------
# Classification Report
# -------------------------------------------------------

report = classification_report(
    y_test,
    predictions
)

print("\nClassification Report\n")

print(report)

with open(
    "models/final_classification_report.txt",
    "w"
) as f:
    f.write(report)

# -------------------------------------------------------
# Confusion Matrix
# -------------------------------------------------------

cm = confusion_matrix(
    y_test,
    predictions
)

disp = ConfusionMatrixDisplay(cm)

plt.figure(figsize=(10,10))

disp.plot()

plt.tight_layout()

plt.savefig(
    "models/final_confusion_matrix.png"
)

plt.close()

# -------------------------------------------------------
# Final Feature Importance
# -------------------------------------------------------

importance = pd.DataFrame({
    "Feature": feature_names,
    "Importance": model.feature_importances_
})

importance = importance.sort_values(
    by="Importance",
    ascending=False
)

importance.to_csv(
    "models/final_feature_importance.csv",
    index=False
)

plt.figure(figsize=(12,8))

plt.barh(
    importance["Feature"],
    importance["Importance"]
)

plt.gca().invert_yaxis()

plt.title("Final Feature Importance")

plt.tight_layout()

plt.savefig(
    "models/final_feature_importance.png"
)

plt.close()

# -------------------------------------------------------
# Save Model
# -------------------------------------------------------

joblib.dump(
    model,
    "models/final_xgboost.pkl"
)

print("\nFinal Model Saved Successfully.")