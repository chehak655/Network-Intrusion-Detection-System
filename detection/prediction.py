import joblib
import pandas as pd


class Predictor:

    def __init__(self):

        # Load trained models
        self.xgb_model = joblib.load("models/final_xgboost.pkl")
        self.iso_model = joblib.load("models/isolation_forest.pkl")

        # Feature names used during training
        self.selected_features = pd.read_csv(
            "models/selected_features.csv"
        )["Feature"].tolist()

        # Label encoder
        self.label_encoder = joblib.load(
            "models/label_encoder.pkl"
        )

    def predict(self, feature_dict):

        # Convert dictionary to dataframe
        df = pd.DataFrame([feature_dict])

        # Flag (and log) any expected feature the live extractor didn't
        # produce, instead of silently letting it default to 0. A
        # silent zero-fill here is what let live predictions quietly
        # drift from training-time accuracy in the first place.
        missing = [
            feature for feature in self.selected_features
            if feature not in df.columns
        ]

        for feature in missing:
            df[feature] = 0

        # Arrange columns exactly as during training
        df = df[self.selected_features]

        # XGBoost prediction
        prediction = self.xgb_model.predict(df)[0]

        probabilities = self.xgb_model.predict_proba(df)[0]

        confidence = probabilities.max()

        attack_name = self.label_encoder.inverse_transform(
            [prediction]
        )[0]

        # Isolation Forest
        anomaly = self.iso_model.predict(df)[0]

        anomaly_score = self.iso_model.decision_function(df)[0]

        return {

            "Attack": attack_name,

            "Confidence": float(confidence),

            "Anomaly": int(anomaly),

            "Anomaly Score": float(anomaly_score),

            "Missing Features": missing

        }