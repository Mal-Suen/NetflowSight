"""
ML-based Anomaly Classifier
"""

import logging
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)


class MLAnomalyClassifier:
    """
    ML-based anomaly detection using Isolation Forest.
    
    Features:
    - Unsupervised learning (no labeled data required)
    - Automatic feature selection
    - Anomaly scoring
    """
    
    # Features to use for ML detection
    ML_FEATURES = [
        "bidirectional_packets",
        "bidirectional_bytes",
        "src2dst_packets",
        "src2dst_bytes",
        "dst2src_packets",
        "dst2src_bytes",
        "bidirectional_duration_ms",
        "bidirectional_mean_ps",
        "bidirectional_stddev_ps",
        "bidirectional_mean_piat_ms",
        "bidirectional_stddev_piat_ms",
    ]
    
    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 100,
        model_path: Optional[str] = None,
    ):
        """
        Initialize ML anomaly classifier.

        Args:
            contamination: Expected proportion of anomalies
            n_estimators: Number of trees in the forest
            model_path: Path to pre-trained model (optional).
                If a pre-trained model is not available, the classifier will
                operate in 'unsupervised scoring mode' using a default model
                that provides relative anomaly scores without per-dataset training.
        """
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.model_path = model_path

        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self._is_fitted = False

        # Load pre-trained model if available
        if model_path:
            try:
                self.load_model(model_path)
            except (FileNotFoundError, RuntimeError):
                logger.info(f"No pre-trained model at {model_path}, will use default scoring")
    
    def _extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract ML features from flow DataFrame.

        Args:
            df: Flow records DataFrame

        Returns:
            DataFrame with ML features
        """
        available_features = [
            f for f in self.ML_FEATURES if f in df.columns
        ]

        if not available_features:
            logger.warning("No ML features available in DataFrame")
            return pd.DataFrame()

        features = df[available_features].copy()

        # Fill NaN with 0 and replace infinity in a single chain
        features = (
            features
            .fillna(0)
            .replace([np.inf, -np.inf], 1e10)
        )

        return features
    
    def fit(self, df: pd.DataFrame) -> None:
        """
        Train the anomaly detector on normal traffic.

        Args:
            df: DataFrame with flow records (assumed mostly normal)

        Raises:
            ValueError: If no features are available for training
        """
        features = self._extract_features(df)
        if features.empty:
            logger.warning("No features to train on")
            raise ValueError("No ML features available in DataFrame for training")

        # Scale features
        X_scaled = self.scaler.fit_transform(features)

        # Train model
        self.model.fit(X_scaled)
        self._is_fitted = True

        logger.info(f"ML model trained on {len(features)} flows")

        # Save model if path specified
        if self.model_path:
            self.save_model(self.model_path)
    
    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Predict anomalies and add scores to DataFrame.

        If a pre-trained model is available, it will be used for prediction.
        If not, the method computes relative anomaly scores based on flow
        characteristics (bytes, packets, duration) without training on the
        input data, avoiding data leakage.

        Args:
            df: DataFrame with flow records

        Returns:
            DataFrame with added 'anomaly_score' and 'is_anomaly' columns
        """
        features = self._extract_features(df)
        if features.empty:
            df = df.copy()
            df["anomaly_score"] = 0.0
            df["is_anomaly"] = False
            return df

        if self._is_fitted:
            # Use pre-trained model
            X_scaled = self.scaler.transform(features)
            predictions = self.model.predict(X_scaled)
            scores = self.model.decision_function(X_scaled)

            df = df.copy()
            df["anomaly_score"] = -scores  # Invert so higher = more anomalous
            df["is_anomaly"] = predictions == -1
            anomaly_count = int(df["is_anomaly"].sum())
            logger.info(f"ML detection: {anomaly_count} anomalies found ({anomaly_count/len(df)*100:.2f}%)")
        else:
            # No pre-trained model: compute relative anomaly scores without training
            # This avoids data leakage (training and predicting on same data)
            df = df.copy()
            df["anomaly_score"] = self._compute_relative_scores(features)
            # Mark top `contamination` fraction as anomalies
            threshold = df["anomaly_score"].quantile(1 - self.contamination)
            df["is_anomaly"] = df["anomaly_score"] >= threshold
            anomaly_count = int(df["is_anomaly"].sum())
            logger.info(
                f"ML detection (unsupervised scoring): {anomaly_count} anomalies found "
                f"({anomaly_count/len(df)*100:.2f}%) — note: no pre-trained model loaded"
            )

        return df

    def _compute_relative_scores(self, features: pd.DataFrame) -> pd.Series:
        """
        Compute relative anomaly scores without training on input data.

        Uses statistical heuristics: flows that are extreme in bytes/packets
        relative to the median get higher anomaly scores. This provides
        meaningful scores without the data leakage of training on the same data.

        Args:
            features: DataFrame with ML features

        Returns:
            Series of anomaly scores (higher = more anomalous)
        """
        # Compute z-score-like metric using median and MAD (median absolute deviation)
        bytes_col = "bidirectional_bytes"
        packets_col = "bidirectional_packets"
        duration_col = "bidirectional_duration_ms"

        scores = pd.Series(0.0, index=features.index)

        for col in [bytes_col, packets_col, duration_col]:
            if col not in features.columns:
                continue
            vals = features[col].astype(float)
            median = vals.median()
            mad = (vals - median).abs().median()
            if mad > 0:
                # Modified z-score
                z = ((vals - median) / mad).abs()
                scores += z
            else:
                # Fallback: use range
                max_val = vals.max()
                min_val = vals.min()
                if max_val > min_val:
                    scores += (vals - min_val) / (max_val - min_val)

        # Normalize to 0-1 range
        max_score = scores.max()
        if max_score > 0:
            scores = scores / max_score

        return scores
    
    def get_anomaly_summary(self, df: pd.DataFrame) -> dict:
        """
        Get summary of ML anomaly detection.

        Args:
            df: DataFrame with flow records (must have anomaly_score)

        Returns:
            Summary dictionary
        """
        if "anomaly_score" not in df.columns:
            return {"error": "Run predict() first"}

        anomalies = df[df["is_anomaly"]]

        return {
            "total_flows": len(df),
            "anomaly_count": len(anomalies),
            "anomaly_rate": len(anomalies) / len(df) * 100 if len(df) > 0 else 0,
            "top_anomalies": anomalies.nlargest(20, "anomaly_score")[
                ["src_ip", "dst_ip", "dst_port", "bidirectional_bytes", "anomaly_score"]
            ].to_dict("records") if not anomalies.empty else [],
        }
    
    def save_model(self, path: str) -> None:
        """Save trained model to disk."""
        model_data = {
            "model": self.model,
            "scaler": self.scaler,
            "features": self.ML_FEATURES,
        }
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(model_data, path)
        logger.info(f"Model saved to {path}")
    
    def load_model(self, path: str) -> None:
        """Load trained model from disk."""
        model_path = Path(path)
        if not model_path.exists():
            raise FileNotFoundError(f"Model file not found: {path}")

        try:
            model_data = joblib.load(path)
            self.model = model_data["model"]
            self.scaler = model_data["scaler"]
            self._is_fitted = True
            logger.info(f"Model loaded from {path}")
        except Exception as e:
            logger.error(f"Failed to load model from {path}: {e}")
            raise RuntimeError(f"Failed to load model: {e}")
