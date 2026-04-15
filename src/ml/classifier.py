"""ML 异常检测分类器 - 基于 Isolation Forest"""

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
    """基于 Isolation Forest 的异常检测分类器"""

    ML_FEATURES = [
        "bidirectional_packets", "bidirectional_bytes",
        "src2dst_packets", "src2dst_bytes", "dst2src_packets", "dst2src_bytes",
        "bidirectional_duration_ms", "bidirectional_mean_ps", "bidirectional_stddev_ps",
        "bidirectional_mean_piat_ms", "bidirectional_stddev_piat_ms",
    ]

    def __init__(self, contamination: float = 0.05, n_estimators: int = 100, model_path: Optional[str] = None):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.model_path = model_path

        self.model = IsolationForest(
            n_estimators=n_estimators, contamination=contamination,
            random_state=42, n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self._is_fitted = False

        if model_path:
            try:
                self.load_model(model_path)
            except (FileNotFoundError, RuntimeError):
                logger.info(f"未找到预训练模型 {model_path}，将使用默认评分方法")

    def _extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """从流 DataFrame 中提取 ML 特征"""
        available_features = [f for f in self.ML_FEATURES if f in df.columns]
        if not available_features:
            logger.warning("DataFrame 中没有可用的 ML 特征")
            return pd.DataFrame()

        features = df[available_features].copy()
        features = features.fillna(0).replace([np.inf, -np.inf], 1e10)
        return features

    def fit(self, df: pd.DataFrame) -> None:
        """训练异常检测器"""
        features = self._extract_features(df)
        if features.empty:
            raise ValueError("DataFrame 中没有可用的 ML 特征")

        X_scaled = self.scaler.fit_transform(features)
        self.model.fit(X_scaled)
        self._is_fitted = True
        logger.info(f"ML 模型训练完成，共 {len(features)} 个流")

        if self.model_path:
            self.save_model(self.model_path)

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """预测异常并添加评分到 DataFrame"""
        features = self._extract_features(df)
        if features.empty:
            df = df.copy()
            df["anomaly_score"] = 0.0
            df["is_anomaly"] = False
            return df

        if self._is_fitted:
            X_scaled = self.scaler.transform(features)
            predictions = self.model.predict(X_scaled)
            scores = self.model.decision_function(X_scaled)

            df = df.copy()
            df["anomaly_score"] = -scores
            df["is_anomaly"] = predictions == -1
            logger.info(f"ML 检测: 发现 {int(df['is_anomaly'].sum())} 个异常")
        else:
            df = df.copy()
            df["anomaly_score"] = self._compute_relative_scores(features)
            threshold = df["anomaly_score"].quantile(1 - self.contamination)
            df["is_anomaly"] = df["anomaly_score"] >= threshold
            logger.info(f"ML 检测（无监督评分）: 发现 {int(df['is_anomaly'].sum())} 个异常")

        return df

    def _compute_relative_scores(self, features: pd.DataFrame) -> pd.Series:
        """使用统计启发式计算相对异常评分"""
        scores = pd.Series(0.0, index=features.index)

        for col in ["bidirectional_bytes", "bidirectional_packets", "bidirectional_duration_ms"]:
            if col not in features.columns:
                continue
            vals = features[col].astype(float)
            median = vals.median()
            mad = (vals - median).abs().median()
            if mad > 0:
                scores += ((vals - median) / mad).abs()

        max_score = scores.max()
        return scores / max_score if max_score > 0 else scores

    def get_anomaly_summary(self, df: pd.DataFrame) -> dict:
        """获取 ML 异常检测摘要"""
        if "anomaly_score" not in df.columns:
            return {"error": "请先运行 predict() 方法"}

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
        """保存模型到磁盘"""
        model_data = {"model": self.model, "scaler": self.scaler, "features": self.ML_FEATURES}
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(model_data, path)
        logger.info(f"模型已保存到 {path}")

    def load_model(self, path: str) -> None:
        """从磁盘加载模型"""
        if not Path(path).exists():
            raise FileNotFoundError(f"模型文件不存在: {path}")

        try:
            model_data = joblib.load(path)
            self.model = model_data["model"]
            self.scaler = model_data["scaler"]
            self._is_fitted = True
            logger.info(f"模型已从 {path} 加载")
        except Exception as e:
            raise RuntimeError(f"加载模型失败: {e}")
