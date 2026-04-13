"""Tests for ML anomaly classifier"""

import pandas as pd
import pytest
import numpy as np
from ml.classifier import MLAnomalyClassifier


@pytest.fixture
def sample_dataframe():
    np.random.seed(42)
    n = 100
    return pd.DataFrame({
        "src_ip": [f"192.168.1.{i%256}" for i in range(n)],
        "dst_ip": [f"10.0.0.{i%256}" for i in range(n)],
        "dst_port": [80, 443, 53, 8080] * (n // 4),
        "bidirectional_packets": np.random.poisson(50, n),
        "bidirectional_bytes": np.random.normal(10000, 2000, n).astype(int),
        "src2dst_packets": np.random.poisson(25, n),
        "src2dst_bytes": np.random.normal(5000, 1000, n).astype(int),
        "dst2src_packets": np.random.poisson(25, n),
        "dst2src_bytes": np.random.normal(5000, 1000, n).astype(int),
        "bidirectional_duration_ms": np.random.exponential(1000, n),
        "bidirectional_mean_ps": np.random.normal(100, 20, n),
        "bidirectional_stddev_ps": np.random.normal(10, 5, n),
        "bidirectional_mean_piat_ms": np.random.normal(500, 100, n),
        "bidirectional_stddev_piat_ms": np.random.normal(50, 10, n),
    })


@pytest.fixture
def empty_dataframe():
    return pd.DataFrame()


@pytest.fixture
def no_features_dataframe():
    return pd.DataFrame({"src_ip": ["192.168.1.1"], "dst_ip": ["10.0.0.1"], "some_col": [42]})


class TestMLAnomalyClassifier:
    def test_init_default(self):
        clf = MLAnomalyClassifier()
        assert clf.contamination == 0.05
        assert clf._is_fitted is False

    def test_predict_no_data_leakage(self, sample_dataframe):
        clf = MLAnomalyClassifier()
        result_df = clf.predict(sample_dataframe)
        assert "anomaly_score" in result_df.columns
        assert "is_anomaly" in result_df.columns
        assert clf._is_fitted is False

    def test_predict_empty_dataframe(self, empty_dataframe):
        clf = MLAnomalyClassifier()
        result_df = clf.predict(empty_dataframe)
        assert "anomaly_score" in result_df.columns

    def test_predict_no_features_dataframe(self, no_features_dataframe):
        clf = MLAnomalyClassifier()
        result_df = clf.predict(no_features_dataframe)
        assert "anomaly_score" in result_df.columns
        assert (result_df["anomaly_score"] == 0.0).all()

    def test_anomaly_scores_are_reasonable(self, sample_dataframe):
        clf = MLAnomalyClassifier()
        result_df = clf.predict(sample_dataframe)
        assert (result_df["anomaly_score"] >= 0).all()

    def test_fit_and_predict_with_pretrained(self, sample_dataframe):
        clf = MLAnomalyClassifier()
        clf.fit(sample_dataframe.head(50))
        assert clf._is_fitted is True
        result_df = clf.predict(sample_dataframe.tail(10))
        assert "anomaly_score" in result_df.columns

    def test_get_anomaly_summary(self, sample_dataframe):
        clf = MLAnomalyClassifier()
        result_df = clf.predict(sample_dataframe)
        summary = clf.get_anomaly_summary(result_df)
        assert summary["total_flows"] == len(sample_dataframe)
        assert "anomaly_count" in summary

    def test_compute_relative_scores(self):
        clf = MLAnomalyClassifier()
        features = pd.DataFrame({
            "bidirectional_bytes": [100, 200, 300, 10000],
            "bidirectional_packets": [10, 20, 30, 1000],
            "bidirectional_duration_ms": [100, 200, 300, 50000],
        })
        scores = clf._compute_relative_scores(features)
        assert len(scores) == 4
        assert scores.iloc[3] == scores.max()

    def test_model_save_load(self, sample_dataframe, tmp_path):
        model_path = str(tmp_path / "model.pkl")
        clf1 = MLAnomalyClassifier()
        clf1.fit(sample_dataframe.head(50))
        clf1.save_model(model_path)
        clf2 = MLAnomalyClassifier()
        clf2.load_model(model_path)
        assert clf2._is_fitted is True

    def test_model_load_nonexistent(self):
        clf = MLAnomalyClassifier()
        with pytest.raises(FileNotFoundError):
            clf.load_model("/nonexistent/model.pkl")
