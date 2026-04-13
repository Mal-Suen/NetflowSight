"""Tests for AbuseIPDB smart detector"""

import pandas as pd
import pytest
from unittest.mock import patch
from engines.abuseipdb_detector import AbuseIPDBSmartDetector
from core.models import IPReputation


@pytest.fixture
def detector(tmp_path):
    return AbuseIPDBSmartDetector(
        whitelist_file=str(tmp_path / "wl.json"),
        safe_cache_file=str(tmp_path / "sc.json"),
        malicious_cache_file=str(tmp_path / "mc.json"),
    )


@pytest.fixture
def sample_dataframe():
    return pd.DataFrame({
        "dst_ip": ["8.8.8.8", "1.1.1.1", "203.0.113.50", "192.168.1.1", "10.0.0.1", "127.0.0.1", "169.254.169.254"],
        "src_ip": ["192.168.1.100"] * 7,
        "bidirectional_bytes": [1000] * 7,
    })


class TestAbuseIPDBSmartDetector:
    def test_detect_with_empty_api_key(self, detector, sample_dataframe, monkeypatch):
        monkeypatch.setattr(detector.client, "abuseipdb_key", None)
        results, malicious = detector.detect_threats(sample_dataframe)
        assert results == []
        assert malicious == []

    def test_private_ip_exclusion(self, detector, sample_dataframe, monkeypatch):
        monkeypatch.setattr(detector.client, "abuseipdb_key", "test-key")
        queried = []
        with patch.object(detector.client, 'check_abuseipdb', side_effect=lambda ip: queried.append(ip) or None):
            detector.detect_threats(sample_dataframe)
        assert "8.8.8.8" in queried
        assert "192.168.1.1" not in queried
        assert "10.0.0.1" not in queried
        assert "127.0.0.1" not in queried
        assert "169.254.169.254" not in queried

    def test_malicious_ip_cached(self, detector, sample_dataframe, monkeypatch):
        monkeypatch.setattr(detector.client, "abuseipdb_key", "test-key")
        detector._malicious_cache["8.8.8.8"] = {
            "ip": "8.8.8.8", "abuse_score": 80, "isp": "Evil", "country_code": "XX",
            "is_tor": False, "is_public": True, "reports_count": 50, "usage_type": "Malicious",
            "domain": "evil.com", "is_whitelist": False, "is_safe": False, "is_malicious": True,
            "cached_at": "2026-04-13T00:00:00",
        }
        results, malicious = detector.detect_threats(sample_dataframe)
        assert len(malicious) > 0
        assert any(m.get("ip") == "8.8.8.8" for m in malicious)

    def test_safe_ip_not_cached_as_malicious(self, detector, sample_dataframe, monkeypatch):
        monkeypatch.setattr(detector.client, "abuseipdb_key", "test-key")
        def mock_check(ip):
            return IPReputation(ip=ip, abuse_score=5, isp="Normal ISP", country_code="US")
        with patch.object(detector.client, 'check_abuseipdb', side_effect=mock_check):
            detector.detect_threats(sample_dataframe)
        assert "8.8.8.8" in detector._safe_cache
        assert "8.8.8.8" not in detector._malicious_cache

    def test_malicious_ip_not_in_safe_cache(self, detector, sample_dataframe, monkeypatch):
        monkeypatch.setattr(detector.client, "abuseipdb_key", "test-key")
        def mock_check(ip):
            return IPReputation(ip=ip, abuse_score=80, isp="Evil", country_code="XX",
                                is_tor=True, reports_count=100, usage_type="Malicious", domain="evil.com")
        with patch.object(detector.client, 'check_abuseipdb', side_effect=mock_check):
            detector.detect_threats(sample_dataframe)
        assert "8.8.8.8" in detector._malicious_cache
        assert "8.8.8.8" not in detector._safe_cache

    def test_get_stats(self, detector):
        detector._whitelist = {"1.2.3.4": {}}
        detector._safe_cache = {"5.6.7.8": {}}
        detector._malicious_cache = {"9.10.11.12": {}}
        detector._query_count = 50
        detector._cache_hits = 10
        stats = detector.get_stats()
        assert stats["whitelist_size"] == 1
        assert stats["api_queries"] == 50
        assert stats["cache_hits"] == 10

    def test_close_saves_all_caches(self, detector, tmp_path):
        detector._whitelist = {"1.2.3.4": {}}
        detector._safe_cache = {"5.6.7.8": {}}
        detector._malicious_cache = {"9.10.11.12": {}}
        detector.close()
        assert (tmp_path / "wl.json").exists()
        assert (tmp_path / "sc.json").exists()
        assert (tmp_path / "mc.json").exists()
