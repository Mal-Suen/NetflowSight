"""Tests for threat intelligence cache"""

import time
import pytest
from intel.cache import ThreatCache
from core.models import IPReputation
from core.config import settings


@pytest.fixture
def cache_dir(tmp_path):
    return str(tmp_path / "cache")


@pytest.fixture
def cache(cache_dir):
    return ThreatCache(cache_dir=cache_dir)


class TestThreatCache:
    def test_set_and_get(self, cache):
        rep = IPReputation(ip="1.2.3.4", abuse_score=10, country_code="CN", isp="Test ISP")
        cache.set(rep)
        result = cache.get("1.2.3.4")
        assert result is not None
        assert result.ip == "1.2.3.4"
        assert result.abuse_score == 10

    def test_get_nonexistent(self, cache):
        assert cache.get("9.9.9.9") is None

    def test_cache_disabled(self, cache, monkeypatch):
        monkeypatch.setattr(settings, "THREAT_CACHE_ENABLED", False)
        cache.set(IPReputation(ip="1.2.3.4", abuse_score=10))
        assert cache.get("1.2.3.4") is None

    def test_cache_expiration(self, cache):
        cache.ttl_hours = 0.0001
        cache.set(IPReputation(ip="1.2.3.4", abuse_score=10))
        assert cache.get("1.2.3.4") is not None
        time.sleep(0.5)
        assert cache.get("1.2.3.4") is None

    def test_cleanup_expired(self, cache):
        old_time = time.time() - 100 * 3600
        cache._cache = {
            "1.2.3.4": {"abuse_score": 10, "timestamp": old_time},
            "5.6.7.8": {"abuse_score": 0, "timestamp": time.time()},
        }
        assert cache.cleanup_expired() == 1
        assert "1.2.3.4" not in cache._cache
        assert "5.6.7.8" in cache._cache

    def test_flush(self, cache):
        cache.set(IPReputation(ip="1.2.3.4", abuse_score=10))
        cache.flush()
        assert len(cache._cache) == 0

    def test_persistence(self, cache, cache_dir):
        cache.set(IPReputation(ip="1.2.3.4", abuse_score=50))
        cache._save_cache()
        cache2 = ThreatCache(cache_dir=cache_dir)
        result = cache2.get("1.2.3.4")
        assert result is not None
        assert result.abuse_score == 50
