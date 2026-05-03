"""Tests for CacheManager utility"""

import tempfile
from pathlib import Path

import pytest

from utils.cache_manager import (
    CacheLevel,
    CacheEntry,
    GenericCacheManager,
    create_ip_cache,
    create_domain_cache,
)


class TestCacheEntry:
    def test_cache_entry_creation(self):
        """测试缓存条目创建"""
        entry = CacheEntry(
            data={"score": 50},
            cached_at="2024-01-01T00:00:00",
        )
        assert entry.data == {"score": 50}
        assert entry.cached_at == "2024-01-01T00:00:00"
    
    def test_is_expired_no_ttl(self):
        """测试无 TTL 时不过期"""
        entry = CacheEntry(
            data={"test": 1},
            cached_at="2020-01-01T00:00:00",  # 很久以前
        )
        assert entry.is_expired(None) is False
    
    def test_is_expired_within_ttl(self):
        """测试在 TTL 内不过期"""
        from datetime import datetime
        entry = CacheEntry(
            data={"test": 1},
            cached_at=datetime.now().isoformat(),
        )
        assert entry.is_expired(30) is False
    
    def test_is_expired_past_ttl(self):
        """测试超过 TTL 过期"""
        entry = CacheEntry(
            data={"test": 1},
            cached_at="2020-01-01T00:00:00",
        )
        assert entry.is_expired(1) is True


class TestGenericCacheManager:
    @pytest.fixture
    def cache_manager(self):
        """创建测试用缓存管理器"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield GenericCacheManager(
                cache_name="test_cache",
                cache_dir=tmpdir,
            )
    
    def test_initialization(self, cache_manager):
        """测试初始化"""
        assert cache_manager.cache_name == "test_cache"
        stats = cache_manager.get_stats()
        assert stats["hits"] == 0
        assert stats["misses"] == 0
    
    def test_set_and_get(self, cache_manager):
        """测试设置和获取"""
        cache_manager.set("key1", {"value": 100}, CacheLevel.SAFE)
        
        result = cache_manager.get("key1")
        assert result is not None
        assert result["value"] == 100
    
    def test_get_nonexistent_key(self, cache_manager):
        """测试获取不存在的键"""
        result = cache_manager.get("nonexistent")
        assert result is None
    
    def test_get_with_level(self, cache_manager):
        """测试按级别获取"""
        cache_manager.set("key1", {"level": "safe"}, CacheLevel.SAFE)
        cache_manager.set("key2", {"level": "malicious"}, CacheLevel.MALICIOUS)
        
        result1 = cache_manager.get("key1", CacheLevel.SAFE)
        assert result1["level"] == "safe"
        
        result2 = cache_manager.get("key2", CacheLevel.MALICIOUS)
        assert result2["level"] == "malicious"
    
    def test_contains(self, cache_manager):
        """测试键存在检查"""
        cache_manager.set("key1", {"data": 1}, CacheLevel.SAFE)
        
        assert cache_manager.contains("key1") is True
        assert cache_manager.contains("nonexistent") is False
    
    def test_remove(self, cache_manager):
        """测试删除"""
        cache_manager.set("key1", {"data": 1}, CacheLevel.SAFE)
        
        assert cache_manager.remove("key1") is True
        assert cache_manager.get("key1") is None
    
    def test_get_level_size(self, cache_manager):
        """测试获取级别大小"""
        cache_manager.set("key1", {"data": 1}, CacheLevel.SAFE)
        cache_manager.set("key2", {"data": 2}, CacheLevel.SAFE)
        cache_manager.set("key3", {"data": 3}, CacheLevel.MALICIOUS)
        
        assert cache_manager.get_level_size(CacheLevel.SAFE) == 2
        assert cache_manager.get_level_size(CacheLevel.MALICIOUS) == 1
    
    def test_get_level_keys(self, cache_manager):
        """测试获取级别所有键"""
        cache_manager.set("key1", {"data": 1}, CacheLevel.SAFE)
        cache_manager.set("key2", {"data": 2}, CacheLevel.SAFE)
        
        keys = cache_manager.get_level_keys(CacheLevel.SAFE)
        assert set(keys) == {"key1", "key2"}
    
    def test_clear_level(self, cache_manager):
        """测试清空特定级别"""
        cache_manager.set("key1", {"data": 1}, CacheLevel.SAFE)
        cache_manager.set("key2", {"data": 2}, CacheLevel.MALICIOUS)
        
        cache_manager.clear(CacheLevel.SAFE)
        
        assert cache_manager.get_level_size(CacheLevel.SAFE) == 0
        assert cache_manager.get_level_size(CacheLevel.MALICIOUS) == 1
    
    def test_clear_all(self, cache_manager):
        """测试清空所有级别"""
        cache_manager.set("key1", {"data": 1}, CacheLevel.SAFE)
        cache_manager.set("key2", {"data": 2}, CacheLevel.MALICIOUS)
        
        cache_manager.clear()
        
        assert cache_manager.get_level_size(CacheLevel.SAFE) == 0
        assert cache_manager.get_level_size(CacheLevel.MALICIOUS) == 0
    
    def test_save_and_load(self):
        """测试保存和加载"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # 创建并写入
            cache1 = GenericCacheManager(
                cache_name="test_cache",
                cache_dir=tmpdir,
            )
            cache1.set("key1", {"data": 1}, CacheLevel.SAFE)
            cache1.set("key2", {"data": 2}, CacheLevel.MALICIOUS)
            cache1.save_all()
            
            # 重新加载
            cache2 = GenericCacheManager(
                cache_name="test_cache",
                cache_dir=tmpdir,
            )
            
            assert cache2.get("key1") is not None
            assert cache2.get("key2") is not None
    
    def test_hit_rate(self, cache_manager):
        """测试命中率计算"""
        cache_manager.set("key1", {"data": 1}, CacheLevel.SAFE)
        
        cache_manager.get("key1")  # hit
        cache_manager.get("key1")  # hit
        cache_manager.get("nonexistent")  # miss
        
        stats = cache_manager.get_stats()
        assert stats["hits"] == 2
        assert stats["misses"] == 1
        assert abs(stats["hit_rate"] - 0.6666666666666666) < 0.01


class TestFactoryFunctions:
    def test_create_ip_cache(self):
        """测试创建 IP 缓存"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = create_ip_cache(tmpdir)
            assert cache.cache_name == "ip_reputation"
    
    def test_create_domain_cache(self):
        """测试创建域名缓存"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = create_domain_cache(tmpdir)
            assert cache.cache_name == "domain_reputation"
