"""
通用缓存管理器 - 减少重复的缓存加载/保存逻辑

支持:
- 多级缓存 (白名单/安全/恶意)
- TTL 过期清理
- JSON 持久化
- 线程安全操作
"""

import json
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Generic, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass
class CacheEntry:
    """缓存条目"""
    data: dict[str, Any]
    cached_at: str
    expires_at: str | None = None
    
    def is_expired(self, ttl_days: int | None = None) -> bool:
        """检查是否过期"""
        if ttl_days is None:
            return False
        try:
            cached_time = datetime.fromisoformat(self.cached_at)
            return (datetime.now() - cached_time).days >= ttl_days
        except ValueError:
            return True


class CacheLevel:
    """缓存级别常量"""
    WHITELIST = "whitelist"      # 永久缓存
    SAFE = "safe"                # 安全缓存 (30天)
    MALICIOUS = "malicious"      # 恶意缓存 (90天)


class GenericCacheManager(Generic[T]):
    """
    通用缓存管理器
    
    支持多级缓存策略:
    - 白名单: 永久有效
    - 安全缓存: 30天过期
    - 恶意缓存: 90天过期
    
    使用示例:
        cache = CacheManager[str](
            cache_name="ip_reputation",
            cache_dir=Path("data/cache"),
        )
        cache.set("192.168.1.1", {"score": 0}, level=CacheLevel.SAFE)
        entry = cache.get("192.168.1.1")
    """
    
    # 默认 TTL 配置 (天)
    DEFAULT_TTL_DAYS = {
        CacheLevel.WHITELIST: None,    # 永不过期
        CacheLevel.SAFE: 30,
        CacheLevel.MALICIOUS: 90,
    }
    
    def __init__(
        self,
        cache_name: str,
        cache_dir: Path | str,
        ttl_days: dict[str, int | None] | None = None,
    ):
        """
        初始化缓存管理器
        
        Args:
            cache_name: 缓存名称 (用于文件名)
            cache_dir: 缓存目录
            ttl_days: 各级别 TTL 配置
        """
        self.cache_name = cache_name
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self._ttl_days = {**self.DEFAULT_TTL_DAYS, **(ttl_days or {})}
        self._lock = threading.RLock()
        
        # 多级缓存存储
        self._caches: dict[str, dict[str, CacheEntry]] = {
            CacheLevel.WHITELIST: {},
            CacheLevel.SAFE: {},
            CacheLevel.MALICIOUS: {},
        }
        
        # 统计信息
        self._hits = 0
        self._misses = 0
        
        # 加载缓存
        self._load_all()
    
    def _get_cache_file(self, level: str) -> Path:
        """获取缓存文件路径"""
        return self.cache_dir / f"{self.cache_name}_{level}.json"
    
    def _load_all(self) -> None:
        """加载所有级别的缓存"""
        for level in self._caches:
            self._load_level(level)
    
    def _load_level(self, level: str) -> None:
        """加载指定级别的缓存"""
        cache_file = self._get_cache_file(level)
        if not cache_file.exists():
            return
        
        try:
            with open(cache_file, encoding="utf-8") as f:
                data = json.load(f)
            
            ttl = self._ttl_days.get(level)
            valid_entries = {}
            
            for key, entry_data in data.items():
                entry = CacheEntry(
                    data=entry_data.get("data", entry_data),
                    cached_at=entry_data.get("cached_at", datetime.now().isoformat()),
                    expires_at=entry_data.get("expires_at"),
                )
                
                # 清理过期条目
                if not entry.is_expired(ttl):
                    valid_entries[key] = entry
            
            self._caches[level] = valid_entries
            expired_count = len(data) - len(valid_entries)
            
            if valid_entries:
                logger.info(f"加载 {self.cache_name}/{level} 缓存: {len(valid_entries)} 条有效"
                           f"{f', 清理 {expired_count} 条过期' if expired_count > 0 else ''}")
                
        except Exception as e:
            logger.warning(f"加载缓存 {self.cache_name}/{level} 失败: {e}")
    
    def _save_level(self, level: str) -> None:
        """保存指定级别的缓存"""
        cache = self._caches.get(level, {})
        if not cache:
            return
        
        cache_file = self._get_cache_file(level)
        try:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            
            data = {
                key: {
                    "data": entry.data,
                    "cached_at": entry.cached_at,
                    "expires_at": entry.expires_at,
                }
                for key, entry in cache.items()
            }
            
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            logger.warning(f"保存缓存 {self.cache_name}/{level} 失败: {e}")
    
    def get(self, key: str, level: str | None = None) -> dict[str, Any] | None:
        """
        获取缓存值
        
        Args:
            key: 缓存键
            level: 缓存级别 (None 表示搜索所有级别)
        
        Returns:
            缓存数据或 None
        """
        with self._lock:
            levels_to_search = [level] if level else list(self._caches.keys())
            
            for lvl in levels_to_search:
                cache = self._caches.get(lvl, {})
                entry = cache.get(key)
                
                if entry:
                    ttl = self._ttl_days.get(lvl)
                    if not entry.is_expired(ttl):
                        self._hits += 1
                        return entry.data
                    else:
                        # 过期，删除
                        del cache[key]
            
            self._misses += 1
            return None
    
    def set(
        self,
        key: str,
        data: dict[str, Any],
        level: str = CacheLevel.SAFE,
        save_immediately: bool = False,
    ) -> None:
        """
        设置缓存值
        
        Args:
            key: 缓存键
            data: 缓存数据
            level: 缓存级别
            save_immediately: 是否立即保存到磁盘
        """
        with self._lock:
            now = datetime.now()
            ttl = self._ttl_days.get(level)
            
            expires_at = None
            if ttl is not None:
                from datetime import timedelta
                expires_at = (now + timedelta(days=ttl)).isoformat()
            
            entry = CacheEntry(
                data=data,
                cached_at=now.isoformat(),
                expires_at=expires_at,
            )
            
            self._caches[level][key] = entry
            
            if save_immediately:
                self._save_level(level)
    
    def remove(self, key: str, level: str | None = None) -> bool:
        """
        删除缓存条目
        
        Args:
            key: 缓存键
            level: 缓存级别 (None 表示从所有级别删除)
        
        Returns:
            是否删除成功
        """
        with self._lock:
            removed = False
            levels = [level] if level else list(self._caches.keys())
            
            for lvl in levels:
                cache = self._caches.get(lvl, {})
                if key in cache:
                    del cache[key]
                    removed = True
            
            return removed
    
    def contains(self, key: str, level: str | None = None) -> bool:
        """检查键是否存在"""
        return self.get(key, level) is not None
    
    def get_level_keys(self, level: str) -> list[str]:
        """获取指定级别的所有键"""
        with self._lock:
            return list(self._caches.get(level, {}).keys())
    
    def get_level_size(self, level: str) -> int:
        """获取指定级别的大小"""
        with self._lock:
            return len(self._caches.get(level, {}))
    
    def cleanup_expired(self) -> dict[str, int]:
        """
        清理所有过期的缓存条目
        
        Returns:
            各级别清理的数量
        """
        with self._lock:
            cleaned = {}
            
            for level, cache in self._caches.items():
                ttl = self._ttl_days.get(level)
                if ttl is None:
                    cleaned[level] = 0
                    continue
                
                original_size = len(cache)
                self._caches[level] = {
                    k: v for k, v in cache.items()
                    if not v.is_expired(ttl)
                }
                cleaned[level] = original_size - len(self._caches[level])
            
            # 保存清理后的缓存
            for level in self._caches:
                if cleaned.get(level, 0) > 0:
                    self._save_level(level)
            
            total_cleaned = sum(cleaned.values())
            if total_cleaned > 0:
                logger.info(f"缓存清理完成: 共清理 {total_cleaned} 条过期条目")
            
            return cleaned
    
    def save_all(self) -> None:
        """保存所有缓存到磁盘"""
        with self._lock:
            for level in self._caches:
                self._save_level(level)
    
    def clear(self, level: str | None = None) -> None:
        """清空缓存"""
        with self._lock:
            if level:
                self._caches[level] = {}
            else:
                for lvl in self._caches:
                    self._caches[lvl] = {}
    
    def get_stats(self) -> dict[str, Any]:
        """获取缓存统计信息"""
        with self._lock:
            return {
                "cache_name": self.cache_name,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": self._hits / (self._hits + self._misses) if (self._hits + self._misses) > 0 else 0,
                "levels": {
                    level: {
                        "size": len(cache),
                        "ttl_days": self._ttl_days.get(level),
                    }
                    for level, cache in self._caches.items()
                },
            }


# 便捷工厂函数
def create_ip_cache(cache_dir: Path | str = "data/cache") -> GenericCacheManager:
    """创建 IP 信誉缓存管理器"""
    return GenericCacheManager(
        cache_name="ip_reputation",
        cache_dir=cache_dir,
    )


def create_domain_cache(cache_dir: Path | str = "data/cache") -> GenericCacheManager:
    """创建域名信誉缓存管理器"""
    return GenericCacheManager(
        cache_name="domain_reputation",
        cache_dir=cache_dir,
    )
