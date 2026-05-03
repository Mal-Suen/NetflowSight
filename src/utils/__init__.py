"""工具模块"""

from utils.cache_manager import (
    CacheLevel,
    GenericCacheManager,
    create_domain_cache,
    create_ip_cache,
)

__all__ = [
    "CacheLevel",
    "GenericCacheManager",
    "create_ip_cache",
    "create_domain_cache",
]
