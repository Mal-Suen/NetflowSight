"""
Threat Intelligence Cache
"""

import json
import logging
import time
from pathlib import Path
from typing import Optional

from core.config import settings
from core.models import IPReputation

logger = logging.getLogger(__name__)


class ThreatCache:
    """
    Local cache for threat intelligence results.
    
    Reduces API calls and improves performance.
    """
    
    def __init__(self, cache_dir: str = ".cache/threat_intel"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "ip_reputation.json"
        self.ttl_hours = settings.THREAT_CACHE_TTL_HOURS
        self._cache: dict = self._load_cache()
    
    def _load_cache(self) -> dict:
        """Load cache from disk."""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load threat cache: {e}")
        return {}
    
    def _save_cache(self) -> None:
        """Save cache to disk."""
        try:
            with open(self.cache_file, "w") as f:
                json.dump(self._cache, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save threat cache: {e}")
    
    def get(self, ip: str) -> Optional[IPReputation]:
        """
        Get cached IP reputation.
        
        Args:
            ip: IP address
            
        Returns:
            Cached IPReputation or None if not found/expired
        """
        if not settings.THREAT_CACHE_ENABLED:
            return None
        
        if ip not in self._cache:
            return None
        
        entry = self._cache[ip]
        age_hours = (time.time() - entry["timestamp"]) / 3600
        
        if age_hours > self.ttl_hours:
            # Expired
            del self._cache[ip]
            return None
        
        return IPReputation(
            ip=ip,
            abuse_score=entry.get("abuse_score", 0),
            country_code=entry.get("country_code"),
            usage_type=entry.get("usage_type"),
            isp=entry.get("isp"),
            domain=entry.get("domain"),
            is_tor=entry.get("is_tor", False),
            is_public=entry.get("is_public", True),
            reports_count=entry.get("reports_count", 0),
        )
    
    def set(self, reputation: IPReputation) -> None:
        """
        Cache IP reputation result.
        
        Args:
            reputation: IPReputation object to cache
        """
        if not settings.THREAT_CACHE_ENABLED:
            return
        
        self._cache[reputation.ip] = {
            "abuse_score": reputation.abuse_score,
            "country_code": reputation.country_code,
            "usage_type": reputation.usage_type,
            "isp": reputation.isp,
            "domain": reputation.domain,
            "is_tor": reputation.is_tor,
            "is_public": reputation.is_public,
            "reports_count": reputation.reports_count,
            "timestamp": time.time(),
        }
        
        # Periodically save (every 100 entries)
        if len(self._cache) % 100 == 0:
            self._save_cache()
    
    def flush(self) -> None:
        """Save and clear cache."""
        self._save_cache()
        self._cache.clear()

    def cleanup_expired(self) -> int:
        """Remove expired entries. Returns count of removed entries."""
        now = time.time()
        ttl_seconds = self.ttl_hours * 3600

        # Build new cache without expired entries (more efficient than del in loop)
        active = {
            ip: entry
            for ip, entry in self._cache.items()
            if (now - entry["timestamp"]) <= ttl_seconds
        }

        expired_count = len(self._cache) - len(active)
        if expired_count > 0:
            self._cache = active
            logger.info(f"Cleaned up {expired_count} expired cache entries")
            self._save_cache()

        return expired_count
