"""
Threat Intelligence Fusion Engine

Standardized multi-source threat intelligence aggregation with:
- Provider abstraction (AbuseIPDB, VirusTotal, etc.)
- Weighted scoring
- Local caching
- IOC feed management
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from plugins.interfaces import (
    DomainReputation,
    IOC,
    IPReputation,
    ThreatIntelProvider,
)

logger = logging.getLogger(__name__)


class AbuseIPDBProvider:
    """AbuseIPDB threat intelligence provider."""
    
    name = "abuseipdb"
    cost_tier = "freemium"
    rate_limit = 1000  # requests per day (free tier)
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self._session = None
    
    def _get_session(self):
        if self._session is None:
            import requests
            self._session = requests.Session()
            self._session.headers.update({"Accept": "application/json", "Key": self.api_key})
        return self._session
    
    def check_ip(self, ip: str) -> Optional[IPReputation]:
        if not self.api_key:
            return None
        
        try:
            session = self._get_session()
            response = session.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""},
                timeout=10,
            )
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                return IPReputation(
                    ip=ip,
                    threat_score=data.get("abuseConfidenceScore", 0) / 100.0,
                    source=self.name,
                    tags=self._extract_tags(data),
                    country=data.get("countryCode"),
                    isp=data.get("isp"),
                    is_tor=data.get("isTor", False),
                    is_hosting=data.get("usageType", "") == "Data Center/Web Hosting/Transit",
                    reports_count=data.get("totalReports", 0),
                    last_seen=data.get("lastReportedAt"),
                    raw_data=data,
                )
            elif response.status_code == 429:
                logger.warning("AbuseIPDB rate limit exceeded")
            elif response.status_code != 404:
                logger.warning(f"AbuseIPDB API error: {response.status_code}")
        except Exception as e:
            logger.error(f"AbuseIPDB check failed for {ip}: {e}")
        
        return None
    
    def check_domain(self, domain: str) -> Optional[DomainReputation]:
        # AbuseIPDB doesn't support domain checks directly
        return None
    
    def get_ioc_feed(self) -> list[IOC]:
        # Would require premium API access
        return []
    
    @staticmethod
    def _extract_tags(data: dict) -> list[str]:
        tags = []
        if data.get("isTor"):
            tags.append("tor")
        if data.get("isPublic"):
            tags.append("public")
        usage_type = data.get("usageType", "")
        if "hosting" in usage_type.lower():
            tags.append("hosting")
        if "residential" in usage_type.lower():
            tags.append("residential")
        return tags


class ThreatIntelFusion:
    """
    Multi-source threat intelligence fusion engine.
    
    Combines results from multiple providers with weighted scoring
    to produce a unified, high-confidence threat assessment.
    """
    
    def __init__(self, providers: Optional[list[ThreatIntelProvider]] = None):
        self.providers = providers or []
        self.confidence_weights = {
            "abuseipdb": 0.8,
            "virustotal": 0.9,
            "alienvault_otx": 0.7,
            "local_ioc_db": 1.0,
        }
        self._cache: dict[str, Any] = {}
        self._cache_ttl = 3600  # 1 hour
        self._stats = {
            "checks": 0,
            "cache_hits": 0,
            "api_calls": 0,
            "errors": 0,
        }
    
    def add_provider(self, provider: ThreatIntelProvider) -> None:
        """Add a threat intelligence provider."""
        self.providers.append(provider)
        logger.info(f"Added provider: {provider.name} ({provider.cost_tier})")
    
    def check_ip(self, ip: str) -> FusionResult:
        """
        Check IP against all providers and fuse results.
        
        Returns:
            FusionResult with combined threat assessment
        """
        # Check cache
        cache_key = f"ip:{ip}"
        cached = self._check_cache(cache_key)
        if cached:
            self._stats["cache_hits"] += 1
            return cached
        
        self._stats["checks"] += 1
        results = {}
        
        for provider in self.providers:
            try:
                result = provider.check_ip(ip)
                if result:
                    results[provider.name] = result
                    self._stats["api_calls"] += 1
            except Exception as e:
                logger.error(f"Provider {provider.name} failed: {e}")
                self._stats["errors"] += 1
        
        fused = self._fuse_ip_results(ip, results)
        self._set_cache(cache_key, fused)
        
        return fused
    
    def check_domain(self, domain: str) -> FusionResult:
        """Check domain against all providers and fuse results."""
        cache_key = f"domain:{domain}"
        cached = self._check_cache(cache_key)
        if cached:
            self._stats["cache_hits"] += 1
            return cached
        
        self._stats["checks"] += 1
        results = {}
        
        for provider in self.providers:
            try:
                result = provider.check_domain(domain)
                if result:
                    results[provider.name] = result
                    self._stats["api_calls"] += 1
            except Exception as e:
                logger.error(f"Provider {provider.name} failed: {e}")
                self._stats["errors"] += 1
        
        fused = self._fuse_domain_results(domain, results)
        self._set_cache(cache_key, fused)
        
        return fused
    
    def _fuse_ip_results(self, ip: str, results: dict[str, IPReputation]) -> FusionResult:
        """Fuse multiple IP reputation results."""
        if not results:
            return FusionResult(
                query=ip,
                query_type="ip",
                threat_score=0.0,
                consensus="UNKNOWN",
                sources={},
                tags=[],
                recommended_action="No intelligence data available for this IP.",
            )
        
        weighted_scores = []
        all_tags = set()
        sources = {}
        
        for source_name, data in results.items():
            weight = self.confidence_weights.get(source_name, 0.5)
            score = data.threat_score * weight
            weighted_scores.append(score)
            all_tags.update(data.tags)
            sources[source_name] = {
                "threat_score": data.threat_score,
                "tags": data.tags,
                "raw": data.raw_data,
            }
        
        # Calculate weighted average
        total_weight = sum(self.confidence_weights.get(s, 0.5) for s in results)
        final_score = sum(weighted_scores) / total_weight if total_weight > 0 else 0.0
        
        # Determine consensus
        if final_score >= 0.8:
            consensus = "HIGH_CONFIDENCE_MALICIOUS"
        elif final_score >= 0.6:
            consensus = "LIKELY_MALICIOUS"
        elif final_score >= 0.3:
            consensus = "POSSIBLY_SUSPICIOUS"
        else:
            consensus = "LIKELY_CLEAN"
        
        # Determine recommended action
        if final_score >= 0.8:
            action = "Block immediately. High confidence malicious IP."
        elif final_score >= 0.6:
            action = "Investigate and consider blocking. Likely malicious."
        elif final_score >= 0.3:
            action = "Monitor and investigate further. Possibly suspicious."
        else:
            action = "No action required. Appears clean."
        
        return FusionResult(
            query=ip,
            query_type="ip",
            threat_score=round(final_score, 3),
            consensus=consensus,
            sources=sources,
            tags=list(all_tags),
            recommended_action=action,
        )
    
    def _fuse_domain_results(self, domain: str, results: dict[str, DomainReputation]) -> FusionResult:
        """Fuse multiple domain reputation results."""
        if not results:
            return FusionResult(
                query=domain,
                query_type="domain",
                threat_score=0.0,
                consensus="UNKNOWN",
                sources={},
                tags=[],
                recommended_action="No intelligence data available for this domain.",
            )
        
        weighted_scores = []
        all_tags = set()
        sources = {}
        
        for source_name, data in results.items():
            weight = self.confidence_weights.get(source_name, 0.5)
            score = data.threat_score * weight
            weighted_scores.append(score)
            all_tags.update(data.tags)
            sources[source_name] = {
                "threat_score": data.threat_score,
                "tags": data.tags,
                "raw": data.raw_data,
            }
        
        total_weight = sum(self.confidence_weights.get(s, 0.5) for s in results)
        final_score = sum(weighted_scores) / total_weight if total_weight > 0 else 0.0
        
        if final_score >= 0.8:
            consensus = "HIGH_CONFIDENCE_MALICIOUS"
        elif final_score >= 0.6:
            consensus = "LIKELY_MALICIOUS"
        elif final_score >= 0.3:
            consensus = "POSSIBLY_SUSPICIOUS"
        else:
            consensus = "LIKELY_CLEAN"
        
        if final_score >= 0.8:
            action = "Block domain immediately. High confidence malicious."
        elif final_score >= 0.6:
            action = "Investigate and consider blocking. Likely malicious."
        elif final_score >= 0.3:
            action = "Monitor and investigate further. Possibly suspicious."
        else:
            action = "No action required. Appears clean."
        
        return FusionResult(
            query=domain,
            query_type="domain",
            threat_score=round(final_score, 3),
            consensus=consensus,
            sources=sources,
            tags=list(all_tags),
            recommended_action=action,
        )
    
    def _check_cache(self, key: str) -> Optional[FusionResult]:
        """Check if result is in cache and not expired."""
        if key in self._cache:
            entry = self._cache[key]
            if time.time() - entry["timestamp"] < self._cache_ttl:
                return entry["result"]
            else:
                del self._cache[key]
        return None
    
    def _set_cache(self, key: str, result: FusionResult) -> None:
        """Cache a result with timestamp."""
        self._cache[key] = {
            "result": result,
            "timestamp": time.time(),
        }
    
    def get_stats(self) -> dict[str, Any]:
        """Get provider statistics."""
        return {
            "providers": [p.name for p in self.providers],
            "cache_size": len(self._cache),
            "checks": self._stats["checks"],
            "cache_hits": self._stats["cache_hits"],
            "api_calls": self._stats["api_calls"],
            "errors": self._stats["errors"],
            "cache_hit_rate": (
                round(self._stats["cache_hits"] / max(self._stats["checks"], 1) * 100, 1)
            ),
        }
    
    def clear_cache(self) -> None:
        """Clear all cached results."""
        self._cache.clear()


class FusionResult:
    """Standardized fusion result from multi-source intelligence."""
    
    def __init__(
        self,
        query: str,
        query_type: str,
        threat_score: float,
        consensus: str,
        sources: dict,
        tags: list[str],
        recommended_action: str,
    ):
        self.query = query
        self.query_type = query_type
        self.threat_score = threat_score
        self.consensus = consensus
        self.sources = sources
        self.tags = tags
        self.recommended_action = recommended_action
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "query_type": self.query_type,
            "threat_score": self.threat_score,
            "consensus": self.consensus,
            "sources": self.sources,
            "tags": self.tags,
            "recommended_action": self.recommended_action,
        }
