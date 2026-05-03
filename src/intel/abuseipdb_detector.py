"""AbuseIPDB 智能威胁检测模块 - 三层缓存策略优化 API 调用"""

import ipaddress
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

import pandas as pd

from core.interfaces import DetectionResult
from core.models import Severity, ThreatType
from intel.client import ThreatIntelligenceClient
from utils.cache_manager import CacheLevel, GenericCacheManager

logger = logging.getLogger(__name__)

# AbuseIPDB 评分阈值
ABUSE_SCORE_WHITELIST = 0   # 白名单阈值
ABUSE_SCORE_SAFE = 10       # 安全缓存阈值
ABUSE_SCORE_THREAT = 10     # 恶意阈值


class AbuseIPDBSmartDetector:
    """AbuseIPDB 智能检测器，三层缓存：白名单(永久) + 安全缓存(30天) + 恶意缓存(90天)"""

    SAFE_IP_TTL_DAYS = 30

    KNOWN_CLOUD_PROVIDERS = {
        "Google LLC", "Google Cloud", "Cloudflare, Inc.", "Cloudflare",
        "Amazon Technologies Inc.", "Amazon.com", "Microsoft Corporation", "Azure",
        "Akamai Technologies", "Fastly", "DigitalOcean, LLC",
    }

    def __init__(self, cache_dir: Optional[str] = None):
        self.client = ThreatIntelligenceClient()
        self._query_count = 0
        self._cache_hits = 0

        # 使用通用缓存管理器
        project_root = Path(__file__).resolve().parent.parent.parent
        cache_path = Path(cache_dir) if cache_dir else project_root / "data" / "cache"
        
        self._cache = GenericCacheManager(
            cache_name="abuseipdb",
            cache_dir=cache_path,
            ttl_days={
                CacheLevel.WHITELIST: None,  # 永久
                CacheLevel.SAFE: 30,
                CacheLevel.MALICIOUS: 90,
            },
        )

    def _check_cache(self, ip: str) -> tuple[Optional[dict], bool]:
        """检查三层缓存"""
        # 检查白名单
        data = self._cache.get(ip, CacheLevel.WHITELIST)
        if data:
            self._cache_hits += 1
            return data, True
        
        # 检查恶意缓存
        data = self._cache.get(ip, CacheLevel.MALICIOUS)
        if data:
            self._cache_hits += 1
            return data, True
        
        # 检查安全缓存
        data = self._cache.get(ip, CacheLevel.SAFE)
        if data:
            self._cache_hits += 1
            return data, True
        
        return None, False

    def detect_threats(self, df: pd.DataFrame) -> tuple[list[DetectionResult], list[dict]]:
        """检测网络流中的威胁 IP"""
        if "dst_ip" not in df.columns:
            return [], []

        # 获取外部 IP
        external_ips = []
        for ip_str in df["dst_ip"].dropna().unique():
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_link_local:
                    external_ips.append(ip_str)
            except ValueError:
                continue

        results = []
        malicious_ips = []
        checked_ips = set()

        for ip in external_ips:
            if ip in checked_ips:
                continue
            checked_ips.add(ip)

            # 检查缓存
            cached_result, from_cache = self._check_cache(ip)
            if from_cache:
                if cached_result.get("is_whitelist"):
                    continue
                elif cached_result.get("is_safe"):
                    continue
                elif cached_result.get("is_malicious"):
                    malicious_ips.append(cached_result)
                    continue

            # 查询 API
            reputation = self._query_api(ip)
            if not reputation:
                continue

            abuse_score = reputation.get("abuse_score", 0)
            isp = reputation.get("isp") or ""
            is_known_cloud = any(provider in isp for provider in self.KNOWN_CLOUD_PROVIDERS)
            is_malicious = abuse_score >= ABUSE_SCORE_THREAT
            is_safe = abuse_score < ABUSE_SCORE_SAFE

            cache_data = {**reputation, "cached_at": datetime.now().isoformat()}

            if is_safe and abuse_score == ABUSE_SCORE_WHITELIST and is_known_cloud:
                cache_data.update({"is_whitelist": True, "is_safe": False, "is_malicious": False})
                self._cache.set(ip, cache_data, CacheLevel.WHITELIST)
            elif is_safe:
                cache_data.update({"is_whitelist": False, "is_safe": True, "is_malicious": False})
                self._cache.set(ip, cache_data, CacheLevel.SAFE)
            elif is_malicious:
                cache_data.update({"is_whitelist": False, "is_safe": False, "is_malicious": True})
                self._cache.set(ip, cache_data, CacheLevel.MALICIOUS)
                malicious_ips.append(cache_data)
                results.append(DetectionResult(
                    engine_name="abuseipdb_smart_detector",
                    engine_version="1.0.0",
                    threat_type=ThreatType.MALICIOUS_IP,
                    severity=Severity.HIGH if abuse_score >= 50 else Severity.MEDIUM,
                    description=f"AbuseIPDB: {ip} (滥用评分: {abuse_score}%)",
                    evidence={"ip": ip, "abuse_score": abuse_score, "country_code": reputation.get("country_code"), "isp": reputation.get("isp")},
                    confidence=0.95 if abuse_score >= 50 else 0.7,
                    ioc=[ip],
                    recommended_action="建议封禁该 IP 或进一步调查"
                ))

        # 保存缓存
        self._cache.save_all()

        logger.info(f"AbuseIPDB: 检查 {len(checked_ips)} 个 IP, API 查询 {self._query_count} 次, 发现 {len(malicious_ips)} 个恶意 IP")
        return results, malicious_ips

    def _query_api(self, ip: str) -> Optional[dict]:
        """查询 AbuseIPDB API"""
        reputation = self.client.check_abuseipdb(ip)
        if reputation:
            self._query_count += 1
            return {
                "ip": ip, "abuse_score": reputation.abuse_score,
                "country_code": reputation.country_code, "isp": reputation.isp,
                "usage_type": reputation.usage_type, "is_tor": reputation.is_tor,
                "is_public": reputation.is_public, "reports_count": reputation.reports_count,
                "domain": reputation.domain,
            }
        return None

    def get_stats(self) -> dict:
        """获取统计信息"""
        return {
            "whitelist_size": self._cache.get_level_size(CacheLevel.WHITELIST),
            "safe_cache_size": self._cache.get_level_size(CacheLevel.SAFE),
            "malicious_cache_size": self._cache.get_level_size(CacheLevel.MALICIOUS),
            "api_queries": self._query_count,
            "cache_hits": self._cache_hits,
        }

    def close(self):
        """关闭检测器并保存缓存"""
        self.client.close()
        self._cache.save_all()
