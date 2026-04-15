"""AbuseIPDB 智能威胁检测模块 - 三层缓存策略优化 API 调用"""

import logging
import json
import ipaddress
from pathlib import Path
from typing import Optional
from datetime import datetime, timedelta

import pandas as pd

from intel.client import ThreatIntelligenceClient
from core.models import Severity, ThreatType
from core.interfaces import DetectionResult

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

    def __init__(self, whitelist_file: Optional[str] = None,
                 safe_cache_file: Optional[str] = None,
                 malicious_cache_file: Optional[str] = None):
        self.client = ThreatIntelligenceClient()
        self._query_count = 0
        self._cache_hits = 0

        self._whitelist: dict[str, dict] = {}
        self._safe_cache: dict[str, dict] = {}
        self._malicious_cache: dict[str, dict] = {}

        project_root = Path(__file__).resolve().parent.parent.parent
        self._whitelist_file = Path(whitelist_file) if whitelist_file else project_root / "data" / "sources" / "abuseipdb_whitelist.json"
        self._safe_cache_file = Path(safe_cache_file) if safe_cache_file else project_root / "data" / "sources" / "abuseipdb_safe_cache.json"
        self._malicious_cache_file = Path(malicious_cache_file) if malicious_cache_file else project_root / "data" / "sources" / "abuseipdb_malicious_cache.json"

        self._load_whitelist()
        self._load_safe_cache()
        self._load_malicious_cache()

    def _load_whitelist(self):
        """加载白名单"""
        if self._whitelist_file.exists():
            try:
                with open(self._whitelist_file, "r", encoding="utf-8") as f:
                    self._whitelist = json.load(f)
                logger.info(f"加载 AbuseIPDB 白名单: {len(self._whitelist)} 个 IP")
            except Exception as e:
                logger.warning(f"加载白名单失败: {e}")

    def _save_whitelist(self):
        if not self._whitelist:
            return
        try:
            self._whitelist_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._whitelist_file, "w", encoding="utf-8") as f:
                json.dump(self._whitelist, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.warning(f"保存白名单失败: {e}")

    def _load_safe_cache(self):
        """加载安全缓存（自动清理过期）"""
        if self._safe_cache_file.exists():
            try:
                with open(self._safe_cache_file, "r", encoding="utf-8") as f:
                    cache_data = json.load(f)
                now = datetime.now()
                valid_cache = {}
                for ip, info in cache_data.items():
                    cached_time = datetime.fromisoformat(info.get("cached_at", ""))
                    if (now - cached_time).days < self.SAFE_IP_TTL_DAYS:
                        valid_cache[ip] = info
                self._safe_cache = valid_cache
                logger.info(f"加载安全缓存: {len(self._safe_cache)} 个 IP")
            except Exception as e:
                logger.warning(f"加载安全缓存失败: {e}")

    def _save_safe_cache(self):
        if not self._safe_cache:
            return
        try:
            self._safe_cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._safe_cache_file, "w", encoding="utf-8") as f:
                json.dump(self._safe_cache, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.warning(f"保存安全缓存失败: {e}")

    def _load_malicious_cache(self):
        """加载恶意缓存（90天过期）"""
        if self._malicious_cache_file.exists():
            try:
                with open(self._malicious_cache_file, "r", encoding="utf-8") as f:
                    cache_data = json.load(f)
                now = datetime.now()
                valid_cache = {}
                for ip, info in cache_data.items():
                    cached_time = datetime.fromisoformat(info.get("cached_at", ""))
                    if (now - cached_time).days < 90:
                        valid_cache[ip] = info
                self._malicious_cache = valid_cache
                logger.info(f"加载恶意缓存: {len(self._malicious_cache)} 个 IP")
            except Exception as e:
                logger.warning(f"加载恶意缓存失败: {e}")

    def _save_malicious_cache(self):
        if not self._malicious_cache:
            return
        try:
            self._malicious_cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._malicious_cache_file, "w", encoding="utf-8") as f:
                json.dump(self._malicious_cache, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.warning(f"保存恶意缓存失败: {e}")

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
        whitelist_added = 0
        safe_cached = 0
        checked_ips = set()

        for ip in external_ips:
            if ip in checked_ips:
                continue
            checked_ips.add(ip)

            # 检查缓存
            cached_result, from_cache = self._check_cache(ip)
            if from_cache:
                if cached_result.get("is_whitelist"):
                    whitelist_added += 1
                    continue
                elif cached_result.get("is_safe"):
                    safe_cached += 1
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

            if is_safe and abuse_score == ABUSE_SCORE_WHITELIST and is_known_cloud:
                self._whitelist[ip] = {**reputation, "is_whitelist": True, "is_safe": False, "is_malicious": False, "cached_at": datetime.now().isoformat()}
                whitelist_added += 1
            elif is_safe:
                self._safe_cache[ip] = {**reputation, "is_whitelist": False, "is_safe": True, "is_malicious": False, "cached_at": datetime.now().isoformat()}
                safe_cached += 1
            elif is_malicious:
                result = {**reputation, "is_whitelist": False, "is_safe": False, "is_malicious": True, "cached_at": datetime.now().isoformat()}
                self._malicious_cache[ip] = result
                malicious_ips.append(result)
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

        self._save_whitelist()
        self._save_safe_cache()
        self._save_malicious_cache()

        logger.info(f"AbuseIPDB: 检查 {len(checked_ips)} 个 IP, API 查询 {self._query_count} 次, 发现 {len(malicious_ips)} 个恶意 IP")
        return results, malicious_ips

    def _check_cache(self, ip: str) -> tuple[Optional[dict], bool]:
        """检查三层缓存"""
        if ip in self._whitelist:
            self._cache_hits += 1
            return self._whitelist[ip], True
        if ip in self._malicious_cache:
            cached = self._malicious_cache[ip]
            cached_time = datetime.fromisoformat(cached.get("cached_at", ""))
            if (datetime.now() - cached_time).days < 90:
                self._cache_hits += 1
                return cached, True
        if ip in self._safe_cache:
            cached = self._safe_cache[ip]
            cached_time = datetime.fromisoformat(cached.get("cached_at", ""))
            if (datetime.now() - cached_time).days < self.SAFE_IP_TTL_DAYS:
                self._cache_hits += 1
                return cached, True
        return None, False

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
        return {"whitelist_size": len(self._whitelist), "safe_cache_size": len(self._safe_cache), "api_queries": self._query_count, "cache_hits": self._cache_hits}

    def close(self):
        self.client.close()
        self._save_whitelist()
        self._save_safe_cache()
        self._save_malicious_cache()
