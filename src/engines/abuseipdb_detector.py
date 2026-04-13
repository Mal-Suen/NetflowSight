"""
AbuseIPDB 智能威胁检测模块
类似微步在线的智能检测逻辑：
- 根据 abuse_score 判断 IP 威胁等级
- 白名单 IP（永久保存）
- 安全 IP 缓存（有过期机制）
- 恶意 IP 生成告警
"""

import logging
import json
import ipaddress
from pathlib import Path
from typing import Optional
from datetime import datetime, timedelta

import pandas as pd

from intel.client import ThreatIntelligenceClient
from core.models import Severity, ThreatType
from plugins.interfaces import DetectionResult

logger = logging.getLogger(__name__)

# AbuseIPDB abuse_score 阈值
# 0 = 完全干净，1-9 = 轻微可疑，10+ = 威胁
ABUSE_SCORE_WHITELIST = 0      # abuse_score == 0 且是知名服务 → 白名单
ABUSE_SCORE_SAFE = 10          # abuse_score < 10 → 安全缓存
ABUSE_SCORE_THREAT = 10        # abuse_score >= 10 → 恶意 IP


class AbuseIPDBSmartDetector:
    """
    AbuseIPDB 智能威胁检测器

    策略：
    1. 先检查本地白名单和安全缓存
    2. 未命中则查询 AbuseIPDB API
    3. 根据 abuse_score 分类处理：
       - abuse_score == 0 且是知名服务 → ✅ 加入白名单（永久）
       - abuse_score < 10 → 🔒 加入安全缓存（30 天过期）
       - abuse_score >= 10 → 🔴 生成告警
    4. 下次遇到相同 IP 先从两份名单中查找，命中则不消耗 API 额度

    注意：白名单和安全 IP 缓存是两份不同的名单
    - 白名单：知名云服务/CDN IP，永久有效
    - 安全 IP 缓存：本次查询未发现异常，但有有效期（30 天），过期后需重新查询
    """

    # 安全 IP 缓存有效期（30 天）
    SAFE_IP_TTL_DAYS = 30

    # 知名云服务/CDN IP 段（用于白名单判断）
    KNOWN_CLOUD_PROVIDERS = {
        "Google LLC", "Google Cloud", "Google LLC",
        "Cloudflare, Inc.", "Cloudflare",
        "Amazon Technologies Inc.", "Amazon.com", "Amazon Data Services",
        "Microsoft Corporation", "Microsoft Azure", "Azure",
        "Akamai Technologies", "Akamai",
        "Fastly", "Fastly, Inc",
        "DigitalOcean, LLC", "Digital Ocean",
    }

    def __init__(self,
                 whitelist_file: Optional[str] = None,
                 safe_cache_file: Optional[str] = None,
                 malicious_cache_file: Optional[str] = None):
        self.client = ThreatIntelligenceClient()
        self._query_count = 0
        self._cache_hits = 0

        # 三份不同的名单
        self._whitelist: dict[str, dict] = {}  # 白名单（永久）
        self._safe_cache: dict[str, dict] = {}  # 安全缓存（30 天过期）
        self._malicious_cache: dict[str, dict] = {}  # 恶意缓存（90 天过期，用于避免重复告警）

        # 获取项目根目录
        project_root = Path(__file__).resolve().parent.parent.parent

        # 设置默认文件路径
        self._whitelist_file = Path(whitelist_file) if whitelist_file else project_root / "data" / "sources" / "abuseipdb_whitelist.json"
        self._safe_cache_file = Path(safe_cache_file) if safe_cache_file else project_root / "data" / "sources" / "abuseipdb_safe_cache.json"
        self._malicious_cache_file = Path(malicious_cache_file) if malicious_cache_file else project_root / "data" / "sources" / "abuseipdb_malicious_cache.json"

        # 加载本地数据
        self._load_whitelist()
        self._load_safe_cache()
        self._load_malicious_cache()

    def _load_whitelist(self):
        """加载白名单文件（永久有效）"""
        if self._whitelist_file.exists():
            try:
                with open(self._whitelist_file, "r", encoding="utf-8") as f:
                    self._whitelist = json.load(f)
                logger.info(f"加载 AbuseIPDB 白名单: {len(self._whitelist)} 个 IP")
            except Exception as e:
                logger.warning(f"加载 AbuseIPDB 白名单失败: {e}")
                self._whitelist = {}

    def _save_whitelist(self):
        """保存白名单到本地文件"""
        if not self._whitelist:
            return

        try:
            self._whitelist_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._whitelist_file, "w", encoding="utf-8") as f:
                json.dump(self._whitelist, f, indent=2, ensure_ascii=False)
            logger.info(f"AbuseIPDB 白名单已保存到 {self._whitelist_file} ({len(self._whitelist)} 个 IP)")
        except Exception as e:
            logger.warning(f"保存 AbuseIPDB 白名单失败: {e}")

    def _load_safe_cache(self):
        """加载安全 IP 缓存（有过期机制）"""
        if self._safe_cache_file.exists():
            try:
                with open(self._safe_cache_file, "r", encoding="utf-8") as f:
                    cache_data = json.load(f)

                # 清理过期缓存（超过 30 天）
                now = datetime.now()
                valid_cache = {}
                expired_count = 0
                for ip, info in cache_data.items():
                    cached_time = datetime.fromisoformat(info.get("cached_at", ""))
                    if (now - cached_time).days < self.SAFE_IP_TTL_DAYS:
                        valid_cache[ip] = info
                    else:
                        expired_count += 1

                self._safe_cache = valid_cache
                if expired_count > 0:
                    logger.info(f"清理了 {expired_count} 个过期的 AbuseIPDB 安全 IP 缓存")
                logger.info(f"加载 AbuseIPDB 安全 IP 缓存: {len(self._safe_cache)} 个 IP")
            except Exception as e:
                logger.warning(f"加载 AbuseIPDB 安全缓存失败: {e}")
                self._safe_cache = {}

    def _save_safe_cache(self):
        """保存安全 IP 缓存到本地文件"""
        if not self._safe_cache:
            return

        try:
            self._safe_cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._safe_cache_file, "w", encoding="utf-8") as f:
                json.dump(self._safe_cache, f, indent=2, ensure_ascii=False)
            logger.info(f"AbuseIPDB 安全 IP 缓存已保存到 {self._safe_cache_file} ({len(self._safe_cache)} 个 IP)")
        except Exception as e:
            logger.warning(f"保存 AbuseIPDB 安全缓存失败: {e}")

    def _load_malicious_cache(self):
        """加载恶意 IP 缓存（90 天过期）"""
        if self._malicious_cache_file.exists():
            try:
                with open(self._malicious_cache_file, "r", encoding="utf-8") as f:
                    cache_data = json.load(f)

                # 清理过期缓存（超过 90 天）
                now = datetime.now()
                valid_cache = {}
                expired_count = 0
                for ip, info in cache_data.items():
                    cached_time = datetime.fromisoformat(info.get("cached_at", ""))
                    if (now - cached_time).days < 90:
                        valid_cache[ip] = info
                    else:
                        expired_count += 1

                self._malicious_cache = valid_cache
                if expired_count > 0:
                    logger.info(f"清理了 {expired_count} 个过期的 AbuseIPDB 恶意 IP 缓存")
                logger.info(f"加载 AbuseIPDB 恶意 IP 缓存: {len(self._malicious_cache)} 个 IP")
            except Exception as e:
                logger.warning(f"加载 AbuseIPDB 恶意缓存失败: {e}")
                self._malicious_cache = {}

    def _save_malicious_cache(self):
        """保存恶意 IP 缓存到本地文件"""
        if not self._malicious_cache:
            return

        try:
            self._malicious_cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._malicious_cache_file, "w", encoding="utf-8") as f:
                json.dump(self._malicious_cache, f, indent=2, ensure_ascii=False)
            logger.info(f"AbuseIPDB 恶意 IP 缓存已保存到 {self._malicious_cache_file} ({len(self._malicious_cache)} 个 IP)")
        except Exception as e:
            logger.warning(f"保存 AbuseIPDB 恶意缓存失败: {e}")

    def detect_threats(self, df: pd.DataFrame) -> tuple[list[DetectionResult], list[dict]]:
        """
        检测网络流中的威胁 IP

        Args:
            df: 网络流 DataFrame

        Returns:
            (威胁检测结果列表, 恶意 IP 列表)
        """
        if "dst_ip" not in df.columns:
            return [], []

        # 获取外部 IP（使用 ipaddress 模块排除私有/保留 IP，支持 IPv6）
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

            # 第一步：检查白名单、安全缓存和恶意缓存
            cached_result, from_cache = self._check_cache(ip)
            if from_cache:
                if cached_result.get("is_whitelist"):
                    # 白名单 IP，直接跳过
                    whitelist_added += 1
                    continue
                elif cached_result.get("is_safe"):
                    # 安全 IP 缓存，跳过
                    safe_cached += 1
                    continue
                elif cached_result.get("is_malicious"):
                    # 之前标记为恶意的 IP，重新生成告警
                    malicious_ips.append(cached_result)
                    continue

            # 第二步：查询 AbuseIPDB API
            reputation = self._query_api(ip)
            if not reputation:
                continue

            abuse_score = reputation.get("abuse_score", 0)
            isp = reputation.get("isp") or ""
            is_known_cloud = any(provider in isp for provider in self.KNOWN_CLOUD_PROVIDERS)
            is_malicious = abuse_score >= ABUSE_SCORE_THREAT
            is_safe = abuse_score < ABUSE_SCORE_SAFE

            if is_safe and abuse_score == ABUSE_SCORE_WHITELIST and is_known_cloud:
                # ✅ 加入白名单（知名云服务，abuse_score == 0）
                self._whitelist[ip] = {
                    **reputation,
                    "is_whitelist": True,
                    "is_safe": False,
                    "is_malicious": False,
                    "cached_at": datetime.now().isoformat(),
                }
                whitelist_added += 1
                logger.debug(f"AbuseIPDB 白名单 IP: {ip} (abuse_score: {abuse_score})")

            elif is_safe:
                # 🔒 加入安全缓存（abuse_score < 10）
                self._safe_cache[ip] = {
                    **reputation,
                    "is_whitelist": False,
                    "is_safe": True,
                    "is_malicious": False,
                    "cached_at": datetime.now().isoformat(),
                }
                safe_cached += 1
                logger.debug(f"AbuseIPDB 安全 IP: {ip} (abuse_score: {abuse_score})")

            elif is_malicious:
                # 🔴 生成告警，存入恶意缓存（不与安全缓存混用）
                result = {
                    **reputation,
                    "is_whitelist": False,
                    "is_safe": False,
                    "is_malicious": True,
                    "cached_at": datetime.now().isoformat(),
                }
                self._malicious_cache[ip] = result

                malicious_ips.append(result)
                results.append(DetectionResult(
                    engine_name="abuseipdb_smart_detector",
                    engine_version="1.0.0",
                    threat_type=ThreatType.MALICIOUS_IP,
                    severity=Severity.HIGH if abuse_score >= 50 else Severity.MEDIUM,
                    description=f"[{'缓存' if from_cache else 'API'}] AbuseIPDB 情报: {ip} (滥用评分: {abuse_score}%, ISP: {reputation.get('isp', 'Unknown')})",
                    evidence={
                        "ip": ip,
                        "abuse_score": abuse_score,
                        "country_code": reputation.get("country_code"),
                        "isp": reputation.get("isp"),
                        "usage_type": reputation.get("usage_type"),
                        "is_tor": reputation.get("is_tor", False),
                        "reports_count": reputation.get("reports_count", 0),
                    },
                    confidence=0.95 if abuse_score >= 50 else 0.7,
                    ioc=[ip],
                    recommended_action="建议：该 IP 被 AbuseIPDB 标记为恶意 IP，建议封禁或进一步调查。"
                ))

        # 保存三份名单
        self._save_whitelist()
        self._save_safe_cache()
        self._save_malicious_cache()

        # 输出统计
        cache_tag = f"(缓存命中 {self._cache_hits} 次)" if self._cache_hits > 0 else ""
        logger.info(
            f"AbuseIPDBSmartDetector: 检查 {len(checked_ips)} 个外部 IP, "
            f"API 查询 {self._query_count} 次 {cache_tag}, "
            f"发现 {len(malicious_ips)} 个恶意 IP, "
            f"白名单 +{whitelist_added}, 安全缓存 +{safe_cached}"
        )
        return results, malicious_ips

    def _check_cache(self, ip: str) -> tuple[Optional[dict], bool]:
        """
        检查白名单、安全缓存和恶意缓存

        Returns:
            (威胁情报字典，是否来自缓存)
        """
        # 检查白名单（永久有效）
        if ip in self._whitelist:
            self._cache_hits += 1
            return self._whitelist[ip], True

        # 检查恶意缓存（90 天过期）
        if ip in self._malicious_cache:
            cached = self._malicious_cache[ip]
            cached_time = datetime.fromisoformat(cached.get("cached_at", ""))
            if (datetime.now() - cached_time).days < 90:
                self._cache_hits += 1
                return cached, True

        # 检查安全缓存（30 天过期）
        if ip in self._safe_cache:
            cached = self._safe_cache[ip]
            cached_time = datetime.fromisoformat(cached.get("cached_at", ""))
            if (datetime.now() - cached_time).days < self.SAFE_IP_TTL_DAYS:
                self._cache_hits += 1
                return cached, True

        return None, False

    def _query_api(self, ip: str) -> Optional[dict]:
        """
        查询 AbuseIPDB API

        Returns:
            威胁情报字典，或 None（如果查询失败）
        """
        reputation = self.client.check_abuseipdb(ip)
        if reputation:
            self._query_count += 1
            return {
                "ip": ip,
                "abuse_score": reputation.abuse_score,
                "country_code": reputation.country_code,
                "isp": reputation.isp,
                "usage_type": reputation.usage_type,
                "is_tor": reputation.is_tor,
                "is_public": reputation.is_public,
                "reports_count": reputation.reports_count,
                "domain": reputation.domain,
            }
        return None

    def get_stats(self) -> dict:
        """获取检测统计"""
        return {
            "whitelist_size": len(self._whitelist),
            "safe_cache_size": len(self._safe_cache),
            "api_queries": self._query_count,
            "cache_hits": self._cache_hits,
        }

    def get_whitelist(self) -> list[str]:
        """获取白名单 IP 列表"""
        return list(self._whitelist.keys())

    def get_safe_ips(self) -> list[dict]:
        """获取安全 IP 列表（含过期时间）"""
        now = datetime.now()
        safe_ips = []
        for ip, info in self._safe_cache.items():
            cached_time = datetime.fromisoformat(info.get("cached_at", ""))
            expires_at = cached_time + timedelta(days=self.SAFE_IP_TTL_DAYS)
            days_left = (expires_at - now).days
            if days_left > 0:
                safe_ips.append({
                    "ip": ip,
                    "expires_at": expires_at.isoformat(),
                    "days_left": days_left,
                    "abuse_score": info.get("abuse_score"),
                    "isp": info.get("isp"),
                })
        return safe_ips

    def close(self):
        """关闭客户端"""
        self.client.close()
        self._save_whitelist()
        self._save_safe_cache()
        self._save_malicious_cache()
