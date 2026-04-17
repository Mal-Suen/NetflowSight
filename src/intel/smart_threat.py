"""
智能威胁检测模块
只查询可疑域名到微步 API，避免滥用免费额度

策略：
1. 先使用 ML 域名分类器筛选可疑域名（替代旧的正则规则）
2. 查询微步 API
3. 根据返回结果分类处理：
   - judgments 包含 "Whitelist" → ✅ 加入白名单（永久保存）
   - 安全但未标记白名单 → 🔒 加入安全缓存（30 天过期）
   - 可疑/恶意 → 🔴 生成告警
4. 下次遇到相同域名先从两份名单中查找，命中则不消耗 API 额度

注意：白名单和安全域名是两份不同的名单
- 白名单：微步官方认证的合法域名，永久有效
- 安全域名：本次查询未发现异常，但有有效期（30 天），过期后需重新查询
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import pandas as pd

from core.interfaces import DetectionResult, Severity, ThreatType
from intel.threatbook import ThreatBookClient
from ml.domain_classifier import DomainClassifier

logger = logging.getLogger(__name__)

# 已知安全域名关键词（用于快速过滤，避免对正常服务产生 API 查询）
_SAFE_DOMAIN_KEYWORDS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "github.com", "cloudflare.com",
    "baidu.com", "aliyun.com", "tencent.com", "qq.com",
    "netease.com", "sina.com.cn", "sohu.com", "jd.com",
    "huawei.com", "xiaomi.com", "bilibili.com", "douyin.com",
}


class SmartThreatDetector:
    """
    智能威胁检测器

    策略：
    1. 先使用本地规则筛选可疑域名
    2. 只将可疑域名发送到微步 API 查询
    3. 根据返回结果分类处理：
       - judgments 包含 "Whitelist" → ✅ 加入白名单（永久保存）
       - 安全但未标记白名单 → 🔒 加入安全缓存（30 天过期）
       - 可疑/恶意 → 🔴 生成告警
    4. 下次遇到相同域名先从两份名单中查找，命中则不消耗 API 额度

    注意：白名单和安全域名是两份不同的名单
    - 白名单：微步官方认证的合法域名，永久有效
    - 安全域名：本次查询未发现异常，但有有效期（30 天），过期后需重新查询
    """

    # 安全域名缓存有效期（30 天）
    SAFE_DOMAIN_TTL_DAYS = 30

    def __init__(self,
                 whitelist_file: Optional[str] = None,
                 safe_cache_file: Optional[str] = None,
                 domain_classifier_threshold: float = 0.85):
        self.client = ThreatBookClient()
        self._query_count = 0
        self._cache_hits = 0

        # ML-based domain classifier (replaces regex rules)
        # Uses a high threshold (0.85) to minimize false positives
        self._domain_classifier = DomainClassifier()
        self._classifier_threshold = domain_classifier_threshold

        # 两份不同的名单
        self._whitelist: dict[str, dict] = {}  # 白名单（永久）
        self._safe_cache: dict[str, dict] = {}  # 安全缓存（30 天过期）

        # 获取项目根目录（当前文件在 src/engines/，向上3级到项目根）
        project_root = Path(__file__).resolve().parent.parent.parent

        # 设置默认文件路径（始终相对于项目根目录）
        self._whitelist_file = Path(whitelist_file) if whitelist_file else project_root / "data" / "sources" / "threatbook_whitelist.json"
        self._safe_cache_file = Path(safe_cache_file) if safe_cache_file else project_root / "data" / "sources" / "threatbook_safe_cache.json"

        # 加载本地数据
        self._load_whitelist()
        self._load_safe_cache()

    def _load_whitelist(self):
        """加载白名单文件（永久有效）"""
        if self._whitelist_file.exists():
            try:
                with open(self._whitelist_file, encoding="utf-8") as f:
                    self._whitelist = json.load(f)
                logger.info(f"加载白名单: {len(self._whitelist)} 个域名")
            except Exception as e:
                logger.warning(f"加载白名单失败: {e}")
                self._whitelist = {}

    def _save_whitelist(self):
        """保存白名单到本地文件"""
        if not self._whitelist:
            return

        try:
            self._whitelist_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._whitelist_file, "w", encoding="utf-8") as f:
                json.dump(self._whitelist, f, indent=2, ensure_ascii=False)
            logger.info(f"白名单已保存到 {self._whitelist_file} ({len(self._whitelist)} 个域名)")
        except Exception as e:
            logger.warning(f"保存白名单失败: {e}")

    def _load_safe_cache(self):
        """加载安全域名缓存（有过期机制）"""
        if self._safe_cache_file.exists():
            try:
                with open(self._safe_cache_file, encoding="utf-8") as f:
                    cache_data = json.load(f)

                # 清理过期缓存（超过 30 天）
                now = datetime.now()
                valid_cache = {}
                expired_count = 0
                for domain, info in cache_data.items():
                    cached_time = datetime.fromisoformat(info.get("cached_at", ""))
                    if (now - cached_time).days < self.SAFE_DOMAIN_TTL_DAYS:
                        valid_cache[domain] = info
                    else:
                        expired_count += 1

                self._safe_cache = valid_cache
                if expired_count > 0:
                    logger.info(f"清理了 {expired_count} 个过期的安全域名缓存")
                logger.info(f"加载安全域名缓存: {len(self._safe_cache)} 个域名")
            except Exception as e:
                logger.warning(f"加载安全缓存失败: {e}")
                self._safe_cache = {}

    def _save_safe_cache(self):
        """保存安全域名缓存到本地文件"""
        if not self._safe_cache:
            return

        try:
            self._safe_cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._safe_cache_file, "w", encoding="utf-8") as f:
                json.dump(self._safe_cache, f, indent=2, ensure_ascii=False)
            logger.info(f"安全域名缓存已保存到 {self._safe_cache_file} ({len(self._safe_cache)} 个域名)")
        except Exception as e:
            logger.warning(f"保存安全缓存失败: {e}")

    def detect_threats(self, df: pd.DataFrame, suspicious_domains: Optional[list[str]] = None) -> list[DetectionResult]:
        """
        检测网络流中的威胁域名

        Args:
            df: 网络流 DataFrame
            suspicious_domains: 可选，外部传入的可疑域名列表（如 ML 检测结果）

        Returns:
            威胁检测结果列表
        """
        if "requested_server_name" not in df.columns and not suspicious_domains:
            return []

        dns_flows = df[df["application_name"] == "DNS"] if "application_name" in df.columns else df
        if dns_flows.empty and not suspicious_domains:
            return []

        results = []
        checked_domains = set()
        whitelist_added = 0
        safe_cached = 0

        # 确定要检查的域名集合
        domains_to_check = set()
        if suspicious_domains:
            domains_to_check.update(d.lower().rstrip(".") for d in suspicious_domains)
        if not dns_flows.empty:
            domains_to_check.update(dns_flows["requested_server_name"].dropna().str.lower().str.rstrip(".").unique())

        for domain in domains_to_check:
            domain_lower = domain.lower().rstrip(".")

            # 跳过已检查的域名
            if domain_lower in checked_domains:
                continue
            checked_domains.add(domain_lower)

            # 第一步：本地可疑度检查
            if not self._is_suspicious_domain(domain_lower):
                continue

            # 第二步：检查白名单和安全缓存
            cached_result, from_cache = self._check_cache(domain_lower)
            if from_cache:
                # 缓存命中，不消耗 API 额度
                if cached_result.get("is_whitelist"):
                    # 白名单域名，直接跳过
                    whitelist_added += 1
                    continue
                elif cached_result.get("is_safe"):
                    # 安全域名缓存，跳过
                    safe_cached += 1
                    continue
                elif cached_result.get("is_malicious") or cached_result.get("is_suspicious"):
                    # 之前标记为威胁的域名，重新生成告警
                    count = int(len(dns_flows[dns_flows["requested_server_name"].str.lower().str.rstrip(".") == domain_lower]))
                    src_ips = dns_flows[dns_flows["requested_server_name"].str.lower().str.rstrip(".") == domain_lower]["src_ip"].dropna().unique()

                    severity = Severity.HIGH if cached_result.get("is_malicious") else Severity.MEDIUM
                    results.append(DetectionResult(
                        engine_name="smart_threat_detector",
                        engine_version="3.0.0",
                        threat_type=ThreatType.PHISHING,
                        severity=severity,
                        description=f"[缓存] 微步在线情报: {domain} (严重: {cached_result.get('severity', 'unknown')}, 判断: {', '.join(cached_result.get('judgments', [])[:3])})",
                        evidence={
                            "domain": domain,
                            "severity": cached_result.get("severity"),
                            "judgments": cached_result.get("judgments", []),
                            "tags_classes": cached_result.get("tags_classes", []),
                            "confidence_level": cached_result.get("confidence_level"),
                            "query_count": count,
                            "source_ips": list(src_ips[:10]),
                            "from_cache": True,
                        },
                        confidence=0.9,
                        ioc=[domain],
                        recommended_action="建议：该域名被微步在线标记为威胁，建议立即隔离相关主机并进行取证分析。"
                    ))
                    continue

            # 第三步：查询微步 API
            threat_info = self._query_api(domain_lower)
            if not threat_info:
                continue

            # 第四步：根据返回结果分类处理
            judgments = threat_info.get("judgments", [])
            is_whitelist = "Whitelist" in judgments
            is_malicious = threat_info.get("is_malicious", False)
            is_suspicious = threat_info.get("is_suspicious", False)
            is_safe = not is_malicious and not is_suspicious

            if is_whitelist:
                # ✅ 加入白名单（永久保存）
                self._whitelist[domain_lower] = {
                    **threat_info,
                    "is_whitelist": True,
                    "is_safe": False,
                    "cached_at": datetime.now().isoformat(),
                }
                whitelist_added += 1
                logger.debug(f"白名单域名: {domain_lower}")

            elif is_safe:
                # 🔒 加入安全缓存（30 天过期）
                self._safe_cache[domain_lower] = {
                    **threat_info,
                    "is_whitelist": False,
                    "is_safe": True,
                    "cached_at": datetime.now().isoformat(),
                }
                safe_cached += 1
                logger.debug(f"安全域名: {domain_lower}")

            elif is_malicious or is_suspicious:
                # 🔴 生成告警
                count = int(len(dns_flows[dns_flows["requested_server_name"].str.lower().str.rstrip(".") == domain_lower]))
                src_ips = dns_flows[dns_flows["requested_server_name"].str.lower().str.rstrip(".") == domain_lower]["src_ip"].dropna().unique()

                severity = Severity.HIGH if is_malicious else Severity.MEDIUM
                results.append(DetectionResult(
                    engine_name="smart_threat_detector",
                    engine_version="3.0.0",
                    threat_type=ThreatType.PHISHING,
                    severity=severity,
                    description=f"[API] 微步在线情报: {domain} (严重: {threat_info.get('severity', 'unknown')}, 判断: {', '.join(judgments[:3])})",
                    evidence={
                        "domain": domain,
                        "severity": threat_info.get("severity"),
                        "judgments": judgments,
                        "tags_classes": threat_info.get("tags_classes", []),
                        "confidence_level": threat_info.get("confidence_level"),
                        "query_count": count,
                        "source_ips": list(src_ips[:10]),
                        "from_cache": False,
                    },
                    confidence=0.95 if is_malicious else 0.7,
                    ioc=[domain],
                    recommended_action="建议：该域名被微步在线标记为威胁，建议立即隔离相关主机并进行取证分析。"
                ))

        # 保存两份名单
        self._save_whitelist()
        self._save_safe_cache()

        # 输出统计
        cache_tag = f"(缓存命中 {self._cache_hits} 次)" if self._cache_hits > 0 else ""
        logger.info(
            f"SmartThreatDetector: 筛选 {len(checked_domains)} 个域名, "
            f"API 查询 {self._query_count} 次 {cache_tag}, "
            f"发现 {len(results)} 个威胁, "
            f"白名单 +{whitelist_added}, 安全缓存 +{safe_cached}"
        )
        return results

    def _is_suspicious_domain(self, domain: str) -> bool:
        """
        判断域名是否可疑，使用混合策略：
        1. 已知安全域名 → 直接放行
        2. 白名单/安全缓存 → 直接放行
        3. 规则检查（TLD、长度、连字符等）→ 快速判断
        4. ML 分类器辅助确认（高阈值，低误报）

        返回 True 表示域名可疑，应进一步查询微步 API。
        """
        # 第一层：已知安全域名快速过滤
        for safe_domain in _SAFE_DOMAIN_KEYWORDS:
            if domain == safe_domain or domain.endswith("." + safe_domain):
                return False

        # 第二层：白名单和安全缓存
        if domain in self._whitelist:
            return False

        if domain in self._safe_cache:
            cached = self._safe_cache[domain]
            cached_time = datetime.fromisoformat(cached.get("cached_at", ""))
            if (datetime.now() - cached_time).days < self.SAFE_DOMAIN_TTL_DAYS:
                return False

        # 第三层：规则检查（委托给 domain_classifier）
        rule_suspicious = self._domain_classifier._rule_based_check(domain)[0]

        # 第四层：ML 分类器辅助确认（仅当规则检查为可疑时）
        if rule_suspicious and self._domain_classifier.is_available:
            is_ml_suspicious, ml_prob = self._domain_classifier.is_suspicious(
                domain, threshold=self._classifier_threshold
            )
            logger.debug(f"Domain '{domain}': rule=suspicious, ML score={ml_prob:.3f}, ML suspicious={is_ml_suspicious}")
            # ML 确认可疑 → 查询 API
            # ML 确认安全但规则认为可疑 → 仍然查询 API（保守策略，避免漏报）
            return True

        return rule_suspicious

    def _check_cache(self, domain: str) -> tuple[Optional[dict], bool]:
        """
        检查白名单和安全缓存

        Returns:
            (威胁情报字典，是否来自缓存)
        """
        # 检查白名单（永久有效）
        if domain in self._whitelist:
            self._cache_hits += 1
            return self._whitelist[domain], True

        # 检查安全缓存（30 天过期）
        if domain in self._safe_cache:
            cached = self._safe_cache[domain]
            cached_time = datetime.fromisoformat(cached.get("cached_at", ""))
            if (datetime.now() - cached_time).days < self.SAFE_DOMAIN_TTL_DAYS:
                self._cache_hits += 1
                return cached, True

        return None, False

    def _query_api(self, domain: str) -> Optional[dict]:
        """
        查询微步 API

        Returns:
            威胁情报字典，或 None（如果查询失败）
        """
        result = self.client.check_domain(domain)
        if result:
            self._query_count += 1
        return result

    def get_stats(self) -> dict:
        """获取检测统计"""
        return {
            "whitelist_size": len(self._whitelist),
            "safe_cache_size": len(self._safe_cache),
            "api_queries": self._query_count,
            "cache_hits": self._cache_hits,
        }

    def get_whitelist(self) -> list[str]:
        """获取白名单域名列表"""
        return list(self._whitelist.keys())

    def get_safe_domains(self) -> list[dict]:
        """获取安全域名列表（含过期时间）"""
        now = datetime.now()
        safe_domains = []
        for domain, info in self._safe_cache.items():
            cached_time = datetime.fromisoformat(info.get("cached_at", ""))
            expires_at = cached_time + timedelta(days=self.SAFE_DOMAIN_TTL_DAYS)
            days_left = (expires_at - now).days
            if days_left > 0:
                safe_domains.append({
                    "domain": domain,
                    "expires_at": expires_at.isoformat(),
                    "days_left": days_left,
                    "severity": info.get("severity"),
                    "judgments": info.get("judgments", []),
                })
        return safe_domains

    def close(self):
        """关闭客户端"""
        self.client.close()
        self._save_whitelist()
        self._save_safe_cache()
