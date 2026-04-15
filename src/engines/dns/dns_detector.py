"""DNS 威胁检测引擎 - 黑名单匹配 + ML 分类 + DGA + 隧道检测"""

from __future__ import annotations
import logging
import math
from typing import Any, Optional
import pandas as pd
from core.interfaces import DetectionEngine, DetectionResult, Severity, ThreatType
from ml.domain_classifier import DomainClassifier

logger = logging.getLogger(__name__)


class DNSThreatDetector:
    """DNS 威胁检测引擎"""

    name = "dns_threat_detector"
    version = "3.0.0"
    description = "DNS 威胁检测引擎"
    enabled = True

    def __init__(self, safe_domains: Optional[set[str]] = None, config: Optional[dict] = None):
        default_safe = {
            "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
            "microsoft.com", "windows.com", "azure.com", "apple.com", "icloud.com",
            "amazonaws.com", "cloudfront.net", "cloudflare.com", "github.com",
            "facebook.com", "fbcdn.net", "twitter.com", "linkedin.com",
        }
        self.safe_domains = safe_domains if safe_domains is not None else default_safe
        self.config = config or self._default_config()
        self.domain_classifier = DomainClassifier()

    @staticmethod
    def _default_config() -> dict[str, Any]:
        return {"dns_tunnel_threshold": 20, "dga_entropy_threshold": 3.5}

    def run(self, df: pd.DataFrame, context: Optional[dict] = None,
            threat_domains: Optional[set[str]] = None) -> list[DetectionResult]:
        """运行 DNS 威胁检测"""
        if context and "safe_domains" in context:
            self.safe_domains = context["safe_domains"]

        results = []
        results.extend(self._detect_threat_domains(df, threat_domains))
        results.extend(self._detect_suspicious_domains_ml(df))
        results.extend(self._detect_dns_tunnel(df))
        results.extend(self._detect_dga_domains(df))
        return results

    def _detect_threat_domains(self, df: pd.DataFrame, threat_domains: Optional[set[str]] = None) -> list[DetectionResult]:
        """检测访问黑名单域名"""
        results = []
        if not threat_domains or "requested_server_name" not in df.columns:
            return results

        dns_flows = df[df["application_name"] == "DNS"]
        if dns_flows.empty:
            return results

        threat_set = {d.lower().rstrip(".") for d in threat_domains}

        for domain in dns_flows["requested_server_name"].dropna().unique():
            domain_lower = domain.lower().rstrip(".")
            matched_threat = None
            for threat_domain in threat_set:
                if domain_lower == threat_domain or domain_lower.endswith("." + threat_domain):
                    matched_threat = threat_domain
                    break

            if matched_threat:
                count = int(len(dns_flows[dns_flows["requested_server_name"] == domain]))
                src_ips = dns_flows[dns_flows["requested_server_name"] == domain]["src_ip"].dropna().unique()
                results.append(DetectionResult(
                    engine_name=self.name, engine_version=self.version,
                    threat_type=ThreatType.PHISHING, severity=Severity.HIGH,
                    description=f"检测到访问恶意域名: {domain} (匹配: {matched_threat})",
                    evidence={"domain": domain, "matched_threat_domain": matched_threat, "query_count": count, "source_ips": list(src_ips[:10])},
                    confidence=0.9, ioc=[domain, matched_threat],
                    recommended_action="建议隔离访问该域名的主机"
                ))
        return results

    def _detect_suspicious_domains_ml(self, df: pd.DataFrame) -> list[DetectionResult]:
        """使用 ML 分类器检测可疑域名"""
        results = []
        if "requested_server_name" not in df.columns:
            return results

        dns_flows = df[df["application_name"] == "DNS"]
        if dns_flows.empty:
            return results

        unique_domains = dns_flows["requested_server_name"].dropna().unique()
        if not unique_domains.size:
            return results

        predictions = self.domain_classifier.predict_batch(list(unique_domains), threshold=0.85)

        for domain, (is_suspicious, prob) in zip(unique_domains, predictions):
            if is_suspicious:
                count = int(len(dns_flows[dns_flows["requested_server_name"] == domain]))
                src_ips = dns_flows[dns_flows["requested_server_name"] == domain]["src_ip"].dropna().unique()
                severity = Severity.HIGH if prob > 0.95 else Severity.MEDIUM
                results.append(DetectionResult(
                    engine_name=self.name, engine_version=self.version,
                    threat_type=ThreatType.UNKNOWN_DOMAIN, severity=severity,
                    description=f"ML 检测到可疑域名: {domain} (恶意概率: {prob:.2%})",
                    evidence={"domain": domain, "ml_score": prob, "query_count": count, "source_ips": list(src_ips[:10])},
                    confidence=prob, ioc=[domain],
                    recommended_action="建议进一步分析该域名"
                ))
        return results

    def _detect_dns_tunnel(self, df: pd.DataFrame) -> list[DetectionResult]:
        """检测 DNS 隧道行为"""
        results = []
        if "requested_server_name" not in df.columns:
            return results
        dns_flows = df[df["application_name"] == "DNS"]
        if dns_flows.empty:
            return results

        counts = dns_flows.groupby("dst_ip")["bidirectional_packets"].sum()
        for ip, count in counts.items():
            if count > self.config["dns_tunnel_threshold"]:
                results.append(DetectionResult(
                    engine_name=self.name, engine_version=self.version,
                    threat_type=ThreatType.DNS_TUNNEL, severity=Severity.HIGH,
                    description=f"检测到潜在 DNS 隧道: {ip} ({int(count)} 包)",
                    evidence={"dst_ip": ip, "packet_count": int(count)},
                    confidence=0.75, ioc=[ip], mitre_technique="T1071.004",
                    recommended_action="检查 DNS 载荷大小和查询模式"
                ))
        return results

    def _detect_dga_domains(self, df: pd.DataFrame) -> list[DetectionResult]:
        """检测 DGA 域名"""
        results = []
        if "requested_server_name" not in df.columns:
            return results
        dns_flows = df[df["application_name"] == "DNS"]
        if dns_flows.empty:
            return results

        for domain in dns_flows["requested_server_name"].dropna().unique():
            sld = domain.split(".")[-2] if len(domain.split(".")) >= 2 else ""
            if len(sld) > 10:
                entropy = -sum((sld.count(c)/len(sld)) * math.log2(sld.count(c)/len(sld)) for c in set(sld))
                if entropy > self.config["dga_entropy_threshold"]:
                    results.append(DetectionResult(
                        engine_name=self.name, engine_version=self.version,
                        threat_type=ThreatType.DGA_DOMAIN, severity=Severity.HIGH,
                        description=f"检测到 DGA 域名: {domain} (熵值: {entropy:.2f})",
                        evidence={"domain": domain, "entropy": entropy},
                        confidence=0.8, ioc=[domain], mitre_technique="T1583.001",
                        recommended_action="该域名可能由恶意软件生成"
                    ))
        return results

    def get_config(self): return self.config
    def set_config(self, config): self.config = config
    def health_check(self): return {"status": "healthy"}
