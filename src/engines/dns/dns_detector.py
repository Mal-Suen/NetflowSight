"""
DNS Threat Detection Engine

DNS 威胁检测策略：
1. 黑名单匹配：只检测已知的恶意域名（零误报）
2. ML 域名分类：基于 LightGBM 模型检测可疑域名
3. DNS 隧道检测：基于包数量的异常
4. DGA 域名检测：基于信息熵识别算法生成域名
"""
from __future__ import annotations
import logging
import math
from typing import Any, Optional
import pandas as pd
from plugins.interfaces import DetectionEngine, DetectionResult, Severity, ThreatType
from engines.domain_classifier import DomainClassifier

logger = logging.getLogger(__name__)

class DNSThreatDetector:
    name = "dns_threat_detector"
    version = "3.0.0"
    description = "DNS 威胁检测引擎（黑名单 + ML 分类器 + DGA + 隧道检测）"
    enabled = True

    def __init__(self, safe_domains: Optional[set[str]] = None, config: Optional[dict] = None):
        # 内置安全域名库（用于排除正常流量）
        default_safe = {
            "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
            "microsoft.com", "windows.com", "windows.net", "windowsupdate.com", "azure.com", "azureedge.net",
            "office.com", "office365.com", "microsoftonline.com", "sharepoint.com", "lync.com", "skype.com",
            "facebook.com", "fbcdn.net", "instagram.com",
            "amazonaws.com", "cloudfront.net", "awsstatic.com",
            "apple.com", "icloud.com", "mzstatic.com",
            "cloudflare.com", "akamai.net", "akamaiedge.net",
            "github.com", "githubusercontent.com",
            "twitter.com", "twimg.com", "x.com",
            "linkedin.com", "licdn.com",
            "whatsapp.com", "whatsapp.net",
            "tiktok.com", "tiktokv.com",
            "netflix.com", "nflxvideo.net",
        }
        self.safe_domains = safe_domains if safe_domains is not None else default_safe
        self.config = config or self._default_config()
        # Initialize ML Domain Classifier
        self.domain_classifier = DomainClassifier()

    @staticmethod
    def _default_config() -> dict[str, Any]:
        return {
            "dns_tunnel_threshold": 20,
            "dga_entropy_threshold": 3.5,
        }

    def run(self, df: pd.DataFrame, context: Optional[dict] = None,
            threat_domains: Optional[set[str]] = None) -> list[DetectionResult]:
        """
        运行 DNS 威胁检测。

        Args:
            df: 网络流 DataFrame
            context: 上下文信息（可包含 safe_domains）
            threat_domains: 威胁域名黑名单（来自威胁情报源）

        Returns:
            威胁检测结果列表
        """
        if context and "safe_domains" in context:
            self.safe_domains = context["safe_domains"]

        results = []

        # 1. 黑名单匹配（零误报策略）
        results.extend(self._detect_threat_domains(df, threat_domains))

        # 2. ML 域名分类检测（基于 LightGBM 模型）
        results.extend(self._detect_suspicious_domains_ml(df))

        # 3. DNS 隧道检测
        results.extend(self._detect_dns_tunnel(df))

        # 4. DGA 域名检测
        results.extend(self._detect_dga_domains(df))

        return results

    def _detect_threat_domains(self, df: pd.DataFrame,
                                threat_domains: Optional[set[str]] = None) -> list[DetectionResult]:
        """
        检测访问黑名单域名的行为。

        只报告访问已知恶意域名的流量，不会产生误报。
        """
        results = []
        if not threat_domains:
            return results

        if "requested_server_name" not in df.columns:
            return results

        dns_flows = df[df["application_name"] == "DNS"]
        if dns_flows.empty:
            return results

        # 将威胁域名转为小写集合用于快速匹配
        threat_set = {d.lower().rstrip(".") for d in threat_domains}

        for domain in dns_flows["requested_server_name"].dropna().unique():
            domain_lower = domain.lower().rstrip(".")

            # 精确匹配或子域名匹配
            is_threat = False
            matched_threat_domain = None
            for threat_domain in threat_set:
                if domain_lower == threat_domain or domain_lower.endswith("." + threat_domain):
                    is_threat = True
                    matched_threat_domain = threat_domain
                    break

            if is_threat:
                count = int(len(dns_flows[dns_flows["requested_server_name"] == domain]))
                src_ips = dns_flows[dns_flows["requested_server_name"] == domain]["src_ip"].dropna().unique()
                dst_ips = dns_flows[dns_flows["requested_server_name"] == domain]["dst_ip"].dropna().unique()

                results.append(DetectionResult(
                    engine_name=self.name, engine_version=self.version,
                    threat_type=ThreatType.PHISHING,
                    severity=Severity.HIGH,
                    description=f"检测到访问恶意域名: {domain} (匹配: {matched_threat_domain}, {count} 次查询)",
                    evidence={
                        "domain": domain,
                        "matched_threat_domain": matched_threat_domain,
                        "query_count": count,
                        "source_ips": list(src_ips[:10]),
                        "dns_servers": list(dst_ips[:5]),
                    },
                    confidence=0.9,
                    ioc=[domain, matched_threat_domain],
                    recommended_action="建议：立即隔离访问该域名的主机，进行恶意软件扫描和取证分析。"
                ))

        return results

    def _detect_suspicious_domains_ml(self, df: pd.DataFrame) -> list[DetectionResult]:
        """
        使用 ML 域名分类器检测可疑域名。
        替代旧的正则规则检测，提供基于概率的评分。
        """
        results = []
        if "requested_server_name" not in df.columns:
            return results

        dns_flows = df[df["application_name"] == "DNS"]
        if dns_flows.empty:
            return results

        # 获取所有唯一域名
        unique_domains = dns_flows["requested_server_name"].dropna().unique()
        if not unique_domains.size:
            return results

        # 批量预测
        predictions = self.domain_classifier.predict_batch(list(unique_domains), threshold=0.85)

        for domain, (is_suspicious, prob) in zip(unique_domains, predictions):
            if is_suspicious:
                count = int(len(dns_flows[dns_flows["requested_server_name"] == domain]))
                src_ips = dns_flows[dns_flows["requested_server_name"] == domain]["src_ip"].dropna().unique()

                # 根据概率设置严重程度
                severity = Severity.HIGH if prob > 0.95 else Severity.MEDIUM

                results.append(DetectionResult(
                    engine_name=self.name, engine_version=self.version,
                    threat_type=ThreatType.UNKNOWN_DOMAIN,
                    severity=severity,
                    description=f"ML 域名分类器检测到可疑域名: {domain} (恶意概率: {prob:.2%}, {count} 次查询)",
                    evidence={
                        "domain": domain,
                        "ml_score": prob,
                        "query_count": count,
                        "source_ips": list(src_ips[:10]),
                    },
                    confidence=prob,
                    ioc=[domain],
                    recommended_action="建议：该域名被 ML 模型判定为高度可疑，建议进一步分析其解析记录和相关流量。"
                ))

        return results

    def _detect_dns_tunnel(self, df: pd.DataFrame) -> list[DetectionResult]:
        """检测 DNS 隧道行为（基于向同一 DNS 服务器发送的包数量）。"""
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
                    description=f"检测到潜在的 DNS 隧道行为: 向 {ip} 发送了 {int(count)} 个包 (阈值: {self.config['dns_tunnel_threshold']})",
                    evidence={"dst_ip": ip, "packet_count": int(count)},
                    confidence=0.75, ioc=[ip], mitre_technique="T1071.004",
                    recommended_action="建议：检查 DNS 载荷大小和查询模式，确认是否存在隐蔽数据通道。"
                ))
        return results

    def _detect_dga_domains(self, df: pd.DataFrame) -> list[DetectionResult]:
        """检测 DGA（域名生成算法）特征域名（基于信息熵）。"""
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
                        description=f"检测到 DGA (域名生成算法) 特征域名: {domain} (熵值: {entropy:.2f})",
                        evidence={"domain": domain, "entropy": entropy},
                        confidence=0.8, ioc=[domain], mitre_technique="T1583.001",
                        recommended_action="建议：该域名可能由恶意软件动态生成，建议隔离相关主机并进行取证。"
                    ))
        return results

    def get_config(self): return self.config
    def set_config(self, config): self.config = config
    def health_check(self): return {"status": "healthy"}