"""
Covert Channel Detection Engine
"""
from __future__ import annotations

import logging

import pandas as pd

from core.interfaces import DetectionResult, Severity, ThreatType

logger = logging.getLogger(__name__)

class CovertChannelDetector:
    name = "covert_channel_detector"
    version = "2.0.0"
    description = "隐蔽通道检测引擎"
    enabled = True

    def run(self, df: pd.DataFrame, context: dict | None = None) -> list[DetectionResult]:
        results = []
        results.extend(self._detect_icmp(df))
        results.extend(self._detect_dns_exfil(df))
        results.extend(self._detect_unknown_tls(df))
        results.extend(self._detect_one_way(df))
        return results

    def _detect_icmp(self, df: pd.DataFrame) -> list[DetectionResult]:
        results = []
        icmp = df[df["protocol"] == 1]
        if icmp.empty:
            return results

        for _, r in icmp[icmp["bidirectional_bytes"] > 1000].iterrows():
            results.append(DetectionResult(
                engine_name=self.name, engine_version="2.0.0",
                threat_type=ThreatType.ICMP_TUNNEL, severity=Severity.HIGH,
                description=f"检测到异常 ICMP 大流量: 共 {int(r['bidirectional_bytes'])} 字节 (源: {r['src_ip']}, 目标: {r['dst_ip']})",
                evidence={"bytes": int(r['bidirectional_bytes']), "src": r['src_ip'], "dst": r['dst_ip']},
                confidence=0.7, ioc=[r['dst_ip']],
                recommended_action="建议：标准的 Ping 包很小，大流量通常意味着封装了其他协议 (ICMP 隧道)。"
            ))
        return results

    def _detect_dns_exfil(self, df: pd.DataFrame) -> list[DetectionResult]:
        results = []
        dns = df[df["application_name"] == "DNS"]
        if dns.empty:
            return results

        for _, r in dns[dns["bidirectional_bytes"] > 500].iterrows():
            results.append(DetectionResult(
                engine_name=self.name, engine_version="2.0.0",
                threat_type=ThreatType.DNS_EXFILTRATION, severity=Severity.HIGH,
                description=f"检测到 DNS 流量过大: 共 {int(r['bidirectional_bytes'])} 字节",
                evidence={"bytes": int(r['bidirectional_bytes']), "dst": r['dst_ip']},
                confidence=0.65, ioc=[r['dst_ip']],
                recommended_action="建议：正常 DNS 查询很小，大流量可能用于隐蔽数据外发 (DNS Exfiltration)。"
            ))
        return results

    def _detect_unknown_tls(self, df: pd.DataFrame) -> list[DetectionResult]:
        results = []
        if "application_name" not in df.columns:
            return results
        tls = df[df["application_name"] == "TLS"]
        if tls.empty:
            return results

        unknown = tls[tls.get("application_confidence", 100) < 50] if "application_confidence" in tls.columns else tls
        for ip, group in unknown.groupby("dst_ip"):
            if len(group) >= 5:
                results.append(DetectionResult(
                    engine_name=self.name, engine_version="2.0.0",
                    threat_type=ThreatType.UNKNOWN_TLS, severity=Severity.MEDIUM,
                    description=f"检测到未识别的 TLS 加密流量: 共 {len(group)} 条流向 {ip}",
                    evidence={"dst": ip, "flows": len(group)},
                    confidence=0.5, ioc=[ip],
                    recommended_action="建议：无法识别应用层协议，可能存在加密隧道或非标准应用通信。"
                ))
        return results

    def _detect_one_way(self, df: pd.DataFrame) -> list[DetectionResult]:
        results = []
        one_way = df[(df["src2dst_bytes"] > df["dst2src_bytes"] * 10) & (df["src2dst_bytes"] > 1_000_000)]
        for _, r in one_way.iterrows():
            results.append(DetectionResult(
                engine_name=self.name, engine_version="2.0.0",
                threat_type=ThreatType.C2_DATA_EXFIL, severity=Severity.HIGH,
                description=f"检测到单向大数据传输: {r['src2dst_bytes'] / 1e6:.2f} MB 流向 {r['dst_ip']}",
                evidence={"dst": r['dst_ip'], "bytes": int(r['src2dst_bytes'])},
                confidence=0.7, ioc=[r['dst_ip']],
                recommended_action="建议：极不对称的流量比例通常是数据泄露或 C2 指令回传的典型特征。"
            ))
        return results

    def get_config(self):
        return {}

    def set_config(self, c):
        pass

    def health_check(self):
        return {"status": "healthy"}
