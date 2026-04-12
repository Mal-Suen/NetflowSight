"""
Behavioral Anomaly Detection Engine
"""
from __future__ import annotations
import logging
import re
import time
from typing import Any, Optional
import pandas as pd
from plugins.interfaces import DetectionEngine, DetectionResult, Severity, ThreatType

logger = logging.getLogger(__name__)

class BehavioralAnomalyDetector:
    name = "behavioral_anomaly_detector"
    version = "2.0.0"
    description = "行为异常检测引擎"
    enabled = True

    PRIVATE_IP_PATTERN = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)")
    SAFE_PREFIXES = ["8.8.", "1.1.", "52.", "54.", "13.", "104.", "172.217."]

    def run(self, df: pd.DataFrame, context: Optional[dict] = None) -> list[DetectionResult]:
        results = []
        results.extend(self._detect_large_transfers(df))
        results.extend(self._detect_suspicious_comm(df))
        results.extend(self._detect_port_scan(df))
        return results

    def _detect_large_transfers(self, df: pd.DataFrame) -> list[DetectionResult]:
        results = []
        large = df[df["bidirectional_bytes"] > 10 * 1024 * 1024]
        for _, r in large.iterrows():
            results.append(DetectionResult(
                engine_name=self.name, engine_version="2.0.0",
                threat_type=ThreatType.LARGE_DATA_TRANSFER, severity=Severity.MEDIUM,
                description=f"检测到大数据传输: 总量达 {r['bidirectional_bytes'] / 1e6:.2f} MB",
                evidence={"bytes": int(r['bidirectional_bytes']), "src": r['src_ip'], "dst": r['dst_ip']},
                confidence=0.5, ioc=[r['dst_ip']],
                recommended_action="建议：核实该传输是否符合业务预期。"
            ))
        return results

    def _detect_suspicious_comm(self, df: pd.DataFrame) -> list[DetectionResult]:
        results = []
        mask = df["src_ip"].str.match(self.PRIVATE_IP_PATTERN, na=False) & ~df["dst_ip"].str.match(self.PRIVATE_IP_PATTERN, na=False)
        for _, r in df[mask].iterrows():
            dst = str(r["dst_ip"])
            if not any(dst.startswith(p) for p in self.SAFE_PREFIXES) and int(r["bidirectional_packets"]) > 50:
                results.append(DetectionResult(
                    engine_name=self.name, engine_version="2.0.0",
                    threat_type=ThreatType.SUSPICIOUS_COMMUNICATION, severity=Severity.MEDIUM,
                    description=f"检测到可疑的内外网通信: 内网 {r['src_ip']} 向未知外网 {dst} 发送了 {int(r['bidirectional_packets'])} 个包",
                    evidence={"src": r['src_ip'], "dst": dst, "packets": int(r['bidirectional_packets'])},
                    confidence=0.55, ioc=[dst],
                    recommended_action="建议：排查该内网主机是否感染木马并正在与 C2 服务器通信。"
                ))
        return results

    def _detect_port_scan(self, df: pd.DataFrame) -> list[DetectionResult]:
        results = []
        stats = df.groupby("src_ip").agg(
            u_ports=("dst_port", "nunique"),
            u_ips=("dst_ip", "nunique"),
            pkts=("bidirectional_packets", "sum")
        )
        scanners = stats[(stats["u_ports"] > 50) & (stats["u_ips"] < 5)]
        for src, s in scanners.iterrows():
            results.append(DetectionResult(
                engine_name=self.name, engine_version="2.0.0",
                threat_type=ThreatType.PORT_SCAN, severity=Severity.HIGH,
                description=f"检测到端口扫描行为: {src} 对 {int(s['u_ips'])} 个目标扫描了 {int(s['u_ports'])} 个端口",
                evidence={"src": src, "ports": int(s['u_ports']), "targets": int(s['u_ips'])},
                confidence=0.8, ioc=[src], mitre_technique="T1046",
                recommended_action="建议：这是典型的攻击者侦察行为，建议立即封禁源 IP。"
            ))
        return results

    def get_config(self): return {}
    def set_config(self, c): pass
    def health_check(self): return {"status": "healthy"}