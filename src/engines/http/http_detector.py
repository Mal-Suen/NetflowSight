"""
HTTP/HTTPS Threat Detection Engine
"""
from __future__ import annotations
import logging
import time
from typing import Any, Optional
import pandas as pd
from plugins.interfaces import DetectionEngine, DetectionResult, Severity, ThreatType

logger = logging.getLogger(__name__)

class HTTPThreatDetector:
    name = "http_threat_detector"
    version = "2.0.0"
    description = "HTTP 威胁检测引擎"
    enabled = True

    SUSPICIOUS_UA = ["python-requests", "curl", "wget", "powershell", "go-http-client", "java/", "nikto", "sqlmap", "nmap"]

    def run(self, df: pd.DataFrame, context: Optional[dict] = None) -> list[DetectionResult]:
        results = []
        results.extend(self._detect_anomaly(df))
        results.extend(self._detect_ports(df))
        results.extend(self._detect_ua(df))
        return results

    def _detect_anomaly(self, df: pd.DataFrame) -> list[DetectionResult]:
        results = []
        http = df[df["application_name"].isin(["HTTP", "HTTPS", "TLS"])]
        if http.empty: return results
        
        for _, r in http.iterrows():
            s, d = r.get("src2dst_bytes", 0), r.get("dst2src_bytes", 0)
            if s > 0 and d > s * 10 and d > 1_000_000:
                results.append(DetectionResult(
                    engine_name=self.name, engine_version="2.0.0",
                    threat_type=ThreatType.HTTP_EXFILTRATION, severity=Severity.MEDIUM,
                    description=f"检测到 HTTP 响应异常: 响应流量是请求流量的 {d/s:.1f} 倍 (目标: {r.get('dst_ip')}:{r.get('dst_port')})",
                    evidence={"src_ip": r.get("src_ip"), "dst_ip": r.get("dst_ip"), "ratio": d/s},
                    confidence=0.5, ioc=[r.get("dst_ip")],
                    recommended_action="建议：排查是否存在非预期的数据下载或隐蔽数据回传行为。"
                ))
        return results

    def _detect_ports(self, df: pd.DataFrame) -> list[DetectionResult]:
        results = []
        # 扩充常见端口：包含 DNS(53), NetBIOS(137/138/139), Kerberos(88), LDAP(389), SMB(445) 等
        common = {
            20, 21, 22, 23, 25, 53, 67, 68, 80, 88, 110, 123, 137, 138, 139, 143, 
            389, 443, 445, 465, 514, 587, 636, 993, 995, 1433, 3306, 3389, 5432, 
            8080, 8443, 3000, 5000, 8000, 9090
        }
        unusual = df[~df["dst_port"].isin(common)]
        if unusual.empty: return results
        
        counts = unusual["dst_port"].value_counts()
        for port, count in counts.items():
            if count > 10:
                results.append(DetectionResult(
                    engine_name=self.name, engine_version="2.0.0",
                    threat_type=ThreatType.UNCOMMON_PORT, severity=Severity.MEDIUM,
                    description=f"检测到非常用端口通信: 端口 {port} 发生了 {int(count)} 次连接",
                    evidence={"port": port, "count": int(count)},
                    confidence=0.6, ioc=[],
                    recommended_action="建议：核实该端口上运行的服务，排除恶意后门或隧道工具。"
                ))
        return results

    def _detect_ua(self, df: pd.DataFrame) -> list[DetectionResult]:
        results = []
        if "user_agent" not in df.columns: return results
        
        for _, r in df[df["user_agent"].notna()].iterrows():
            ua = str(r["user_agent"]).lower()
            hits = [p for p in self.SUSPICIOUS_UA if p in ua]
            if hits:
                results.append(DetectionResult(
                    engine_name=self.name, engine_version="2.0.0",
                    threat_type=ThreatType.SUSPICIOUS_USER_AGENT, severity=Severity.MEDIUM,
                    description=f"检测到可疑 User-Agent: {str(r['user_agent'])[:50]}",
                    evidence={"ua": r["user_agent"], "hits": hits},
                    confidence=0.65, ioc=[],
                    recommended_action="建议：该 UA 特征通常被自动化攻击脚本或扫描工具使用，需关注源 IP 行为。"
                ))
        return results

    def get_config(self): return {}
    def set_config(self, c): pass
    def health_check(self): return {"status": "healthy"}