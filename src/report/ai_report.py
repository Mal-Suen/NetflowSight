"""
AI-Assisted Analysis Report Generator

Generates a comprehensive JSON report specifically designed for
AI-assisted threat analysis. Includes full context, evidence,
and suggested prompts for AI reasoning.
"""

import json
import time
import logging
import re
from pathlib import Path
from datetime import datetime
from typing import Optional

import pandas as pd
import ipaddress

logger = logging.getLogger(__name__)

# 编译正则表达式，提升性能
_PRIVATE_IP_REGEX = re.compile(
    r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)"
)


class AIAnalysisReport:
    """
    Generates AI-friendly analysis reports.
    
    Unlike human reports (which focus on summaries), this report includes:
    - Full context about the PCAP and environment
    - Detailed evidence for each finding
    - Raw flow data for top threats
    - Detection methodology and confidence levels
    - Suggested prompts for AI reasoning
    """
    
    def __init__(
        self,
        pcap_file: str,
        df: pd.DataFrame,
        dns_threats: list,
        http_threats: list,
        covert_threats: list,
        behavior_threats: list,
        ml_anomalies: dict,
        parse_time: float,
    ):
        self.pcap_file = Path(pcap_file)
        self.df = df
        self.dns_threats = dns_threats
        self.http_threats = http_threats
        self.covert_threats = covert_threats
        self.behavior_threats = behavior_threats
        self.ml_anomalies = ml_anomalies
        self.parse_time = parse_time
        self.all_threats = dns_threats + http_threats + covert_threats + behavior_threats
    
    def _serialize_threat(self, threat) -> dict:
        """Convert a ThreatFinding to a serializable dict."""
        return {
            "type": threat.threat_type.value,
            "severity": threat.severity.value,
            "description": threat.description,
            "evidence": threat.evidence,
            "recommended_action": getattr(threat, "recommended_action", ""),
            "flow_count": getattr(threat, "flow_count", 0),
        }
    
    def _build_context_section(self) -> dict:
        """Build network context section."""
        df = self.df

        # Identify internal IPs using ipaddress module (more accurate than regex)
        def is_private_ip(ip_str: str) -> bool:
            try:
                ip = ipaddress.ip_address(ip_str)
                return ip.is_private
            except (ValueError, TypeError):
                return False

        # Handle NaN values safely
        src_ips = df["src_ip"].dropna().unique()
        internal_ips = [ip for ip in src_ips if is_private_ip(str(ip))]

        # Identify time range
        if "bidirectional_first_seen_ms" in df.columns:
            first_ms = df["bidirectional_first_seen_ms"].min()
            last_ms = df["bidirectional_last_seen_ms"].max()
            duration_sec = (last_ms - first_ms) / 1000
        else:
            duration_sec = 0

        # Count external IPs safely
        dst_ips = df["dst_ip"].dropna().unique()
        external_ips = [ip for ip in dst_ips if not is_private_ip(str(ip))]

        return {
            "pcap_info": {
                "filename": self.pcap_file.name,
                "file_size_mb": round(self.pcap_file.stat().st_size / 1024 / 1024, 2) if self.pcap_file.exists() else 0,
                "parse_time_sec": round(self.parse_time, 2),
            },
            "traffic_summary": {
                "total_flows": len(df),
                "total_packets": int(df["bidirectional_packets"].sum()),
                "total_bytes": int(df["bidirectional_bytes"].sum()),
                "total_bytes_human": f"{df['bidirectional_bytes'].sum() / 1e6:.2f} MB",
                "internal_ips": [str(ip) for ip in internal_ips[:20]],
                "external_ip_count": len(external_ips),
                "duration_sec": round(duration_sec, 1),
                "avg_flow_bytes": round(df["bidirectional_bytes"].mean(), 0),
                "max_flow_bytes": int(df["bidirectional_bytes"].max()),
            },
            "protocol_distribution": df["application_name"].value_counts().head(30).to_dict(),
            "top_talkers": (
                df.groupby("src_ip")["bidirectional_bytes"]
                .sum()
                .nlargest(10)
                .to_dict()
            ),
            "top_destinations": (
                df.groupby("dst_ip")["bidirectional_bytes"]
                .sum()
                .nlargest(10)
                .to_dict()
            ),
        }
    
    def _build_threats_section(self) -> dict:
        """Build detailed threats section."""
        # Group threats by type
        threats_by_type = {}
        for t in self.all_threats:
            t_type = t.threat_type.value
            if t_type not in threats_by_type:
                threats_by_type[t_type] = []
            threats_by_type[t_type].append(self._serialize_threat(t))
        
        # Get raw flow data for top threats
        top_threat_flows = []
        if not self.all_threats:
            return {"total": 0, "by_type": {}, "top_threat_flows": []}

        # For each high severity threat, get the related flow details
        high_threats = [t for t in self.all_threats if t.severity.value in ["HIGH", "CRITICAL"]]
        for threat in high_threats[:10]:
            evidence = threat.evidence
            if "src_ip" in evidence and "dst_ip" in evidence:
                matching_flows = self.df[
                    (self.df["src_ip"] == evidence["src_ip"]) &
                    (self.df["dst_ip"] == evidence["dst_ip"])
                ]
                if not matching_flows.empty:
                    # Aggregate all matching flows instead of just taking the first one
                    flow_details = []
                    for _, flow_detail in matching_flows.iterrows():
                        flow_details.append({
                            "src_ip": str(flow_detail.get("src_ip", "")),
                            "dst_ip": str(flow_detail.get("dst_ip", "")),
                            "src_port": int(flow_detail.get("src_port", 0)),
                            "dst_port": int(flow_detail.get("dst_port", 0)),
                            "protocol": int(flow_detail.get("protocol", 0)),
                            "bidirectional_packets": int(flow_detail.get("bidirectional_packets", 0)),
                            "bidirectional_bytes": int(flow_detail.get("bidirectional_bytes", 0)),
                            "application_name": str(flow_detail.get("application_name", "Unknown")),
                            "duration_ms": float(flow_detail.get("bidirectional_duration_ms", 0)),
                            "src2dst_bytes": int(flow_detail.get("src2dst_bytes", 0)),
                            "dst2src_bytes": int(flow_detail.get("dst2src_bytes", 0)),
                        })
                    top_threat_flows.append({
                        "threat_type": threat.threat_type.value,
                        "threat_description": threat.description,
                        "flows": flow_details,
                        "flow_count": len(flow_details),
                    })
        
        return {
            "total": len(self.all_threats),
            "by_severity": {
                "CRITICAL": len([t for t in self.all_threats if t.severity.value == "CRITICAL"]),
                "HIGH": len([t for t in self.all_threats if t.severity.value == "HIGH"]),
                "MEDIUM": len([t for t in self.all_threats if t.severity.value == "MEDIUM"]),
                "LOW": len([t for t in self.all_threats if t.severity.value == "LOW"]),
            },
            "by_type": threats_by_type,
            "top_threat_flows": top_threat_flows,
        }
    
    def _build_ml_section(self) -> dict:
        """Build ML analysis section."""
        return {
            "algorithm": "Isolation Forest (unsupervised anomaly detection)",
            "contamination_rate": 0.05,
            "anomalies_found": self.ml_anomalies.get("anomaly_count", 0),
            "anomaly_rate_pct": self.ml_anomalies.get("anomaly_rate", 0),
            "top_anomalies": self.ml_anomalies.get("top_anomalies", [])[:10],
        }
    
    def _build_suggested_prompts(self) -> list[str]:
        """Generate suggested prompts for AI analysis."""
        threat_types = set(t.threat_type.value for t in self.all_threats)
        prompts = []
        
        prompts.append(
            "基于以下网络流量分析结果，请评估整体安全态势，"
            "指出最需要关注的威胁，并给出优先级排序的处置建议。"
        )
        
        if "DNS_TUNNEL" in threat_types or "DNS_EXFILTRATION" in threat_types:
            prompts.append(
                "检测到 DNS 隧道/数据外发迹象。请分析 DNS 流量模式，"
                "判断是否为真正的数据外泄，还是正常的 DNS 行为（如 DNS over HTTPS）。"
            )
        
        if "ICMP_TUNNEL" in threat_types:
            prompts.append(
                "检测到异常 ICMP 流量（大于正常 ping 的大小）。"
                "请分析这可能是网络管理工具、隧道工具还是误报。"
            )
        
        if "LARGE_DATA_TRANSFER" in threat_types:
            prompts.append(
                "检测到大流量传输。请结合目标 IP 和协议信息，"
                "判断这是否为合法的业务流量（如云存储同步、视频会议等）。"
            )
        
        if "PORT_SCAN" in threat_types:
            prompts.append(
                "检测到端口扫描行为。请评估这是内部安全扫描、"
                "攻击者侦察还是正常的网络发现协议。"
            )
        
        if "UNKNOWN_DOMAIN" in threat_types:
            prompts.append(
                "检测到多个未知域名。请分析这些域名的模式，"
                "判断是否为 DGA（域名生成算法）、内部服务还是正常的长尾域名。"
            )
        
        prompts.append(
            "如果需要进一步调查，建议获取哪些额外信息？"
            "（如完整 DNS 查询日志、TLS SNI、HTTP 请求内容等）"
        )
        
        return prompts
    
    def generate(self) -> dict:
        """Generate the complete AI analysis report."""
        report = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "NetflowSight v1.0.0",
                "report_type": "AI-Assisted Analysis",
                "version": "1.0",
            },
            "context": self._build_context_section(),
            "threats": self._build_threats_section(),
            "ml_analysis": self._build_ml_section(),
            "suggested_ai_prompts": self._build_suggested_prompts(),
            "ai_analysis_instructions": (
                "你是一位高级网络安全分析师。请基于以上报告内容，"
                "完成以下任务：\n"
                "1. 评估整体网络安全风险等级（低/中/高/严重）\n"
                "2. 列出 Top 5 最值得关注的威胁，说明为什么\n"
                "3. 区分误报和真实威胁\n"
                "4. 给出优先级排序的处置建议\n"
                "5. 识别可能的攻击链或关联威胁\n"
                "6. 建议进一步的调查方向\n"
                "\n"
                "请用中文回复，保持专业、简洁、可操作。"
            ),
        }
        
        return report
    
    def save(self, output_path: str) -> str:
        """Generate and save the report to a JSON file."""
        report = self.generate()
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str, ensure_ascii=False)
        
        logger.info(f"AI analysis report saved to: {output_file}")
        return str(output_file)
