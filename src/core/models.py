"""数据模型定义模块"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    """威胁严重程度等级"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatType(str, Enum):
    """威胁类型枚举（基于 MITRE ATT&CK 框架）"""
    # 初始访问
    WATERING_HOLE = "WATERING_HOLE"
    PHISHING = "PHISHING"
    PHISHING_DOMAIN = "PHISHING_DOMAIN"
    EXPLOITATION = "EXPLOITATION"
    # 命令与控制
    C2_BEACON = "C2_BEACON"
    C2_DATA_EXFIL = "C2_DATA_EXFIL"
    DNS_TUNNEL = "DNS_TUNNEL"
    ICMP_TUNNEL = "ICMP_TUNNEL"
    UNCOMMON_PORT = "UNCOMMON_PORT"
    UNKNOWN_TLS = "UNKNOWN_TLS"
    UNUSUAL_PORT = "UNUSUAL_PORT"
    # 发现
    PORT_SCAN = "PORT_SCAN"
    NETWORK_SCAN = "NETWORK_SCAN"
    # 数据外泄
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    DNS_EXFILTRATION = "DNS_EXFILTRATION"
    HTTP_EXFILTRATION = "HTTP_EXFILTRATION"
    # 信誉
    MALICIOUS_IP = "MALICIOUS_IP"
    MALICIOUS_DOMAIN = "MALICIOUS_DOMAIN"
    DGA_DOMAIN = "DGA_DOMAIN"
    UNKNOWN_DOMAIN = "UNKNOWN_DOMAIN"
    # 异常
    SUSPICIOUS_USER_AGENT = "SUSPICIOUS_USER_AGENT"
    HTTP_POST_ANOMALY = "HTTP_POST_ANOMALY"
    LARGE_DATA_TRANSFER = "LARGE_DATA_TRANSFER"
    SUSPICIOUS_COMMUNICATION = "SUSPICIOUS_COMMUNICATION"
    BEHAVIORAL_ANOMALY = "BEHAVIORAL_ANOMALY"
    ML_ANOMALY = "ML_ANOMALY"
    ONE_WAY_EXFILTRATION = "ONE_WAY_EXFILTRATION"


@dataclass
class FlowRecord:
    """网络流记录（五元组）"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # 6=TCP, 17=UDP, 1=ICMP
    application_name: Optional[str] = None
    bidirectional_packets: int = 0
    bidirectional_bytes: int = 0
    src2dst_packets: int = 0
    src2dst_bytes: int = 0
    dst2src_packets: int = 0
    dst2src_bytes: int = 0
    bidirectional_duration_ms: float = 0.0
    anomaly_score: float = 0.0
    raw_data: Optional[dict] = None


@dataclass
class ThreatFinding:
    """威胁检测结果"""
    threat_type: ThreatType
    severity: Severity
    description: str
    evidence: dict = field(default_factory=dict)
    recommendation: str = ""
    affected_ips: list = field(default_factory=list)
    flow_count: int = 0


@dataclass
class ThreatAlert:
    """威胁告警结果（插件检测输出）"""
    threat_type: ThreatType
    severity: Severity
    description: str
    evidence: dict = field(default_factory=dict)
    confidence: float = 0.0
    ioc: list = field(default_factory=list)
    mitre_technique: str = ""
    recommended_action: str = ""


@dataclass
class IPReputation:
    """IP 信誉信息（来自 AbuseIPDB）"""
    ip: str
    abuse_score: int = 0  # 0-100，越高越可疑
    country_code: Optional[str] = None
    usage_type: Optional[str] = None
    isp: Optional[str] = None
    domain: Optional[str] = None
    is_tor: bool = False
    is_public: bool = True
    reports_count: int = 0


@dataclass
class AnalysisResult:
    """完整分析结果"""
    # 流量摘要
    total_flows: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    protocol_distribution: dict = field(default_factory=dict)
    time_range: Optional[dict] = None

    # 威胁检测结果
    threats: list[ThreatFinding] = field(default_factory=list)
    high_severity_count: int = 0
    medium_severity_count: int = 0
    low_severity_count: int = 0

    # ML 异常检测
    ml_predictions: Optional[dict] = None
    anomaly_count: int = 0

    # 威胁情报
    ip_reputations: list[IPReputation] = field(default_factory=list)
    malicious_ips: list = field(default_factory=list)

    # AI 报告
    ai_report: Optional[str] = None

    # 元数据
    pcap_file: str = ""
    analysis_timestamp: str = ""
    processing_time_ms: float = 0.0
    cost_estimate: dict = field(default_factory=lambda: {"local": "$0", "ai_tokens": 0})

    def get_threats_by_severity(self, severity: Severity) -> list[ThreatFinding]:
        """按严重程度筛选威胁"""
        return [t for t in self.threats if t.severity == severity]

    def get_threats_by_type(self, threat_type: ThreatType) -> list[ThreatFinding]:
        """按威胁类型筛选威胁"""
        return [t for t in self.threats if t.threat_type == threat_type]

    def to_dict(self) -> dict[str, Any]:
        """转换为字典格式，用于 JSON 序列化"""
        return {
            "summary": {
                "total_flows": self.total_flows,
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "unique_src_ips": self.unique_src_ips,
                "unique_dst_ips": self.unique_dst_ips,
                "protocol_distribution": self.protocol_distribution,
                "time_range": self.time_range,
            },
            "threats": {
                "total": len(self.threats),
                "high": self.high_severity_count,
                "medium": self.medium_severity_count,
                "low": self.low_severity_count,
                "findings": [
                    {
                        "type": t.threat_type.value,
                        "severity": t.severity.value,
                        "description": t.description,
                        "evidence": t.evidence,
                        "recommendation": getattr(t, 'recommended_action', None) or getattr(t, 'recommendation', ''),
                    }
                    for t in self.threats[:100]
                ],
            },
            "ml_analysis": self.ml_predictions,
            "threat_intelligence": {"malicious_ips": self.malicious_ips[:50]},
            "ai_report": self.ai_report,
            "metadata": {
                "pcap_file": self.pcap_file,
                "analysis_timestamp": self.analysis_timestamp,
                "processing_time_ms": self.processing_time_ms,
                "cost_estimate": self.cost_estimate,
            },
        }
