"""
Data models for NetflowSight analysis results
"""

from dataclasses import dataclass, field
from typing import Any, Optional
from enum import Enum


class Severity(str, Enum):
    """Threat severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatType(str, Enum):
    """Types of detected threats."""
    UNKNOWN_DOMAIN = "UNKNOWN_DOMAIN"
    DNS_TUNNEL = "DNS_TUNNEL"
    PHISHING_DOMAIN = "PHISHING_DOMAIN"
    HTTP_POST_ANOMALY = "HTTP_POST_ANOMALY"
    UNUSUAL_PORT = "UNUSUAL_PORT"
    SUSPICIOUS_USER_AGENT = "SUSPICIOUS_USER_AGENT"
    ICMP_TUNNEL = "ICMP_TUNNEL"
    DNS_EXFILTRATION = "DNS_EXFILTRATION"
    UNKNOWN_TLS = "UNKNOWN_TLS"
    ONE_WAY_EXFILTRATION = "ONE_WAY_EXFILTRATION"
    LARGE_DATA_TRANSFER = "LARGE_DATA_TRANSFER"
    SUSPICIOUS_COMMUNICATION = "SUSPICIOUS_COMMUNICATION"
    PORT_SCAN = "PORT_SCAN"
    MALICIOUS_IP = "MALICIOUS_IP"
    ML_ANOMALY = "ML_ANOMALY"


@dataclass
class FlowRecord:
    """Represents a single network flow record."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
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
    """Represents a single threat detection finding."""
    threat_type: ThreatType
    severity: Severity
    description: str
    evidence: dict = field(default_factory=dict)
    recommendation: str = ""
    affected_ips: list = field(default_factory=list)
    flow_count: int = 0


@dataclass
class IPReputation:
    """IP reputation information from threat intelligence."""
    ip: str
    abuse_score: int = 0
    country_code: Optional[str] = None
    usage_type: Optional[str] = None
    isp: Optional[str] = None
    domain: Optional[str] = None
    is_tor: bool = False
    is_public: bool = True
    reports_count: int = 0


@dataclass
class AnalysisResult:
    """Complete analysis result for a PCAP file."""
    # Summary
    total_flows: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    protocol_distribution: dict = field(default_factory=dict)
    time_range: Optional[dict] = None
    
    # Threat detection
    threats: list[ThreatFinding] = field(default_factory=list)
    high_severity_count: int = 0
    medium_severity_count: int = 0
    low_severity_count: int = 0
    
    # ML analysis
    ml_predictions: Optional[dict] = None
    anomaly_count: int = 0
    
    # Threat intelligence
    ip_reputations: list[IPReputation] = field(default_factory=list)
    malicious_ips: list = field(default_factory=list)
    
    # AI report
    ai_report: Optional[str] = None
    
    # Metadata
    pcap_file: str = ""
    analysis_timestamp: str = ""
    processing_time_ms: float = 0.0
    cost_estimate: dict = field(default_factory=lambda: {"local": "$0", "ai_tokens": 0})
    
    def get_threats_by_severity(self, severity: Severity) -> list[ThreatFinding]:
        """Get threats filtered by severity."""
        return [t for t in self.threats if t.severity == severity]
    
    def get_threats_by_type(self, threat_type: ThreatType) -> list[ThreatFinding]:
        """Get threats filtered by type."""
        return [t for t in self.threats if t.threat_type == threat_type]
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
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
                        "recommendation": t.recommendation,
                    }
                    for t in self.threats[:100]  # Limit for serialization
                ],
            },
            "ml_analysis": self.ml_predictions,
            "threat_intelligence": {
                "malicious_ips": self.malicious_ips[:50],
            },
            "ai_report": self.ai_report,
            "metadata": {
                "pcap_file": self.pcap_file,
                "analysis_timestamp": self.analysis_timestamp,
                "processing_time_ms": self.processing_time_ms,
                "cost_estimate": self.cost_estimate,
            },
        }
