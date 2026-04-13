"""Tests for core data models"""

import pytest
from core.models import Severity, ThreatType, IPReputation, ThreatFinding, AnalysisResult


class TestSeverity:
    def test_severity_values(self):
        assert Severity.LOW.value == "LOW"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.CRITICAL.value == "CRITICAL"

    def test_severity_is_string_enum(self):
        assert isinstance(Severity.LOW, str)
        assert Severity.LOW == "LOW"


class TestThreatType:
    def test_common_threat_types(self):
        assert ThreatType.UNKNOWN_DOMAIN.value == "UNKNOWN_DOMAIN"
        assert ThreatType.DNS_TUNNEL.value == "DNS_TUNNEL"
        assert ThreatType.PHISHING_DOMAIN.value == "PHISHING_DOMAIN"
        assert ThreatType.MALICIOUS_IP.value == "MALICIOUS_IP"
        assert ThreatType.ML_ANOMALY.value == "ML_ANOMALY"

    def test_mitre_attack_types(self):
        assert ThreatType.C2_BEACON.value == "C2_BEACON"
        assert ThreatType.DATA_EXFILTRATION.value == "DATA_EXFILTRATION"
        assert ThreatType.PORT_SCAN.value == "PORT_SCAN"

    def test_threat_type_is_string_enum(self):
        assert isinstance(ThreatType.MALICIOUS_IP, str)


class TestIPReputation:
    def test_default_values(self):
        rep = IPReputation(ip="1.2.3.4")
        assert rep.ip == "1.2.3.4"
        assert rep.abuse_score == 0
        assert rep.country_code is None
        assert rep.is_tor is False
        assert rep.is_public is True
        assert rep.reports_count == 0

    def test_full_construction(self):
        rep = IPReputation(ip="1.2.3.4", abuse_score=50, country_code="CN",
                           is_tor=True, is_public=False, reports_count=10)
        assert rep.abuse_score == 50
        assert rep.country_code == "CN"
        assert rep.is_tor is True
        assert rep.reports_count == 10


class TestThreatFinding:
    def test_default_values(self):
        finding = ThreatFinding(threat_type=ThreatType.MALICIOUS_IP, severity=Severity.HIGH,
                                description="Test finding")
        assert finding.threat_type == ThreatType.MALICIOUS_IP
        assert finding.severity == Severity.HIGH
        assert finding.description == "Test finding"
        assert finding.evidence == {}
        assert finding.recommendation == ""


class TestAnalysisResult:
    def test_empty_result(self):
        result = AnalysisResult()
        assert result.total_flows == 0
        assert result.threats == []
        assert result.high_severity_count == 0

    def test_to_dict(self):
        result = AnalysisResult(total_flows=100, total_packets=5000, total_bytes=1_000_000,
                                unique_src_ips=10, unique_dst_ips=20)
        d = result.to_dict()
        assert d["summary"]["total_flows"] == 100

    def test_get_threats_by_severity(self):
        result = AnalysisResult(threats=[
            ThreatFinding(threat_type=ThreatType.MALICIOUS_IP, severity=Severity.HIGH, description="High"),
            ThreatFinding(threat_type=ThreatType.UNKNOWN_DOMAIN, severity=Severity.LOW, description="Low"),
        ])
        assert len(result.get_threats_by_severity(Severity.HIGH)) == 1

    def test_get_threats_by_type(self):
        result = AnalysisResult(threats=[
            ThreatFinding(threat_type=ThreatType.DNS_TUNNEL, severity=Severity.HIGH, description="DNS"),
        ])
        assert len(result.get_threats_by_type(ThreatType.DNS_TUNNEL)) == 1
