"""Tests for HTML report generator"""

import html
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from core.models import AnalysisResult, ThreatFinding
from report.html_generator import HTMLReportGenerator


@pytest.fixture
def sample_result():
    """创建示例分析结果"""
    return AnalysisResult(
        total_flows=1000,
        total_packets=50000,
        total_bytes=10_000_000,
        unique_src_ips=50,
        unique_dst_ips=100,
        protocol_distribution={"TCP": 600, "UDP": 300, "ICMP": 100},
        time_range={"start": "2024-01-01T00:00:00", "end": "2024-01-01T01:00:00"},
        threats=[
            ThreatFinding(
                threat_type="MALICIOUS_IP",
                severity="HIGH",
                description="检测到恶意 IP: 192.168.1.100",
                evidence={"ip": "192.168.1.100", "score": 95},
                recommendation="建议封禁该 IP",
            ),
            ThreatFinding(
                threat_type="DNS_TUNNEL",
                severity="MEDIUM",
                description="检测到 DNS 隧道行为",
                evidence={"domain": "suspicious.example.com"},
                recommendation="检查 DNS 查询模式",
            ),
        ],
        high_severity_count=1,
        medium_severity_count=1,
        low_severity_count=0,
        pcap_file="test.pcap",
        analysis_timestamp=datetime.now().isoformat(),
        processing_time_ms=1500.0,
    )


class TestHTMLReportGenerator:
    def test_generate_basic(self, sample_result):
        """测试基本 HTML 生成"""
        generator = HTMLReportGenerator(sample_result)
        html_output = generator.generate()
        
        assert "<!DOCTYPE html>" in html_output
        assert "NetflowSight" in html_output
        assert "test.pcap" in html_output
    
    def test_generate_with_output_path(self, sample_result):
        """测试生成并保存到文件"""
        generator = HTMLReportGenerator(sample_result)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "report.html"
            html_output = generator.generate(output_path=str(output_path))
            
            assert output_path.exists()
            assert len(html_output) > 0
    
    def test_html_contains_stats(self, sample_result):
        """测试 HTML 包含统计信息"""
        generator = HTMLReportGenerator(sample_result)
        html_output = generator.generate()
        
        assert "1,000" in html_output  # total_flows
        assert "50,000" in html_output  # total_packets
        assert "高危" in html_output
        assert "中危" in html_output
    
    def test_html_contains_threats(self, sample_result):
        """测试 HTML 包含威胁信息"""
        generator = HTMLReportGenerator(sample_result)
        html_output = generator.generate()
        
        assert "恶意 IP" in html_output
        assert "DNS 隧道" in html_output
        assert "192.168.1.100" in html_output
    
    def test_html_xss_protection(self, sample_result):
        """测试 XSS 防护"""
        # 添加包含潜在 XSS 内容的威胁
        sample_result.threats.append(
            ThreatFinding(
                threat_type="MALICIOUS_IP",
                severity="LOW",
                description="<script>alert('xss')</script>",
                evidence={"test": "<img src=x onerror=alert(1)>"},
                recommendation="</script><script>alert('xss')</script>",
            )
        )
        
        generator = HTMLReportGenerator(sample_result)
        html_output = generator.generate()
        
        # 检查脚本标签已被转义
        assert "<script>alert" not in html_output
        assert "&lt;script&gt;" in html_output or html.escape("<script>") in html_output
    
    def test_html_with_api_stats(self, sample_result):
        """测试带 API 统计的 HTML"""
        generator = HTMLReportGenerator(sample_result)
        
        api_stats = {
            "abuseipdb": {
                "api_queries": 10,
                "cache_hits": 50,
                "whitelist_size": 100,
            },
            "threatbook": {
                "api_queries": 5,
                "cache_hits": 20,
                "whitelist_size": 50,
            },
        }
        
        html_output = generator.generate(api_stats=api_stats)
        
        assert "AbuseIPDB" in html_output
        assert "ThreatBook" in html_output
    
    def test_html_with_empty_threats(self):
        """测试无威胁时的 HTML"""
        result = AnalysisResult(
            total_flows=100,
            total_packets=1000,
            total_bytes=10000,
            threats=[],
            high_severity_count=0,
            medium_severity_count=0,
            low_severity_count=0,
        )
        
        generator = HTMLReportGenerator(result)
        html_output = generator.generate()
        
        assert "0" in html_output  # 威胁数量为 0
    
    def test_html_chart_includes_chartjs(self, sample_result):
        """测试 HTML 包含 Chart.js"""
        generator = HTMLReportGenerator(sample_result)
        html_output = generator.generate()
        
        assert "chart.js" in html_output.lower() or "Chart" in html_output
        assert "protoChart" in html_output
        assert "threatTypeChart" in html_output
    
    def test_html_collapsible_alerts(self, sample_result):
        """测试可折叠告警"""
        generator = HTMLReportGenerator(sample_result)
        html_output = generator.generate()
        
        assert "threat-header" in html_output
        assert "threat-detail" in html_output
        assert "toggleAll" in html_output
