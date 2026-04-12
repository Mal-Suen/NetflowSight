"""
Report Generator - Creates comprehensive analysis reports
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from core.models import AnalysisResult, Severity

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generate analysis reports in various formats.
    
    Supports:
    - JSON
    - Markdown
    - Text summary
    """
    
    def __init__(self, result: AnalysisResult):
        """
        Initialize report generator.
        
        Args:
            result: AnalysisResult object from analysis
        """
        self.result = result
    
    def generate_json(self, output_path: Optional[str] = None) -> str:
        """
        Generate JSON report.
        
        Args:
            output_path: Optional file path to save report
            
        Returns:
            JSON string
        """
        report_data = self.result.to_dict()
        json_str = json.dumps(report_data, indent=2, default=str)
        
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                f.write(json_str)
            logger.info(f"JSON report saved to {output_path}")
        
        return json_str
    
    def generate_markdown(self, output_path: Optional[str] = None) -> str:
        """
        Generate Markdown report.
        
        Args:
            output_path: Optional file path to save report
            
        Returns:
            Markdown string
        """
        lines = []
        
        # Header
        lines.append("# 🔍 NetflowSight Analysis Report")
        lines.append("")
        lines.append(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**PCAP File**: {self.result.pcap_file}")
        lines.append(f"**Processing Time**: {self.result.processing_time_ms:.2f}ms")
        lines.append("")
        
        # Summary
        lines.append("## 📊 Summary")
        lines.append("")
        lines.append(f"- **Total Flows**: {self.result.total_flows:,}")
        lines.append(f"- **Total Packets**: {self.result.total_packets:,}")
        lines.append(f"- **Total Bytes**: {self.result.total_bytes / 1e6:.2f} MB")
        lines.append(f"- **Unique Source IPs**: {self.result.unique_src_ips}")
        lines.append(f"- **Unique Destination IPs**: {self.result.unique_dst_ips}")
        lines.append("")
        
        # Protocol Distribution
        if self.result.protocol_distribution:
            lines.append("### Protocol Distribution")
            lines.append("")
            for proto, count in list(self.result.protocol_distribution.items())[:10]:
                lines.append(f"- **{proto}**: {count:,}")
            lines.append("")
        
        # Threat Summary
        lines.append("## 🚨 Threat Summary")
        lines.append("")
        lines.append(f"- **High Severity**: {self.result.high_severity_count}")
        lines.append(f"- **Medium Severity**: {self.result.medium_severity_count}")
        lines.append(f"- **Low Severity**: {self.result.low_severity_count}")
        lines.append("")
        
        if self.result.threats:
            lines.append("### Top Threats")
            lines.append("")
            for i, threat in enumerate(self.result.threats[:20], 1):
                severity_emoji = {
                    Severity.CRITICAL: "🔴",
                    Severity.HIGH: "🟠",
                    Severity.MEDIUM: "🟡",
                    Severity.LOW: "🟢",
                }.get(threat.severity, "⚪")
                
                lines.append(f"{i}. {severity_emoji} **{threat.threat_type.value}** ({threat.severity.value})")
                lines.append(f"   - {threat.description}")
                if threat.recommendation:
                    lines.append(f"   - 💡 {threat.recommendation}")
                lines.append("")
        
        # ML Analysis
        if self.result.ml_predictions:
            lines.append("## 🤖 ML Anomaly Detection")
            lines.append("")
            lines.append(f"- **Anomalies Detected**: {self.result.anomaly_count}")
            lines.append("")
        
        # Threat Intelligence
        if self.result.malicious_ips:
            lines.append("## 🌐 Threat Intelligence")
            lines.append("")
            lines.append(f"- **Malicious IPs Found**: {len(self.result.malicious_ips)}")
            lines.append("")
            for ip_info in self.result.malicious_ips[:10]:
                lines.append(f"- **{ip_info.get('ip', 'unknown')}** (Abuse Score: {ip_info.get('abuse_score', 0)})")
            lines.append("")
        
        # AI Report
        if self.result.ai_report:
            lines.append("## 🧠 AI Analysis Report")
            lines.append("")
            lines.append(self.result.ai_report)
            lines.append("")
        
        # Footer
        lines.append("---")
        lines.append("*Generated by NetflowSight - AI-Powered Network Traffic Analysis*")
        
        markdown = "\n".join(lines)
        
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(markdown)
            logger.info(f"Markdown report saved to {output_path}")
        
        return markdown
    
    def generate_text_summary(self) -> str:
        """
        Generate concise text summary for CLI output.
        
        Returns:
            Text summary string
        """
        lines = []
        
        lines.append("=" * 60)
        lines.append("🔍 NetflowSight Analysis Complete")
        lines.append("=" * 60)
        lines.append("")
        lines.append(f"📊 Summary:")
        lines.append(f"   Flows: {self.result.total_flows:,}")
        lines.append(f"   Packets: {self.result.total_packets:,}")
        lines.append(f"   Bytes: {self.result.total_bytes / 1e6:.2f} MB")
        lines.append("")
        
        if self.result.threats:
            lines.append(f"🚨 Threats Found:")
            lines.append(f"   🔴 High: {self.result.high_severity_count}")
            lines.append(f"   🟡 Medium: {self.result.medium_severity_count}")
            lines.append(f"   🟢 Low: {self.result.low_severity_count}")
            lines.append("")
            
            lines.append("   Top 5 Threats:")
            for i, threat in enumerate(self.result.threats[:5], 1):
                lines.append(f"   {i}. [{threat.severity.value}] {threat.threat_type.value}")
            lines.append("")
        
        if self.result.anomaly_count > 0:
            lines.append(f"🤖 ML Anomalies: {self.result.anomaly_count}")
            lines.append("")
        
        if self.result.malicious_ips:
            lines.append(f"🌐 Malicious IPs: {len(self.result.malicious_ips)}")
            lines.append("")
        
        lines.append(f"⏱️  Processing Time: {self.result.processing_time_ms:.0f}ms")
        lines.append(f"💰 AI Cost: {self.result.cost_estimate.get('ai_tokens', 0)} tokens")
        lines.append("")

        return "\n".join(lines)

    def generate_ai_report(self, output_path: Optional[str] = None) -> str:
        """
        Generate AI-optimized analysis report.

        This report is specifically designed for AI (GPT-4/Claude) processing:
        - Structured JSON format with clear sections
        - Includes suggested analysis prompts
        - Compresses context to reduce token usage
        - Provides actionable intelligence for AI reasoning

        Args:
            output_path: Optional file path to save AI report

        Returns:
            AI report JSON string
        """
        # Build network context
        internal_ips = []
        external_ips = []
        if self.result.malicious_ips:
            for ip_info in self.result.malicious_ips:
                if ip_info.get("ip"):
                    external_ips.append(ip_info["ip"])

        # Build threats section by type
        threats_by_type = {}
        for threat in self.result.threats:
            t_type = threat.threat_type.value
            if t_type not in threats_by_type:
                threats_by_type[t_type] = []
            threats_by_type[t_type].append({
                "severity": threat.severity.value,
                "description": threat.description,
                "evidence": threat.evidence if hasattr(threat, 'evidence') else {},
                "ioc": threat.ioc if hasattr(threat, 'ioc') else [],
            })

        # Generate suggested AI prompts based on detected threats
        suggested_prompts = self._generate_suggested_prompts(threats_by_type)

        ai_report = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "NetflowSight v1.0.0",
                "report_type": "AI-Assisted Analysis",
                "version": "1.0",
            },
            "context": {
                "traffic_summary": {
                    "total_flows": self.result.total_flows,
                    "total_packets": self.result.total_packets,
                    "total_bytes": self.result.total_bytes,
                    "total_bytes_human": f"{self.result.total_bytes / 1e6:.2f} MB",
                    "unique_src_ips": self.result.unique_src_ips,
                    "unique_dst_ips": self.result.unique_dst_ips,
                    "duration_ms": self.result.time_range.get("duration_ms", 0) if self.result.time_range else 0,
                },
                "protocol_distribution": self.result.protocol_distribution,
                "threat_summary": {
                    "total_threats": len(self.result.threats),
                    "high_severity": self.result.high_severity_count,
                    "medium_severity": self.result.medium_severity_count,
                    "low_severity": self.result.low_severity_count,
                    "ml_anomalies": self.result.anomaly_count,
                    "malicious_ips": len(self.result.malicious_ips),
                },
            },
            "threats": {
                "by_type": threats_by_type,
                "top_threats": [
                    {
                        "type": t.threat_type.value,
                        "severity": t.severity.value,
                        "description": t.description,
                        "evidence": t.evidence if hasattr(t, 'evidence') else {},
                        "ioc": t.ioc if hasattr(t, 'ioc') else [],
                    }
                    for t in self.result.threats[:50]
                ],
            },
            "ml_analysis": self.result.ml_predictions or {},
            "suggested_ai_prompts": suggested_prompts,
            "ai_analysis_instructions": (
                "你是一位高级网络安全分析师。请基于以上 PCAP 预处理报告，完成以下任务：\n"
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

        ai_json = json.dumps(ai_report, indent=2, default=str, ensure_ascii=False)

        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(ai_json)
            logger.info(f"AI report saved to {output_path}")

        return ai_json

    def _generate_suggested_prompts(self, threats_by_type: dict) -> list[str]:
        """Generate suggested AI analysis prompts based on detected threats."""
        prompts = []

        if "DNS_TUNNEL" in threats_by_type or "DNS_EXFILTRATION" in threats_by_type:
            prompts.append(
                "检测到 DNS 隧道/数据外发迹象。请分析 DNS 流量模式，"
                "判断是否为真正的数据外泄，还是正常的 DNS 行为（如 DNS over HTTPS）。"
            )

        if "ICMP_TUNNEL" in threats_by_type:
            prompts.append(
                "检测到异常 ICMP 流量（大于正常 ping 的大小）。"
                "请分析这可能是网络管理工具、隧道工具还是误报。"
            )

        if "LARGE_DATA_TRANSFER" in threats_by_type:
            prompts.append(
                "检测到大流量传输。请结合目标 IP 和协议信息，"
                "判断这是否为合法的业务流量（如云存储同步、视频会议等）。"
            )

        if "PORT_SCAN" in threats_by_type:
            prompts.append(
                "检测到端口扫描行为。请评估这是内部安全扫描、"
                "攻击者侦察还是正常的网络发现协议。"
            )

        if "DGA_DOMAIN" in threats_by_type:
            prompts.append(
                "检测到 DGA（域名生成算法）特征域名。请分析这些域名的模式，"
                "判断是否为恶意软件动态生成，还是正常的随机字符串域名。"
            )

        if "PHISHING" in threats_by_type:
            prompts.append(
                "检测到可疑钓鱼域名。请结合威胁情报信息，评估这些域名的风险等级，"
                "并给出相应的处置建议。"
            )

        if not prompts:
            prompts.append(
                "未发现明显高危威胁，请评估整体网络安全态势，"
                "并给出常规安全加固建议。"
            )

        prompts.append(
            "如果需要进一步调查，建议获取哪些额外信息？"
            "（如完整 DNS 查询日志、TLS SNI、HTTP 请求内容等）"
        )

        return prompts
