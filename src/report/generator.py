"""报告生成器模块 - 支持 JSON、Markdown、Text、AI 报告格式"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from core.models import AnalysisResult, Severity

logger = logging.getLogger(__name__)


class ReportGenerator:
    """分析报告生成器"""

    def __init__(self, result: AnalysisResult):
        self.result = result

    def generate_json(self, output_path: Optional[str] = None) -> str:
        """生成 JSON 格式报告"""
        report_data = self.result.to_dict()
        json_str = json.dumps(report_data, indent=2, default=str)

        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                f.write(json_str)
            logger.info(f"JSON 报告已保存到 {output_path}")

        return json_str

    def generate_markdown(self, output_path: Optional[str] = None) -> str:
        """生成 Markdown 格式报告"""
        lines = []
        lines.append("# 🔍 NetflowSight 分析报告")
        lines.append("")
        lines.append(f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**PCAP 文件**: {self.result.pcap_file}")
        lines.append(f"**处理耗时**: {self.result.processing_time_ms:.2f} ms")
        lines.append("")

        # 流量摘要
        lines.append("## 📊 流量摘要")
        lines.append("")
        lines.append(f"- **总流量数**: {self.result.total_flows:,}")
        lines.append(f"- **总数据包数**: {self.result.total_packets:,}")
        lines.append(f"- **总字节数**: {self.result.total_bytes / 1e6:.2f} MB")
        lines.append("")

        # 威胁摘要
        lines.append("## 🚨 威胁摘要")
        lines.append("")
        lines.append(f"- **高危**: {self.result.high_severity_count}")
        lines.append(f"- **中危**: {self.result.medium_severity_count}")
        lines.append(f"- **低危**: {self.result.low_severity_count}")
        lines.append("")

        # 威胁详情
        if self.result.threats:
            lines.append("### 威胁详情 (Top 20)")
            lines.append("")
            for i, threat in enumerate(self.result.threats[:20], 1):
                severity_emoji = {
                    Severity.CRITICAL: "🔴", Severity.HIGH: "🟠",
                    Severity.MEDIUM: "🟡", Severity.LOW: "🟢",
                }.get(threat.severity, "⚪")
                lines.append(f"{i}. {severity_emoji} **{threat.threat_type.value}** ({threat.severity.value})")
                lines.append(f"   - {threat.description}")
                lines.append("")

        # ML 异常检测
        if self.result.ml_predictions:
            lines.append("## 🤖 ML 异常检测")
            lines.append(f"- **检测到异常**: {self.result.anomaly_count} 个")
            lines.append("")

        # 威胁情报
        if self.result.malicious_ips:
            lines.append("## 🌐 威胁情报")
            lines.append(f"- **恶意 IP 数量**: {len(self.result.malicious_ips)}")
            for ip_info in self.result.malicious_ips[:10]:
                lines.append(f"- **{ip_info.get('ip', 'unknown')}** (滥用评分: {ip_info.get('abuse_score', 0)})")
            lines.append("")

        # AI 报告
        if self.result.ai_report:
            lines.append("## 🧠 AI 分析报告")
            lines.append(self.result.ai_report)
            lines.append("")

        lines.append("---")
        lines.append("*由 NetflowSight 生成*")

        markdown = "\n".join(lines)

        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(markdown)
            logger.info(f"Markdown 报告已保存到 {output_path}")

        return markdown

    def generate_text_summary(self) -> str:
        """生成简洁的文本摘要"""
        lines = []
        lines.append("=" * 60)
        lines.append("🔍 NetflowSight 分析完成")
        lines.append("=" * 60)
        lines.append("")
        lines.append("📊 流量摘要:")
        lines.append(f"   流量数: {self.result.total_flows:,}")
        lines.append(f"   数据包数: {self.result.total_packets:,}")
        lines.append(f"   总字节数: {self.result.total_bytes / 1e6:.2f} MB")
        lines.append("")

        if self.result.threats:
            lines.append("🚨 发现威胁:")
            lines.append(f"   🔴 高危: {self.result.high_severity_count}")
            lines.append(f"   🟡 中危: {self.result.medium_severity_count}")
            lines.append(f"   🟢 低危: {self.result.low_severity_count}")
            lines.append("")

        if self.result.anomaly_count > 0:
            lines.append(f"🤖 ML 异常检测: {self.result.anomaly_count} 个")
            lines.append("")

        if self.result.malicious_ips:
            lines.append(f"🌐 恶意 IP: {len(self.result.malicious_ips)} 个")
            lines.append("")

        lines.append(f"⏱️  处理耗时: {self.result.processing_time_ms:.0f} ms")
        return "\n".join(lines)

    def generate_ai_report(self, output_path: Optional[str] = None) -> str:
        """生成面向 AI 分析的结构化报告"""
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

        # 根据检测到的威胁生成建议的 AI 提示
        suggested_prompts = self._generate_suggested_prompts(threats_by_type)

        ai_report = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "NetflowSight v1.0.0",
                "report_type": "AI-Assisted Analysis",
            },
            "context": {
                "traffic_summary": {
                    "total_flows": self.result.total_flows,
                    "total_packets": self.result.total_packets,
                    "total_bytes": self.result.total_bytes,
                    "unique_src_ips": self.result.unique_src_ips,
                    "unique_dst_ips": self.result.unique_dst_ips,
                },
                "threat_summary": {
                    "total_threats": len(self.result.threats),
                    "high_severity": self.result.high_severity_count,
                    "medium_severity": self.result.medium_severity_count,
                    "low_severity": self.result.low_severity_count,
                    "ml_anomalies": self.result.anomaly_count,
                    "malicious_ips": len(self.result.malicious_ips),
                },
            },
            "threats": {"by_type": threats_by_type},
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
            logger.info(f"AI 报告已保存到 {output_path}")

        return ai_json

    def _generate_suggested_prompts(self, threats_by_type: dict) -> list[str]:
        """根据检测到的威胁生成建议的 AI 分析提示"""
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
