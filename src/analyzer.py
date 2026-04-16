"""主分析器模块 - 协调所有检测引擎（插件化架构）"""

import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import pandas as pd

from core.parser import FlowStreamAnalyzer
from core.config import settings
from core.models import AnalysisResult, Severity
from datasource.manager import DataSourceManager, DataSourceCategory
from intel.smart_threat import SmartThreatDetector
from intel.abuseipdb_detector import AbuseIPDBSmartDetector
from intel.cache import ThreatCache
from ml.classifier import MLAnomalyClassifier
from report.generator import ReportGenerator
from plugins import PluginManager

logger = logging.getLogger(__name__)


class NetflowSightAnalyzer:
    """主分析器 - 协调所有检测引擎（插件化架构）"""

    def __init__(
        self,
        pcap_file: str,
        enable_ml: bool = True,
        enable_threat_intel: bool = True,
        enable_ai: bool = False,
        ai_client: Optional[object] = None,
        interactive: bool = False,
        plugin_dirs: Optional[list[str]] = None,
    ):
        self.pcap_file = pcap_file
        self.enable_ml = enable_ml
        self.enable_threat_intel = enable_threat_intel
        self.enable_ai = enable_ai
        self.ai_client = ai_client

        # 初始化 PCAP 解析器
        self.parser = FlowStreamAnalyzer(
            source=pcap_file,
            statistical_analysis=settings.STATISTICAL_ANALYSIS,
            n_dissections=settings.N_DISSECTIONS,
            decode_tunnels=settings.DECODE_TUNNELS,
        )

        # 初始化数据源管理器
        project_root = Path(__file__).resolve().parent.parent
        self.datasource_mgr = DataSourceManager(
            data_dir=str(project_root / "data" / "sources"),
            auto_load_state=True,
            auto_update_on_start=True,
            interactive=interactive,
        )

        # 初始化插件管理器
        self.plugin_manager = PluginManager()
        self._init_plugins(plugin_dirs)

        # ML 分类器和 IP 信誉检测器
        self.ml_classifier = MLAnomalyClassifier() if enable_ml else None
        self.abuseipdb_detector = AbuseIPDBSmartDetector() if enable_threat_intel else None
        self.smart_threat_detector = SmartThreatDetector() if enable_threat_intel else None
        self.threat_cache = ThreatCache()

        self._df: Optional[pd.DataFrame] = None
        self._result: Optional[AnalysisResult] = None

    def _init_plugins(self, plugin_dirs: Optional[list[str]] = None):
        """初始化插件系统"""
        # 加载内置插件
        loaded = self.plugin_manager.load_builtin_plugins()
        logger.info(f"加载内置插件: {loaded}")

        # 加载外部插件
        project_root = Path(__file__).resolve().parent.parent
        external_dir = project_root / "src" / "plugins" / "external"
        if external_dir.exists():
            external_loaded = self.plugin_manager.load_external_plugins(str(external_dir))
            logger.info(f"加载外部插件: {external_loaded}")

        # 加载自定义插件目录
        if plugin_dirs:
            for plugin_dir in plugin_dirs:
                self.plugin_manager.load_external_plugins(plugin_dir)

    def analyze(self) -> AnalysisResult:
        """运行完整的分析流程"""
        start_time = time.time()
        logger.info(f"开始分析 {self.pcap_file}")

        # [1/6] 解析 PCAP
        logger.info("[1/6] 解析 PCAP 文件...")
        self._df = self.parser.parse()
        if self._df.empty:
            return AnalysisResult(pcap_file=self.pcap_file, analysis_timestamp=datetime.now().isoformat())

        # [2/6] ML 异常检测
        if self.enable_ml and self.ml_classifier:
            logger.info("[2/6] 运行 ML 异常检测...")
            self._df = self.ml_classifier.predict(self._df)

        # [3/6] 插件化威胁检测
        logger.info("[3/6] 运行检测插件...")
        all_threats = self._run_plugins()

        # 智能威胁检测
        if self.enable_threat_intel and self.smart_threat_detector:
            logger.info("[3.5/6] 运行智能域名验证 (ThreatBook API)...")
            ml_domains = []
            for t in all_threats:
                if t.threat_type.value == "UNKNOWN_DOMAIN":
                    evidence = getattr(t, 'evidence', {})
                    domain = evidence.get('domain', '')
                    if domain:
                        ml_domains.append(domain)
            smart_threats = self.smart_threat_detector.detect_threats(self._df, suspicious_domains=ml_domains)
            all_threats.extend(smart_threats)

        # [4/6] 威胁情报查询
        malicious_ips = []
        if self.enable_threat_intel and self.abuseipdb_detector:
            logger.info("[4/6] 查询 AbuseIPDB 威胁情报...")
            abuse_threats, malicious_ips = self.abuseipdb_detector.detect_threats(self._df)
            all_threats.extend(abuse_threats)

        # [5/6] AI 报告生成
        ai_report = None
        if self.enable_ai and self.ai_client:
            logger.info("[5/6] 生成 AI 分析报告...")
            ai_report = self._generate_ai_report(all_threats)

        # [6/6] 汇总结果
        logger.info("[6/6] 汇总分析结果...")
        summary = self.parser.get_summary()
        processing_time = (time.time() - start_time) * 1000

        self._result = AnalysisResult(
            total_flows=summary.get("total_flows", 0),
            total_packets=summary.get("total_packets", 0),
            total_bytes=summary.get("total_bytes", 0),
            unique_src_ips=summary.get("unique_src_ips", 0),
            unique_dst_ips=summary.get("unique_dst_ips", 0),
            protocol_distribution=summary.get("protocol_distribution", {}),
            time_range=summary.get("time_range"),
            threats=all_threats,
            high_severity_count=len([t for t in all_threats if t.severity == Severity.HIGH]),
            medium_severity_count=len([t for t in all_threats if t.severity == Severity.MEDIUM]),
            low_severity_count=len([t for t in all_threats if t.severity == Severity.LOW]),
            ml_predictions=self.ml_classifier.get_anomaly_summary(self._df) if self.ml_classifier else None,
            anomaly_count=int(self._df["is_anomaly"].sum()) if self.ml_classifier and "is_anomaly" in self._df.columns else 0,
            malicious_ips=malicious_ips,
            ai_report=ai_report,
            pcap_file=self.pcap_file,
            analysis_timestamp=datetime.now().isoformat(),
            processing_time_ms=processing_time,
            cost_estimate={"local": "$0", "ai_tokens": self._estimate_tokens()},
        )

        logger.info(f"分析完成，耗时 {processing_time:.0f}ms")
        return self._result

    def _run_plugins(self) -> list:
        """运行所有检测插件"""
        # 构建上下文
        context = {
            "safe_domains": self.datasource_mgr.get_items(DataSourceCategory.WHITELIST_DOMAINS),
            "threat_domains": self.datasource_mgr.get_items(DataSourceCategory.THREAT_DOMAINS),
            "threat_ips": self.datasource_mgr.get_items(DataSourceCategory.THREAT_IPS),
            "threat_urls": self.datasource_mgr.get_items(DataSourceCategory.THREAT_URLS),
            "suspicious_ua": self.datasource_mgr.get_items(DataSourceCategory.SUSPICIOUS_UA),
            "phishing_keywords": self.datasource_mgr.get_items(DataSourceCategory.PHISHING_KEYWORDS),
            "datasource_manager": self.datasource_mgr,
            "config": {},
        }

        # 执行所有插件
        results = self.plugin_manager.run_all(self._df, context)

        # 转换为兼容格式
        from plugins.base import DetectionResult
        threats = []
        for r in results:
            if isinstance(r, DetectionResult):
                # 转换为 core.models 的 ThreatAlert 格式
                from core.models import ThreatAlert, ThreatType, Severity
                threat = ThreatAlert(
                    threat_type=ThreatType(r.threat_type.value),
                    severity=Severity(r.severity.value),
                    description=r.description,
                    evidence=r.evidence,
                    confidence=r.confidence,
                    ioc=r.ioc,
                    mitre_technique=r.mitre_technique,
                    recommended_action=r.recommended_action,
                )
                threats.append(threat)
            else:
                threats.append(r)

        return threats

    def _generate_ai_report(self, threats: list) -> Optional[str]:
        if not self.ai_client:
            return None
        context = {
            "summary": self.parser.get_summary(),
            "threat_count": len(threats),
            "top_threats": [{"type": t.threat_type.value, "severity": t.severity.value, "description": t.description} for t in threats[:20]],
        }
        try:
            if hasattr(self.ai_client, "generate_report"):
                return self.ai_client.generate_report(context)
        except Exception as e:
            logger.error(f"AI 报告生成失败: {e}")
        return None

    def _estimate_tokens(self) -> int:
        if not self._result:
            return 0
        import json
        context_size = len(json.dumps(self.parser.get_summary()))
        threat_size = len(self._result.threats) * 200
        return (context_size + threat_size) // 4

    def generate_report(
        self,
        format: str = "html",
        output_path: Optional[str] = None,
        generate_ai_report: bool = False,
        ai_output_path: Optional[str] = None,
    ) -> dict[str, str]:
        """生成分析报告"""
        if not self._result:
            raise RuntimeError("必须先调用 analyze() 方法")

        generator = ReportGenerator(self._result)
        results = {}

        if format == "json":
            results["human_report"] = generator.generate_json(output_path)
        elif format == "markdown":
            results["human_report"] = generator.generate_markdown(output_path)
        elif format == "text":
            results["human_report"] = generator.generate_text_summary()
        elif format == "html":
            from report.html_generator import HTMLReportGenerator
            html_gen = HTMLReportGenerator(self._result)
            api_stats = {}
            if hasattr(self, 'abuseipdb_detector') and self.abuseipdb_detector:
                api_stats['abuseipdb'] = self.abuseipdb_detector.get_stats()
            if hasattr(self, 'smart_threat_detector') and self.smart_threat_detector:
                api_stats['threatbook'] = self.smart_threat_detector.get_stats()
            results["human_report"] = html_gen.generate(output_path, api_stats=api_stats)
        else:
            raise ValueError(f"不支持的格式: {format}")

        if generate_ai_report:
            results["ai_report"] = generator.generate_ai_report(ai_output_path)

        return results

    def get_dataframe(self) -> pd.DataFrame:
        if self._df is None:
            raise RuntimeError("必须先调用 analyze() 方法")
        return self._df

    # ==========================================
    # 插件管理接口
    # ==========================================

    def list_plugins(self) -> list[dict]:
        """列出所有插件"""
        return self.plugin_manager.list_plugins()

    def enable_plugin(self, name: str) -> bool:
        """启用插件"""
        return self.plugin_manager.enable_plugin(name)

    def disable_plugin(self, name: str) -> bool:
        """禁用插件"""
        return self.plugin_manager.disable_plugin(name)

    def get_plugin_stats(self) -> dict:
        """获取插件统计"""
        return self.plugin_manager.get_stats()
