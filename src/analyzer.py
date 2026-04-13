"""
Main Analyzer - Orchestrates all components
"""

import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import pandas as pd

from core.parser import FlowStreamAnalyzer
from core.config import settings
from core.models import AnalysisResult, Severity
from engines.dns import DNSThreatDetector
from engines.http import HTTPThreatDetector
from engines.covert import CovertChannelDetector
from engines.behavior import BehavioralAnomalyDetector
from engines.smart_threat import SmartThreatDetector
from engines.abuseipdb_detector import AbuseIPDBSmartDetector
from datasource.manager import DataSourceManager, DataSourceCategory
from intel.cache import ThreatCache
from ml.classifier import MLAnomalyClassifier
from report.generator import ReportGenerator

logger = logging.getLogger(__name__)


class NetflowSightAnalyzer:
    """
    Main analyzer that orchestrates all detection engines.

    This is the primary entry point for PCAP analysis.
    """

    def __init__(
        self,
        pcap_file: str,
        enable_ml: bool = True,
        enable_threat_intel: bool = True,
        enable_ai: bool = False,
        ai_client: Optional[object] = None,
        interactive: bool = False,
    ):
        """
        Initialize the analyzer.

        Args:
            pcap_file: Path to PCAP file
            enable_ml: Enable ML anomaly detection
            enable_threat_intel: Enable threat intelligence APIs
            enable_ai: Enable AI report generation
            ai_client: Optional AI client for report generation
            interactive: Whether to prompt for data source updates
        """
        self.pcap_file = pcap_file
        self.enable_ml = enable_ml
        self.enable_threat_intel = enable_threat_intel
        self.enable_ai = enable_ai
        self.ai_client = ai_client

        # Initialize components
        self.parser = FlowStreamAnalyzer(
            source=pcap_file,
            statistical_analysis=settings.STATISTICAL_ANALYSIS,
            n_dissections=settings.N_DISSECTIONS,
            decode_tunnels=settings.DECODE_TUNNELS,
        )

        # Initialize data source manager (loads local threat intelligence)
        project_root = Path(__file__).resolve().parent.parent  # src/ -> project root
        self.datasource_mgr = DataSourceManager(
            data_dir=str(project_root / "data" / "sources"),
            auto_load_state=True,
            auto_update_on_start=True,
            interactive=interactive,
        )

        safe_domains = settings.load_safe_domains()
        self.dns_detector = DNSThreatDetector(safe_domains=safe_domains)
        self.http_detector = HTTPThreatDetector()
        self.covert_detector = CovertChannelDetector()
        self.behavior_detector = BehavioralAnomalyDetector()

        # Smart threat detector for domain API verification (ThreatBook)
        self.smart_threat_detector = SmartThreatDetector() if enable_threat_intel else None

        # Store safe_domains for reference (threat_domains refreshed per-analyze)
        self._safe_domains = safe_domains

        self.ml_classifier = MLAnomalyClassifier() if enable_ml else None
        self.abuseipdb_detector = AbuseIPDBSmartDetector() if enable_threat_intel else None
        self.threat_cache = ThreatCache()

        self._df: Optional[pd.DataFrame] = None
        self._result: Optional[AnalysisResult] = None

    def analyze(self) -> AnalysisResult:
        """
        Run complete analysis pipeline.

        Returns:
            AnalysisResult with all findings
        """
        start_time = time.time()
        logger.info(f"Starting analysis of {self.pcap_file}")

        # Step 1: Parse PCAP
        logger.info("[1/6] Parsing PCAP file...")
        self._df = self.parser.parse()
        if self._df.empty:
            return AnalysisResult(
                pcap_file=self.pcap_file,
                analysis_timestamp=datetime.now().isoformat(),
            )

        # Step 2: ML Anomaly Detection
        if self.enable_ml and self.ml_classifier:
            logger.info("[2/6] Running ML anomaly detection...")
            self._df = self.ml_classifier.predict(self._df)

        # Step 3: Threat Detection (local data sources first)
        logger.info("[3/6] Running threat detection engines...")
        all_threats = []

        # Refresh threat domains from data source manager on each analysis
        threat_domains = self.datasource_mgr.get_items(DataSourceCategory.THREAT_DOMAINS)

        # DNS detection with local threat domains
        all_threats.extend(self.dns_detector.run(self._df, threat_domains=threat_domains))
        all_threats.extend(self.http_detector.run(self._df))
        all_threats.extend(self.covert_detector.run(self._df))
        all_threats.extend(self.behavior_detector.run(self._df))

        # Smart threat detection: send ML-flagged suspicious domains to ThreatBook API for verification
        if self.enable_threat_intel and self.smart_threat_detector:
            logger.info("[3.5/6] Running smart domain verification (ThreatBook API)...")
            # Extract high-risk domains detected by ML classifier
            ml_domains = []
            for t in all_threats:
                if t.threat_type.value == "UNKNOWN_DOMAIN":
                    evidence = getattr(t, 'evidence', {})
                    domain = evidence.get('domain', '')
                    if domain:
                        ml_domains.append(domain)
            logger.info(f"  Found {len(ml_domains)} ML-flagged domains for ThreatBook verification")
            smart_threats = self.smart_threat_detector.detect_threats(self._df, suspicious_domains=ml_domains)
            all_threats.extend(smart_threats)

        # Step 4: Threat Intelligence (AbuseIPDB with smart caching)
        malicious_ips = []
        if self.enable_threat_intel and self.abuseipdb_detector:
            logger.info("[4/6] Checking AbuseIPDB threat intelligence...")
            abuse_threats, malicious_ips = self.abuseipdb_detector.detect_threats(self._df)
            all_threats.extend(abuse_threats)

        # Step 5: AI Report (optional)
        ai_report = None
        if self.enable_ai and self.ai_client:
            logger.info("[5/6] Generating AI report...")
            ai_report = self._generate_ai_report(all_threats)

        # Step 6: Compile results
        logger.info("[6/6] Compiling results...")
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

        logger.info(f"Analysis complete in {processing_time:.0f}ms")
        return self._result

    def _generate_ai_report(self, threats: list) -> Optional[str]:
        """Generate AI-powered report."""
        if not self.ai_client:
            return None
        
        # Compress context for AI
        context = {
            "summary": self.parser.get_summary(),
            "threat_count": len(threats),
            "top_threats": [
                {
                    "type": t.threat_type.value,
                    "severity": t.severity.value,
                    "description": t.description,
                }
                for t in threats[:20]
            ],
        }
        
        try:
            # Use AI client to generate report
            # This assumes ai_client has a generate_report method
            if hasattr(self.ai_client, "generate_report"):
                return self.ai_client.generate_report(context)
        except Exception as e:
            logger.error(f"AI report generation failed: {e}")
        
        return None
    
    def _estimate_tokens(self) -> int:
        """Estimate AI token usage."""
        if not self._result:
            return 0
        
        # Rough estimate: 1 token ≈ 4 characters
        import json
        context_size = len(json.dumps(self.parser.get_summary()))
        threat_size = len(self._result.threats) * 200  # ~200 chars per threat
        return (context_size + threat_size) // 4
    
    def generate_report(
        self,
        format: str = "html",
        output_path: Optional[str] = None,
        generate_ai_report: bool = False,
        ai_output_path: Optional[str] = None,
    ) -> dict[str, str]:
        """
        Generate analysis reports.

        Args:
            format: Report format ('json', 'markdown', 'text', 'html')
            output_path: Optional file path to save human-readable report
            generate_ai_report: Whether to generate AI-optimized report
            ai_output_path: Optional file path to save AI report

        Returns:
            Dictionary with paths to generated reports
        """
        if not self._result:
            raise RuntimeError("analyze() must be called before generate_report()")

        generator = ReportGenerator(self._result)
        results = {}

        # Generate human-readable report
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
            raise ValueError(f"Unsupported format: {format}")

        # Generate AI-optimized report
        if generate_ai_report:
            ai_report = generator.generate_ai_report(ai_output_path)
            results["ai_report"] = ai_report

        return results

    def get_dataframe(self) -> pd.DataFrame:
        """Get the parsed flow DataFrame."""
        if self._df is None:
            raise RuntimeError("analyze() must be called first")
        return self._df
