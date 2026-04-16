"""
示例插件：数据泄露检测器

检测大流量外传行为，可能的数据泄露迹象。
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import pandas as pd

from plugins.base import (
    BaseDetectionPlugin,
    DetectionResult,
    PluginMetadata,
)
from core.models import Severity, ThreatType

logger = logging.getLogger(__name__)


class DataExfiltrationDetector(BaseDetectionPlugin):
    """
    数据泄露检测插件。

    检测逻辑：
    - 大流量外传（出站流量 >> 入站流量）
    - 可疑端口上传（非标准端口的大流量）
    """

    def __init__(self, config: Optional[dict[str, Any]] = None):
        super().__init__(config)
        self._default_config = {
            "bytes_threshold": 100_000_000,  # 100MB
            "ratio_threshold": 5.0,  # 出站/入站比率
            "suspicious_ports": {8443, 9000, 9999, 4444},  # 可疑端口
        }

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="data_exfil_detector",
            version="1.0.0",
            description="数据泄露检测插件 - 检测大流量外传行为",
            author="Custom Plugin",
            tags=["exfiltration", "data_theft", "large_transfer"],
            priority=60,
        )

    def initialize(self) -> bool:
        for key, value in self._default_config.items():
            if key not in self._config:
                self._config[key] = value
        return True

    def run(
        self,
        df: pd.DataFrame,
        context: Optional[dict[str, Any]] = None
    ) -> list[DetectionResult]:
        if df.empty:
            return []

        results = []
        bytes_threshold = self._config["bytes_threshold"]
        suspicious_ports = self._config["suspicious_ports"]

        # 检测大流量
        for _, row in df.iterrows():
            bytes_out = row.get("bidirectional_bytes", 0)
            dst_port = row.get("dst_port")
            src_ip = row.get("src_ip")
            dst_ip = row.get("dst_ip")

            # 大流量 + 可疑端口
            if bytes_out >= bytes_threshold and dst_port in suspicious_ports:
                results.append(DetectionResult(
                    engine_name=self.name,
                    engine_version=self.version,
                    threat_type=ThreatType.DATA_EXFIL,
                    severity=Severity.HIGH,
                    description=f"检测到可疑大流量外传: {src_ip} -> {dst_ip}:{dst_port} ({bytes_out/1_000_000:.1f} MB)",
                    evidence={
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "destination_port": dst_port,
                        "bytes_transferred": bytes_out,
                    },
                    confidence=0.8,
                    ioc=[src_ip, dst_ip],
                    mitre_technique="T1041",  # Exfiltration Over C2 Channel
                    recommended_action="建议检查传输内容，确认是否为合法数据传输",
                ))

        return results


def get_plugin() -> BaseDetectionPlugin:
    return DataExfiltrationDetector()
