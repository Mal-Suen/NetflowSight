"""
插件适配器 - 将现有检测引擎包装为插件

这些适配器使得现有的 engines/ 目录中的检测器
可以无缝接入插件系统。
"""

from __future__ import annotations

from typing import Any

import pandas as pd

from .base import (
    BaseDetectionPlugin,
    DetectionResult,
    PluginMetadata,
)


class DNSPluginAdapter(BaseDetectionPlugin):
    """DNS 检测引擎适配器"""

    def __init__(self, detector=None):
        super().__init__()
        self._detector = detector

    def initialize(self) -> bool:
        if self._detector is None:
            from engines.dns import DNSThreatDetector
            self._detector = DNSThreatDetector()
        return True

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="dns_detector",
            version="3.0.0",
            description="DNS 威胁检测引擎 - 黑名单匹配 + ML 分类 + DGA + 隧道检测",
            author="NetflowSight",
            tags=["dns", "phishing", "dga", "tunnel"],
            priority=10,
        )

    def run(
        self,
        df: pd.DataFrame,
        context: dict[str, Any] | None = None
    ) -> list[DetectionResult]:
        context = context or {}
        threat_domains = context.get("threat_domains", set())
        safe_domains = context.get("safe_domains", set())

        if safe_domains:
            self._detector.safe_domains = safe_domains

        return self._detector.run(df, context, threat_domains=threat_domains)


class HTTPPluginAdapter(BaseDetectionPlugin):
    """HTTP 检测引擎适配器"""

    def __init__(self, detector=None):
        super().__init__()
        self._detector = detector

    def initialize(self) -> bool:
        if self._detector is None:
            from engines.http import HTTPThreatDetector
            self._detector = HTTPThreatDetector()
        return True

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="http_detector",
            version="2.0.0",
            description="HTTP 威胁检测引擎 - 异常响应 + 可疑 UA + 恶意 URL",
            author="NetflowSight",
            tags=["http", "malware", "suspicious_ua"],
            priority=20,
        )

    def run(
        self,
        df: pd.DataFrame,
        context: dict[str, Any] | None = None
    ) -> list[DetectionResult]:
        context = context or {}
        threat_urls = context.get("threat_urls", set())
        suspicious_ua = context.get("suspicious_ua", set())
        return self._detector.run(df, context, threat_urls=threat_urls, suspicious_ua=suspicious_ua)


class CovertPluginAdapter(BaseDetectionPlugin):
    """隐蔽通道检测引擎适配器"""

    def __init__(self, detector=None):
        super().__init__()
        self._detector = detector

    def initialize(self) -> bool:
        if self._detector is None:
            from engines.covert import CovertChannelDetector
            self._detector = CovertChannelDetector()
        return True

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="covert_detector",
            version="2.0.0",
            description="隐蔽通道检测引擎 - ICMP/DNS 隧道 + 未知 TLS 协议",
            author="NetflowSight",
            tags=["covert", "tunnel", "icmp", "dns_tunnel"],
            priority=30,
        )

    def run(
        self,
        df: pd.DataFrame,
        context: dict[str, Any] | None = None
    ) -> list[DetectionResult]:
        return self._detector.run(df, context)


class BehaviorPluginAdapter(BaseDetectionPlugin):
    """行为异常检测引擎适配器"""

    def __init__(self, detector=None):
        super().__init__()
        self._detector = detector

    def initialize(self) -> bool:
        if self._detector is None:
            from engines.behavior import BehavioralAnomalyDetector
            self._detector = BehavioralAnomalyDetector()
        return True

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="behavior_detector",
            version="2.0.0",
            description="行为异常检测引擎 - 大流量 + 端口扫描 + 内外网通信",
            author="NetflowSight",
            tags=["behavior", "anomaly", "port_scan", "data_exfil"],
            priority=40,
        )

    def run(
        self,
        df: pd.DataFrame,
        context: dict[str, Any] | None = None
    ) -> list[DetectionResult]:
        return self._detector.run(df, context)


# ==========================================
# 适配器注册表
# ==========================================

ADAPTERS = {
    "dns": (DNSPluginAdapter, "engines.dns", "DNSThreatDetector"),
    "http": (HTTPPluginAdapter, "engines.http", "HTTPThreatDetector"),
    "covert": (CovertPluginAdapter, "engines.covert", "CovertChannelDetector"),
    "behavior": (BehaviorPluginAdapter, "engines.behavior", "BehavioralAnomalyDetector"),
}


def create_adapter(engine_type: str, detector=None) -> BaseDetectionPlugin | None:
    """
    创建检测引擎的插件适配器。

    Args:
        engine_type: 引擎类型 (dns/http/covert/behavior)
        detector: 可选的检测器实例

    Returns:
        插件实例或 None
    """
    if engine_type not in ADAPTERS:
        return None

    adapter_cls, _, _ = ADAPTERS[engine_type]
    return adapter_cls(detector)
