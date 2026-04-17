"""核心模块 - 配置、模型、解析器和接口"""

from .config import settings
from .interfaces import IOC, DetectionEngine, DetectionResult, DomainReputation, ThreatIntelProvider
from .models import (
    AnalysisResult,
    FlowRecord,
    IPReputation,
    Severity,
    ThreatAlert,
    ThreatFinding,
    ThreatType,
)
from .parser import FlowStreamAnalyzer

__all__ = [
    "FlowStreamAnalyzer",
    "FlowRecord",
    "AnalysisResult",
    "Severity",
    "ThreatType",
    "IPReputation",
    "ThreatAlert",
    "ThreatFinding",
    "settings",
    "DetectionEngine",
    "DetectionResult",
    "ThreatIntelProvider",
    "DomainReputation",
    "IOC",
]
