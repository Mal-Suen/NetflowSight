"""核心模块 - 配置、模型、解析器和接口"""

from .parser import FlowStreamAnalyzer
from .models import FlowRecord, AnalysisResult, Severity, ThreatType, IPReputation
from .config import settings
from .interfaces import DetectionEngine, DetectionResult, ThreatIntelProvider, DomainReputation, IOC

__all__ = [
    "FlowStreamAnalyzer",
    "FlowRecord",
    "AnalysisResult",
    "Severity",
    "ThreatType",
    "IPReputation",
    "settings",
    "DetectionEngine",
    "DetectionResult",
    "ThreatIntelProvider",
    "DomainReputation",
    "IOC",
]
