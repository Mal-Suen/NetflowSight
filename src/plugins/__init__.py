"""插件系统 - 从 core.interfaces 导出接口"""

from core.interfaces import (
    DetectionEngine,
    DetectionResult,
    ThreatIntelProvider,
    DomainReputation,
    IOC,
    Severity,
    ThreatType,
)

__all__ = [
    "DetectionEngine",
    "DetectionResult",
    "ThreatIntelProvider",
    "DomainReputation",
    "IOC",
    "Severity",
    "ThreatType",
]
