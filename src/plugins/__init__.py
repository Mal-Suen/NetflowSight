"""
NetflowSight Plugin System - Core Interfaces

This module defines the base interfaces for all detection engines,
threat intelligence providers, and analysis plugins.
"""

from .interfaces import (
    DetectionEngine,
    DetectionResult,
    ThreatIntelProvider,
    IPReputation,
    DomainReputation,
    IOC,
    Severity,
    ThreatType,
)

__all__ = [
    "DetectionEngine",
    "DetectionResult",
    "ThreatIntelProvider",
    "IPReputation",
    "DomainReputation",
    "IOC",
    "Severity",
    "ThreatType",
]
