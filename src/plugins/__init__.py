"""
NetflowSight Plugin System - Core Interfaces

This module defines the base interfaces for all detection engines,
threat intelligence providers, and analysis plugins.
"""

from .interfaces import (
    DetectionEngine,
    DetectionResult,
    ThreatIntelProvider,
    PluginBase,
    IPReputation,
    DomainReputation,
    IOC,
    Severity,
    ThreatType,
)
from .registry import EngineRegistry, PluginManager

__all__ = [
    "DetectionEngine",
    "DetectionResult",
    "ThreatIntelProvider",
    "PluginBase",
    "IPReputation",
    "DomainReputation",
    "IOC",
    "Severity",
    "ThreatType",
    "EngineRegistry",
    "PluginManager",
]
