"""
Core interfaces for NetflowSight plugin system.

All detection engines, threat intel providers, and analysis plugins
must implement these interfaces to ensure compatibility.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

import pandas as pd

# Re-export canonical enums and models from core.models to avoid duplication
from core.models import IPReputation, Severity, ThreatType

logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    """
    Standardized detection result from any engine.

    This ensures all engines return consistent, actionable data.
    """
    engine_name: str
    engine_version: str
    threat_type: ThreatType
    severity: Severity
    description: str
    evidence: dict[str, Any]
    confidence: float  # 0.0 - 1.0
    ioc: list[str] = field(default_factory=list)  # Extracted IOCs
    mitre_technique: str = ""  # MITRE ATT&CK technique ID (e.g., "T1071.004")
    recommended_action: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "engine_name": self.engine_name,
            "engine_version": self.engine_version,
            "threat_type": self.threat_type.value,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "confidence": round(self.confidence, 3),
            "ioc": self.ioc,
            "mitre_technique": self.mitre_technique,
            "recommended_action": self.recommended_action,
            "timestamp": self.timestamp,
        }


class DetectionEngine(Protocol):
    """
    Protocol that all detection engines must implement.

    This enables:
    - Standardized execution
    - Hot-reloading
    - Dynamic configuration
    - Health monitoring
    """

    # Engine metadata
    name: str
    version: str
    description: str
    enabled: bool

    def run(self, df: pd.DataFrame, context: dict | None = None) -> list[DetectionResult]:
        """
        Run detection against flow data.

        Args:
            df: DataFrame with flow records from NFStream
            context: Optional context (baseline, config, etc.)

        Returns:
            List of standardized detection results
        """
        ...

    def get_config(self) -> dict[str, Any]:
        """Return current engine configuration."""
        ...

    def set_config(self, config: dict[str, Any]) -> None:
        """Update engine configuration dynamically."""
        ...

    def health_check(self) -> dict[str, Any]:
        """
        Return engine health status.

        Returns:
            {
                "status": "healthy" | "degraded" | "unhealthy",
                "last_run": "2025-06-13T15:34:00",
                "last_run_duration_ms": 123.4,
                "detections_count": 15,
                "error": null
            }
        """
        ...


class ThreatIntelProvider(Protocol):
    """
    Protocol that all threat intelligence providers must implement.

    This enables multi-source threat intel fusion.
    """

    name: str
    cost_tier: str  # "free", "freemium", "paid"
    rate_limit: int  # requests per minute

    def check_ip(self, ip: str) -> IPReputation | None:
        """Check IP reputation."""
        ...

    def check_domain(self, domain: str) -> DomainReputation | None:
        """Check domain reputation."""
        ...

    def get_ioc_feed(self) -> list[IOC]:
        """Get latest IOC feed."""
        ...


@dataclass
class DomainReputation:
    """Standardized domain reputation result."""
    domain: str
    threat_score: float
    source: str
    tags: list[str] = field(default_factory=list)
    category: str | None = None
    is_dga: bool = False
    is_phishing: bool = False
    is_malware: bool = False
    first_seen: str | None = None
    last_seen: str | None = None
    raw_data: dict | None = None


@dataclass
class IOC:
    """Indicator of Compromise."""
    type: str  # "ip", "domain", "url", "hash", "email"
    value: str
    threat_type: str
    severity: str
    source: str
    confidence: float
    first_seen: str
    last_seen: str
    tags: list[str] = field(default_factory=list)
