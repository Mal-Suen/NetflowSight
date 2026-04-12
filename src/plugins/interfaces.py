"""
Core interfaces for NetflowSight plugin system.

All detection engines, threat intel providers, and analysis plugins
must implement these interfaces to ensure compatibility.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional, Protocol

import pandas as pd

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    """Threat severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatType(str, Enum):
    """Standardized threat types aligned with MITRE ATT&CK."""
    # Initial Access
    WATERING_HOLE = "WATERING_HOLE"
    PHISHING = "PHISHING"
    EXPLOITATION = "EXPLOITATION"
    
    # Execution
    MALICIOUS_SCRIPT = "MALICIOUS_SCRIPT"
    POWERSHELL_ABUSE = "POWERSHELL_ABUSE"
    
    # Persistence
    STARTUP_ITEM = "STARTUP_ITEM"
    SCHEDULED_TASK = "SCHEDULED_TASK"
    REGISTRY_MODIFICATION = "REGISTRY_MODIFICATION"
    
    # Command and Control
    C2_BEACON = "C2_BEACON"
    C2_DATA_EXFIL = "C2_DATA_EXFIL"
    DNS_TUNNEL = "DNS_TUNNEL"
    ICMP_TUNNEL = "ICMP_TUNNEL"
    UNCOMMON_PORT = "UNCOMMON_PORT"
    UNKNOWN_TLS = "UNKNOWN_TLS"  # Added for Covert Channel detection
    
    # Discovery
    PORT_SCAN = "PORT_SCAN"
    NETWORK_SCAN = "NETWORK_SCAN"
    
    # Exfiltration
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    DNS_EXFILTRATION = "DNS_EXFILTRATION"
    HTTP_EXFILTRATION = "HTTP_EXFILTRATION"
    
    # Reputation
    MALICIOUS_IP = "MALICIOUS_IP"
    MALICIOUS_DOMAIN = "MALICIOUS_DOMAIN"
    DGA_DOMAIN = "DGA_DOMAIN"
    
    # Anomaly
    UNKNOWN_DOMAIN = "UNKNOWN_DOMAIN"
    SUSPICIOUS_USER_AGENT = "SUSPICIOUS_USER_AGENT"
    LARGE_DATA_TRANSFER = "LARGE_DATA_TRANSFER"
    SUSPICIOUS_COMMUNICATION = "SUSPICIOUS_COMMUNICATION"
    BEHAVIORAL_ANOMALY = "BEHAVIORAL_ANOMALY"
    ML_ANOMALY = "ML_ANOMALY"


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
    
    def run(self, df: pd.DataFrame, context: Optional[dict] = None) -> list[DetectionResult]:
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
    
    def check_ip(self, ip: str) -> Optional[IPReputation]:
        """Check IP reputation."""
        ...
    
    def check_domain(self, domain: str) -> Optional[DomainReputation]:
        """Check domain reputation."""
        ...
    
    def get_ioc_feed(self) -> list[IOC]:
        """Get latest IOC feed."""
        ...


@dataclass
class IPReputation:
    """Standardized IP reputation result."""
    ip: str
    threat_score: float  # 0.0 - 1.0
    source: str
    tags: list[str] = field(default_factory=list)
    country: Optional[str] = None
    isp: Optional[str] = None
    is_tor: bool = False
    is_proxy: bool = False
    is_hosting: bool = False
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    reports_count: int = 0
    raw_data: Optional[dict] = None


@dataclass
class DomainReputation:
    """Standardized domain reputation result."""
    domain: str
    threat_score: float
    source: str
    tags: list[str] = field(default_factory=list)
    category: Optional[str] = None
    is_dga: bool = False
    is_phishing: bool = False
    is_malware: bool = False
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    raw_data: Optional[dict] = None


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


class PluginBase(ABC):
    """
    Base class for all NetflowSight plugins.
    
    Provides:
    - Logging
    - Configuration management
    - Health tracking
    - Lifecycle hooks
    """
    
    def __init__(self, config: Optional[dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(f"netflowsight.plugin.{self.__class__.__name__}")
        self._health = {
            "status": "healthy",
            "last_run": None,
            "last_run_duration_ms": None,
            "error": None,
        }
    
    @abstractmethod
    def run(self, *args: Any, **kwargs: Any) -> Any:
        ...
    
    def on_load(self) -> None:
        """Called when plugin is loaded."""
        self.logger.info(f"Plugin {self.__class__.__name__} loaded")
    
    def on_unload(self) -> None:
        """Called when plugin is unloaded."""
        self.logger.info(f"Plugin {self.__class__.__name__} unloaded")
    
    def get_health(self) -> dict[str, Any]:
        """Return plugin health status."""
        return self._health.copy()
    
    def _mark_run_start(self) -> float:
        """Mark start of a run."""
        import time
        self._health["last_run"] = datetime.now().isoformat()
        self._health["error"] = None
        return time.time()
    
    def _mark_run_end(self, start_time: float, success: bool = True, error: Optional[str] = None) -> None:
        """Mark end of a run."""
        import time
        duration_ms = (time.time() - start_time) * 1000
        self._health["last_run_duration_ms"] = round(duration_ms, 2)
        if not success:
            self._health["status"] = "degraded"
            self._health["error"] = error
