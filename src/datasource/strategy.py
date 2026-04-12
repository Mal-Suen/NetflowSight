"""
Strategy Recommender for Data Sources

Automatically detects source characteristics and recommends
the optimal update strategy.
"""

from __future__ import annotations

import logging
import time
from enum import Enum
from typing import Any, Optional, TYPE_CHECKING
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

logger = logging.getLogger(__name__)


class UpdateStrategy(str, Enum):
    """Update strategies for data sources."""
    FULL = "full"
    ETAG_CHECK = "etag_check"
    TIME_WINDOW = "time_window"
    API_INCREMENTAL = "api_incremental"
    DIFFERENTIAL = "differential"


if TYPE_CHECKING:
    from .manager import DataSource


class StrategyScore:
    """Scoring result for a strategy."""
    
    def __init__(self, strategy: UpdateStrategy, score: float, reasons: list[str]):
        self.strategy = strategy
        self.score = score
        self.reasons = reasons
    
    def __repr__(self):
        return f"{self.strategy.value}: {self.score:.1f} ({', '.join(self.reasons)})"


class StrategyRecommender:
    """
    Automatically recommends the best update strategy for a data source
    based on detected characteristics.
    
    Detection factors:
    1. ETag support (HTTP response headers)
    2. Data size (Content-Length)
    3. Update frequency (inferred or configured)
    4. Incremental endpoint availability
    5. Historical performance
    """
    
    # Scoring weights
    WEIGHTS = {
        "etag_support": 5.0,
        "small_size": 3.0,
        "large_size": -2.0,
        "low_frequency": 2.0,
        "high_frequency": 4.0,
        "incremental_endpoint": 5.0,
        "historical_etag_hit_rate": 3.0,
        "historical_failure_rate": -4.0,
    }
    
    def __init__(self):
        self._history: dict[str, list[dict]] = {}
    
    def record_update(self, source_name: str, result: dict) -> None:
        """
        Record update result for historical analysis.
        
        result should contain:
        - success: bool
        - etag_hit: bool (whether 304 was returned)
        - bytes_downloaded: int
        - duration_ms: float
        - strategy_used: str
        """
        if source_name not in self._history:
            self._history[source_name] = []
        
        self._history[source_name].append({
            **result,
            "timestamp": time.time(),
        })
        
        # Keep only last 100 updates
        if len(self._history[source_name]) > 100:
            self._history[source_name] = self._history[source_name][-100:]
    
    def recommend(self, source: DataSource) -> tuple[UpdateStrategy, list[str]]:
        """
        Recommend the best update strategy for a source.
        
        Returns:
            (recommended_strategy, list_of_reasons)
        """
        # Score all strategies
        scores: dict[UpdateStrategy, float] = {
            UpdateStrategy.ETAG_CHECK: 0.0,
            UpdateStrategy.TIME_WINDOW: 0.0,
            UpdateStrategy.FULL: 0.0,
        }
        reasons: dict[UpdateStrategy, list[str]] = {s: [] for s in scores}
        
        # Factor 1: Detect ETag support
        etag_supported = self._detect_etag_support(source)
        if etag_supported:
            scores[UpdateStrategy.ETAG_CHECK] += self.WEIGHTS["etag_support"]
            reasons[UpdateStrategy.ETAG_CHECK].append("Server supports ETag")
        
        # Factor 2: Data size
        size_mb = self._detect_content_size(source)
        if size_mb is not None:
            if size_mb < 1.0:
                scores[UpdateStrategy.ETAG_CHECK] += self.WEIGHTS["small_size"]
                reasons[UpdateStrategy.ETAG_CHECK].append(f"Small file ({size_mb:.1f}MB)")
            elif size_mb > 10.0:
                scores[UpdateStrategy.TIME_WINDOW] += self.WEIGHTS["large_size"] * -1
                scores[UpdateStrategy.FULL] += self.WEIGHTS["large_size"] * -1
                reasons[UpdateStrategy.TIME_WINDOW].append(f"Large file ({size_mb:.1f}MB), incremental preferred")
        
        # Factor 3: Update frequency
        freq = source.update_interval_hours
        if freq <= 1:
            scores[UpdateStrategy.TIME_WINDOW] += self.WEIGHTS["high_frequency"]
            reasons[UpdateStrategy.TIME_WINDOW].append("High update frequency")
        elif freq >= 168:  # Weekly or less
            scores[UpdateStrategy.ETAG_CHECK] += self.WEIGHTS["low_frequency"]
            reasons[UpdateStrategy.ETAG_CHECK].append("Low update frequency")
        
        # Factor 4: Incremental endpoint
        if source.incremental_url_template:
            scores[UpdateStrategy.TIME_WINDOW] += self.WEIGHTS["incremental_endpoint"]
            reasons[UpdateStrategy.TIME_WINDOW].append("Incremental endpoint configured")
        
        # Factor 5: Historical performance
        history = self._history.get(source.name, [])
        if history:
            etag_hits = sum(1 for h in history if h.get("etag_hit", False))
            hit_rate = etag_hits / len(history) if history else 0
            
            if hit_rate > 0.7:
                scores[UpdateStrategy.ETAG_CHECK] += self.WEIGHTS["historical_etag_hit_rate"]
                reasons[UpdateStrategy.ETAG_CHECK].append(f"High ETag hit rate ({hit_rate:.0%})")
            
            failures = sum(1 for h in history if not h.get("success", True))
            failure_rate = failures / len(history) if history else 0
            
            if failure_rate > 0.3:
                current_strategy = UpdateStrategy(source.update_strategy) if source.update_strategy else UpdateStrategy.FULL
                scores[current_strategy] += self.WEIGHTS["historical_failure_rate"]
                reasons[current_strategy].append(f"High failure rate ({failure_rate:.0%}), consider changing strategy")
        
        # Find best strategy
        best_strategy = max(scores, key=scores.get)
        best_reasons = reasons[best_strategy]
        
        # If no specific reasons, add default explanation
        if not best_reasons:
            if best_strategy == UpdateStrategy.ETAG_CHECK:
                best_reasons.append("Default: assumes ETag support")
            elif best_strategy == UpdateStrategy.TIME_WINDOW:
                best_reasons.append("Default: prefers incremental updates")
            else:
                best_reasons.append("Default: full update fallback")
        
        return best_strategy, best_reasons
    
    def detect_all(self, sources: dict[str, "DataSource"]) -> dict[str, dict]:
        """
        Detect characteristics and recommend strategies for all sources.
        """
        results = {}
        
        for name, source in sources.items():
            # Skip remote detection for generated sources, but still provide recommendation
            if source.source_type.value == "generated":
                results[name] = {
                    "recommended_strategy": source.update_strategy.value,
                    "reasons": ["Built-in source, uses default strategy"],
                    "characteristics": {
                        "etag_supported": False,
                        "size_mb": 0,
                        "update_interval_hours": source.update_interval_hours,
                        "has_incremental_url": False,
                        "historical_updates": 0,
                        "is_builtin": True,
                    }
                }
                continue
            
            strategy, reasons = self.recommend(source)
            characteristics = self._detect_characteristics(source)
            
            results[name] = {
                "recommended_strategy": strategy.value,
                "reasons": reasons,
                "characteristics": characteristics,
            }
        
        return results
    
    def _detect_etag_support(self, source: DataSource) -> bool:
        """Probe server to check if it supports ETag."""
        if source.source_type != DataSource.REMOTE_URL:
            return False
        
        try:
            req = Request(source.url_or_path, method="HEAD")
            req.add_header("User-Agent", "NetflowSight/1.0.0 (Strategy Detector)")
            
            with urlopen(req, timeout=10) as response:
                etag = response.headers.get("ETag")
                last_modified = response.headers.get("Last-Modified")
                return etag is not None or last_modified is not None
        except Exception as e:
            logger.debug(f"ETag detection failed for {source.name}: {e}")
            return False
    
    def _detect_content_size(self, source: DataSource) -> Optional[float]:
        """Detect content size in MB."""
        if source.source_type != DataSource.REMOTE_URL:
            return None
        
        try:
            req = Request(source.url_or_path, method="HEAD")
            req.add_header("User-Agent", "NetflowSight/1.0.0 (Strategy Detector)")
            
            with urlopen(req, timeout=10) as response:
                content_length = response.headers.get("Content-Length")
                if content_length:
                    return int(content_length) / (1024 * 1024)
        except Exception as e:
            logger.debug(f"Content size detection failed for {source.name}: {e}")
        
        return None
    
    def _detect_characteristics(self, source: DataSource) -> dict[str, Any]:
        """Detect all characteristics of a source."""
        return {
            "etag_supported": self._detect_etag_support(source),
            "size_mb": self._detect_content_size(source),
            "update_interval_hours": source.update_interval_hours,
            "has_incremental_url": bool(source.incremental_url_template),
            "historical_updates": len(self._history.get(source.name, [])),
        }
    
    def apply_recommendations(self, manager: "DataSourceManager") -> dict[str, bool]:
        changed = {}
        recommendations = self.detect_all(manager._sources)
        
        for name, info in recommendations.items():
            source = manager._sources.get(name)
            if not source:
                continue
            
            recommended = UpdateStrategy(info["recommended_strategy"])
            if source.update_strategy != recommended:
                old_strategy = source.update_strategy
                source.update_strategy = recommended
                changed[name] = True
                logger.info(
                    f"Strategy changed for {name}: "
                    f"{old_strategy.value} → {recommended.value} "
                    f"({', '.join(info['reasons'])})"
                )
            else:
                changed[name] = False
        
        return changed
