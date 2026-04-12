"""
Engine Registry - Manages detection engines lifecycle.

Supports:
- Registration/deregistration
- Batch execution
- Dynamic enable/disable
- Health monitoring
- Hot-reloading from plugin directory
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import time
from pathlib import Path
from typing import Any, Optional, Type

import pandas as pd
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .interfaces import DetectionEngine, DetectionResult

logger = logging.getLogger(__name__)


class EngineRegistry:
    """
    Central registry for all detection engines.
    
    Usage:
        registry = EngineRegistry()
        registry.register(DNSEngine())
        registry.register(HTTPEngine())
        
        results = registry.run_all(df, context={"baseline": baseline})
    """
    
    def __init__(self):
        self._engines: dict[str, DetectionEngine] = {}
        self._disabled: set[str] = set()
        self._execution_stats: dict[str, dict] = {}
        self._plugin_dir: Optional[Path] = None
        self._observer: Optional[Observer] = None
    
    def register(self, engine: DetectionEngine) -> None:
        """Register a detection engine."""
        if not hasattr(engine, "name"):
            raise ValueError(f"Engine {engine.__class__.__name__} must have 'name' attribute")
        
        name = engine.name
        self._engines[name] = engine
        self._execution_stats[name] = {
            "runs": 0,
            "total_duration_ms": 0,
            "detections": 0,
            "last_error": None,
        }
        logger.info(f"Registered engine: {name} v{getattr(engine, 'version', '1.0.0')}")
    
    def deregister(self, name: str) -> bool:
        """Deregister an engine by name."""
        if name in self._engines:
            engine = self._engines.pop(name)
            if hasattr(engine, "on_unload"):
                engine.on_unload()
            self._execution_stats.pop(name, None)
            self._disabled.discard(name)
            logger.info(f"Deregistered engine: {name}")
            return True
        return False
    
    def enable(self, name: str) -> bool:
        """Enable a disabled engine."""
        if name in self._engines:
            self._disabled.discard(name)
            self._engines[name].enabled = True
            return True
        return False
    
    def disable(self, name: str) -> bool:
        """Disable an engine without removing it."""
        if name in self._engines:
            self._disabled.add(name)
            self._engines[name].enabled = False
            return True
        return False
    
    def get(self, name: str) -> Optional[DetectionEngine]:
        """Get engine by name."""
        return self._engines.get(name)
    
    def list_engines(self) -> list[dict[str, Any]]:
        """List all registered engines with status."""
        return [
            {
                "name": name,
                "version": getattr(engine, "version", "1.0.0"),
                "description": getattr(engine, "description", ""),
                "enabled": name not in self._disabled and getattr(engine, "enabled", True),
                "health": engine.health_check() if hasattr(engine, "health_check") else {},
                "stats": self._execution_stats.get(name, {}),
            }
            for name, engine in self._engines.items()
        ]
    
    def run_all(
        self,
        df: pd.DataFrame,
        context: Optional[dict] = None,
        engine_filter: Optional[list[str]] = None,
    ) -> list[DetectionResult]:
        """
        Run all enabled engines against flow data.
        
        Args:
            df: Flow records DataFrame
            context: Optional context for engines
            engine_filter: Optional list of engine names to run (if None, run all enabled)
            
        Returns:
            Combined list of detection results from all engines
        """
        all_results = []
        context = context or {}
        
        engines_to_run = engine_filter or [
            name for name in self._engines
            if name not in self._disabled and getattr(self._engines[name], "enabled", True)
        ]
        
        for name in engines_to_run:
            if name not in self._engines:
                logger.warning(f"Engine '{name}' not found, skipping")
                continue
            
            engine = self._engines[name]
            start = self._mark_engine_start(name)
            
            try:
                results = engine.run(df, context)
                self._mark_engine_success(name, start, len(results))
                all_results.extend(results)
            except Exception as e:
                self._mark_engine_failure(name, start, str(e))
                logger.error(f"Engine '{name}' failed: {e}", exc_info=True)
        
        logger.info(
            f"Ran {len(engines_to_run)} engines, "
            f"found {len(all_results)} total detections"
        )
        return all_results
    
    def run_by_severity(
        self,
        df: pd.DataFrame,
        severities: list[str],
        context: Optional[dict] = None,
    ) -> list[DetectionResult]:
        """Run only engines that match specified severities."""
        # This would require engines to declare what severities they produce
        # For now, run all and filter results
        all_results = self.run_all(df, context)
        return [r for r in all_results if r.severity.value in severities]
    
    def _mark_engine_start(self, name: str) -> float:
        """Mark engine execution start."""
        return time.time()
    
    def _mark_engine_success(self, name: str, start: float, detections: int) -> None:
        """Mark engine execution success."""
        duration_ms = (time.time() - start) * 1000
        stats = self._execution_stats[name]
        stats["runs"] += 1
        stats["total_duration_ms"] += duration_ms
        stats["detections"] += detections
        stats["last_error"] = None
    
    def _mark_engine_failure(self, name: str, start: float, error: str) -> None:
        """Mark engine execution failure."""
        duration_ms = (time.time() - start) * 1000
        stats = self._execution_stats[name]
        stats["runs"] += 1
        stats["total_duration_ms"] += duration_ms
        stats["last_error"] = error
    
    def enable_hot_reload(self, plugin_dir: str) -> None:
        """
        Enable hot-reloading of engines from plugin directory.
        
        Any .py file in the directory that implements DetectionEngine
        will be automatically loaded/reloaded on change.
        """
        self._plugin_dir = Path(plugin_dir)
        self._plugin_dir.mkdir(parents=True, exist_ok=True)
        
        # Load initial plugins
        self._load_plugins_from_dir()
        
        # Set up file watcher
        handler = _PluginReloadHandler(self)
        self._observer = Observer()
        self._observer.schedule(handler, str(self._plugin_dir), recursive=False)
        self._observer.start()
        logger.info(f"Hot-reload enabled for plugin directory: {plugin_dir}")
    
    def _load_plugins_from_dir(self) -> int:
        """Load all plugins from directory. Returns count loaded."""
        if not self._plugin_dir:
            return 0
        
        loaded = 0
        for py_file in self._plugin_dir.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            
            try:
                self._load_single_plugin(py_file)
                loaded += 1
            except Exception as e:
                logger.error(f"Failed to load plugin {py_file.name}: {e}")
        
        return loaded
    
    def _load_single_plugin(self, py_file: Path) -> None:
        """Load a single plugin file."""
        module_name = f"netflowsight.plugins.external.{py_file.stem}"
        
        spec = importlib.util.spec_from_file_location(module_name, py_file)
        if not spec or not spec.loader:
            raise ImportError(f"Cannot create spec for {py_file}")
        
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        # Find engine classes in module
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and hasattr(attr, "name")
                and hasattr(attr, "run")
                and attr is not DetectionEngine
            ):
                engine = attr()
                self.register(engine)
    
    def get_stats(self) -> dict[str, Any]:
        """Get execution statistics for all engines."""
        return {
            "total_engines": len(self._engines),
            "enabled_engines": len(self._engines) - len(self._disabled),
            "disabled_engines": list(self._disabled),
            "engine_stats": self._execution_stats.copy(),
        }
    
    def shutdown(self) -> None:
        """Shutdown registry and cleanup."""
        if self._observer:
            self._observer.stop()
            self._observer.join()
        
        for name in list(self._engines.keys()):
            self.deregister(name)
        
        logger.info("EngineRegistry shut down")


class _PluginReloadHandler(FileSystemEventHandler):
    """File system event handler for plugin hot-reloading."""
    
    def __init__(self, registry: EngineRegistry):
        self.registry = registry
        self._debounce: dict[str, float] = {}
    
    def on_modified(self, event):
        if event.is_directory:
            return
        if not event.src_path.endswith(".py"):
            return
        
        # Debounce (avoid reloading multiple times for same change)
        import time
        now = time.time()
        if event.src_path in self._debounce:
            if now - self._debounce[event.src_path] < 1.0:
                return
        self._debounce[event.src_path] = now
        
        logger.info(f"Plugin file changed: {event.src_path}")
        # In a full implementation, we'd unload the old module and reload
        # For now, log the change (reloading is complex with Python modules)


class PluginManager:
    """
    High-level plugin manager for end users.
    
    Provides simple interface to:
    - Load default engines
    - Load custom engines
    - Run detection pipeline
    """
    
    def __init__(self):
        self.registry = EngineRegistry()
    
    def load_default_engines(self) -> None:
        """Load all built-in detection engines."""
        # Import and register default engines
        from netflowsight.engines.dns.dns_detector import DNSThreatDetector
        from netflowsight.engines.http.http_detector import HTTPThreatDetector
        from netflowsight.engines.covert.covert_detector import CovertChannelDetector
        from netflowsight.engines.behavior.behavior_detector import BehavioralAnomalyDetector
        
        self.registry.register(DNSThreatDetector())
        self.registry.register(HTTPThreatDetector())
        self.registry.register(CovertChannelDetector())
        self.registry.register(BehavioralAnomalyDetector())
        
        logger.info(f"Loaded {len(self.registry.list_engines())} default engines")
    
    def run_analysis(
        self,
        df: pd.DataFrame,
        context: Optional[dict] = None,
        engines: Optional[list[str]] = None,
    ) -> list[DetectionResult]:
        """
        Run detection analysis.
        
        Args:
            df: Flow records
            context: Optional context
            engines: Optional list of specific engines to run
            
        Returns:
            List of detection results
        """
        return self.registry.run_all(df, context, engine_filter=engines)
    
    def get_engine_status(self) -> list[dict]:
        """Get status of all registered engines."""
        return self.registry.list_engines()
    
    def enable_engine(self, name: str) -> bool:
        """Enable a specific engine."""
        return self.registry.enable(name)
    
    def disable_engine(self, name: str) -> bool:
        """Disable a specific engine."""
        return self.registry.disable(name)
