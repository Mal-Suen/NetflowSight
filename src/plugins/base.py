"""
插件系统基类和接口

所有检测插件必须继承 BaseDetectionPlugin 并实现 run() 方法。
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

import pandas as pd

from core.models import Severity, ThreatType

logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    """
    标准化检测结果。

    所有插件必须返回此格式的结果列表。
    """
    engine_name: str
    engine_version: str
    threat_type: ThreatType
    severity: Severity
    description: str
    evidence: dict[str, Any]
    confidence: float  # 0.0 - 1.0
    ioc: list[str] = field(default_factory=list)
    mitre_technique: str = ""
    recommended_action: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict[str, Any]:
        """转换为字典用于 JSON 序列化"""
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


@dataclass
class PluginMetadata:
    """插件元数据"""
    name: str
    version: str
    description: str
    author: str = ""
    tags: list[str] = field(default_factory=list)
    priority: int = 100  # 执行优先级，数字越小越先执行
    enabled: bool = True
    requires: list[str] = field(default_factory=list)  # 依赖的其他插件


class BaseDetectionPlugin(ABC):
    """
    检测插件基类。

    所有检测插件必须继承此类并实现以下方法：
    - run(): 执行检测逻辑
    - get_metadata(): 返回插件元数据

    可选覆盖：
    - initialize(): 初始化插件
    - cleanup(): 清理资源
    - health_check(): 健康检查
    - set_config(): 动态配置
    """

    def __init__(self, config: Optional[dict[str, Any]] = None):
        self._config = config or {}
        self._initialized = False
        self._last_run_time: Optional[float] = None
        self._last_run_duration_ms: float = 0.0
        self._total_detections: int = 0
        self._error: Optional[str] = None

    @abstractmethod
    def run(
        self,
        df: pd.DataFrame,
        context: Optional[dict[str, Any]] = None
    ) -> list[DetectionResult]:
        """
        执行检测逻辑。

        Args:
            df: NFStream 解析的流量 DataFrame
            context: 可选的上下文信息，包含：
                - safe_domains: 安全域名集合
                - threat_domains: 威胁域名集合
                - threat_ips: 威胁 IP 集合
                - datasource_manager: 数据源管理器实例
                - config: 全局配置

        Returns:
            检测结果列表
        """
        pass

    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """返回插件元数据"""
        pass

    def initialize(self) -> bool:
        """
        初始化插件。

        Returns:
            初始化是否成功
        """
        self._initialized = True
        return True

    def cleanup(self) -> None:
        """清理资源"""
        self._initialized = False

    def health_check(self) -> dict[str, Any]:
        """
        健康检查。

        Returns:
            健康状态字典
        """
        status = "healthy"
        if self._error:
            status = "unhealthy"
        elif not self._initialized:
            status = "degraded"

        return {
            "status": status,
            "last_run": self._last_run_time,
            "last_run_duration_ms": self._last_run_duration_ms,
            "detections_count": self._total_detections,
            "error": self._error,
        }

    def get_config(self) -> dict[str, Any]:
        """获取当前配置"""
        return self._config.copy()

    def set_config(self, config: dict[str, Any]) -> None:
        """更新配置"""
        self._config.update(config)

    @property
    def name(self) -> str:
        """插件名称"""
        return self.get_metadata().name

    @property
    def version(self) -> str:
        """插件版本"""
        return self.get_metadata().version

    @property
    def enabled(self) -> bool:
        """是否启用"""
        return self.get_metadata().enabled and self._initialized

    def _record_run(self, duration_ms: float, detections: int, error: Optional[str] = None):
        """记录运行统计"""
        self._last_run_time = datetime.now().isoformat()
        self._last_run_duration_ms = duration_ms
        self._total_detections += detections
        self._error = error


class PluginError(Exception):
    """插件相关错误"""
    pass


class PluginLoadError(PluginError):
    """插件加载错误"""
    pass


class PluginConfigError(PluginError):
    """插件配置错误"""
    pass
