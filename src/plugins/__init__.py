"""
插件系统 - 检测引擎插件化架构

提供：
- BaseDetectionPlugin: 插件基类
- PluginManager: 插件管理器
- DetectionResult: 标准化检测结果
- 内置适配器: 将现有引擎包装为插件

使用方式：
    from plugins import PluginManager

    manager = PluginManager()
    manager.load_builtin_plugins()
    manager.load_external_plugins("plugins/external/")

    results = manager.run_all(df, context)
"""

from .base import (
    BaseDetectionPlugin,
    DetectionResult,
    PluginMetadata,
    PluginError,
    PluginLoadError,
    PluginConfigError,
)
from .manager import PluginManager, PluginInfo
from .adapters import (
    DNSPluginAdapter,
    HTTPPluginAdapter,
    CovertPluginAdapter,
    BehaviorPluginAdapter,
    create_adapter,
)

__all__ = [
    # 基类
    "BaseDetectionPlugin",
    "DetectionResult",
    "PluginMetadata",
    # 管理器
    "PluginManager",
    "PluginInfo",
    # 适配器
    "DNSPluginAdapter",
    "HTTPPluginAdapter",
    "CovertPluginAdapter",
    "BehaviorPluginAdapter",
    "create_adapter",
    # 异常
    "PluginError",
    "PluginLoadError",
    "PluginConfigError",
]
