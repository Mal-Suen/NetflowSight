"""
插件管理器 - 负责插件的加载、注册、执行和生命周期管理

支持：
- 内置插件（engines/ 目录）
- 外部插件（plugins/external/ 目录）
- 动态加载 Python 模块
- 插件依赖解析
- 插件热重载
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Type

import pandas as pd

from .base import (
    BaseDetectionPlugin,
    DetectionResult,
    PluginMetadata,
    PluginError,
    PluginLoadError,
)

logger = logging.getLogger(__name__)


@dataclass
class PluginInfo:
    """插件注册信息"""
    plugin: BaseDetectionPlugin
    metadata: PluginMetadata
    module_path: Optional[str] = None
    loaded_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))
    enabled: bool = True


class PluginManager:
    """
    插件管理器。

    使用方式：
        manager = PluginManager()

        # 加载内置插件
        manager.load_builtin_plugins()

        # 加载外部插件
        manager.load_external_plugins("plugins/external/")

        # 执行所有插件
        results = manager.run_all(df, context)

        # 获取特定插件
        dns_plugin = manager.get_plugin("dns_detector")
    """

    def __init__(self, config: Optional[dict[str, Any]] = None):
        self._plugins: dict[str, PluginInfo] = {}
        self._config = config or {}
        self._execution_order: list[str] = []

    # ==========================================
    # 插件注册
    # ==========================================

    def register(self, plugin: BaseDetectionPlugin) -> str:
        """
        注册插件。

        Args:
            plugin: 插件实例

        Returns:
            插件名称

        Raises:
            PluginLoadError: 注册失败
        """
        metadata = plugin.get_metadata()
        name = metadata.name

        if name in self._plugins:
            logger.warning(f"插件 {name} 已存在，将被覆盖")

        # 初始化插件
        try:
            if not plugin.initialize():
                raise PluginLoadError(f"插件 {name} 初始化失败")
        except Exception as e:
            raise PluginLoadError(f"插件 {name} 初始化异常: {e}")

        # 注册插件
        self._plugins[name] = PluginInfo(
            plugin=plugin,
            metadata=metadata,
            enabled=metadata.enabled,
        )

        # 更新执行顺序
        self._update_execution_order()

        logger.info(f"注册插件: {name} v{metadata.version} (priority={metadata.priority})")
        return name

    def unregister(self, name: str) -> bool:
        """注销插件"""
        if name not in self._plugins:
            return False

        info = self._plugins[name]
        info.plugin.cleanup()
        del self._plugins[name]
        self._update_execution_order()

        logger.info(f"注销插件: {name}")
        return True

    # ==========================================
    # 插件加载
    # ==========================================

    def load_builtin_plugins(self) -> list[str]:
        """
        加载内置插件（engines/ 目录）。

        Returns:
            加载成功的插件名称列表
        """
        loaded = []

        # DNS 检测插件
        try:
            from engines.dns import DNSThreatDetector
            from .adapters import DNSPluginAdapter
            detector = DNSThreatDetector()
            plugin = DNSPluginAdapter(detector)
            self.register(plugin)
            loaded.append(plugin.name)
        except Exception as e:
            logger.error(f"加载 DNS 插件失败: {e}")

        # HTTP 检测插件
        try:
            from engines.http import HTTPThreatDetector
            from .adapters import HTTPPluginAdapter
            detector = HTTPThreatDetector()
            plugin = HTTPPluginAdapter(detector)
            self.register(plugin)
            loaded.append(plugin.name)
        except Exception as e:
            logger.error(f"加载 HTTP 插件失败: {e}")

        # 隐蔽通道检测插件
        try:
            from engines.covert import CovertChannelDetector
            from .adapters import CovertPluginAdapter
            detector = CovertChannelDetector()
            plugin = CovertPluginAdapter(detector)
            self.register(plugin)
            loaded.append(plugin.name)
        except Exception as e:
            logger.error(f"加载隐蔽通道插件失败: {e}")

        # 行为异常检测插件
        try:
            from engines.behavior import BehavioralAnomalyDetector
            from .adapters import BehaviorPluginAdapter
            detector = BehavioralAnomalyDetector()
            plugin = BehaviorPluginAdapter(detector)
            self.register(plugin)
            loaded.append(plugin.name)
        except Exception as e:
            logger.error(f"加载行为异常插件失败: {e}")

        logger.info(f"加载内置插件: {len(loaded)} 个")
        return loaded

    def load_external_plugins(self, plugin_dir: str) -> list[str]:
        """
        加载外部插件目录。

        Args:
            plugin_dir: 插件目录路径

        Returns:
            加载成功的插件名称列表
        """
        plugin_path = Path(plugin_dir)
        if not plugin_path.exists():
            logger.warning(f"插件目录不存在: {plugin_dir}")
            return []

        loaded = []
        for py_file in plugin_path.glob("*.py"):
            if py_file.name.startswith("_"):
                continue

            try:
                plugin = self._load_plugin_from_file(py_file)
                if plugin:
                    self.register(plugin)
                    loaded.append(plugin.name)
            except Exception as e:
                logger.error(f"加载插件文件 {py_file} 失败: {e}")

        logger.info(f"加载外部插件: {len(loaded)} 个")
        return loaded

    def load_plugin_from_module(self, module_name: str) -> Optional[str]:
        """
        从 Python 模块加载插件。

        模块必须定义一个 get_plugin() 函数返回插件实例。

        Args:
            module_name: 模块名（如 "plugins.external.my_plugin"）

        Returns:
            插件名称或 None
        """
        try:
            module = importlib.import_module(module_name)
            if hasattr(module, "get_plugin"):
                plugin = module.get_plugin()
                return self.register(plugin)
            else:
                logger.error(f"模块 {module_name} 缺少 get_plugin() 函数")
                return None
        except Exception as e:
            logger.error(f"加载模块 {module_name} 失败: {e}")
            return None

    def _load_plugin_from_file(self, file_path: Path) -> Optional[BaseDetectionPlugin]:
        """从文件加载插件"""
        spec = importlib.util.spec_from_file_location(file_path.stem, file_path)
        if not spec or not spec.loader:
            return None

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        if hasattr(module, "get_plugin"):
            return module.get_plugin()
        return None

    # ==========================================
    # 插件执行
    # ==========================================

    def run_all(
        self,
        df: pd.DataFrame,
        context: Optional[dict[str, Any]] = None
    ) -> list[DetectionResult]:
        """
        执行所有已启用的插件。

        Args:
            df: 流量 DataFrame
            context: 上下文信息

        Returns:
            所有检测结果
        """
        all_results = []
        context = context or {}

        for name in self._execution_order:
            info = self._plugins.get(name)
            if not info or not info.enabled:
                continue

            try:
                results = self.run_plugin(name, df, context)
                all_results.extend(results)
            except Exception as e:
                logger.error(f"执行插件 {name} 失败: {e}")
                traceback.print_exc()

        return all_results

    def run_plugin(
        self,
        name: str,
        df: pd.DataFrame,
        context: Optional[dict[str, Any]] = None
    ) -> list[DetectionResult]:
        """
        执行单个插件。

        Args:
            name: 插件名称
            df: 流量 DataFrame
            context: 上下文信息

        Returns:
            检测结果
        """
        info = self._plugins.get(name)
        if not info:
            raise PluginError(f"插件不存在: {name}")

        if not info.enabled:
            return []

        start_time = time.time()
        try:
            results = info.plugin.run(df, context)
            duration_ms = (time.time() - start_time) * 1000
            info.plugin._record_run(duration_ms, len(results))
            return results
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            info.plugin._record_run(duration_ms, 0, str(e))
            raise

    # ==========================================
    # 插件管理
    # ==========================================

    def get_plugin(self, name: str) -> Optional[BaseDetectionPlugin]:
        """获取插件实例"""
        info = self._plugins.get(name)
        return info.plugin if info else None

    def get_plugin_info(self, name: str) -> Optional[PluginInfo]:
        """获取插件信息"""
        return self._plugins.get(name)

    def list_plugins(self) -> list[dict[str, Any]]:
        """列出所有插件"""
        return [
            {
                "name": info.metadata.name,
                "version": info.metadata.version,
                "description": info.metadata.description,
                "priority": info.metadata.priority,
                "enabled": info.enabled,
                "health": info.plugin.health_check(),
            }
            for info in self._plugins.values()
        ]

    def enable_plugin(self, name: str) -> bool:
        """启用插件"""
        info = self._plugins.get(name)
        if info:
            info.enabled = True
            return True
        return False

    def disable_plugin(self, name: str) -> bool:
        """禁用插件"""
        info = self._plugins.get(name)
        if info:
            info.enabled = False
            return True
        return False

    def set_plugin_config(self, name: str, config: dict[str, Any]) -> bool:
        """设置插件配置"""
        info = self._plugins.get(name)
        if info:
            info.plugin.set_config(config)
            return True
        return False

    def _update_execution_order(self):
        """更新执行顺序（按优先级排序）"""
        self._execution_order = sorted(
            self._plugins.keys(),
            key=lambda n: self._plugins[n].metadata.priority
        )

    # ==========================================
    # 统计信息
    # ==========================================

    def get_stats(self) -> dict[str, Any]:
        """获取统计信息"""
        total = len(self._plugins)
        enabled = sum(1 for info in self._plugins.values() if info.enabled)
        healthy = sum(
            1 for info in self._plugins.values()
            if info.plugin.health_check()["status"] == "healthy"
        )

        return {
            "total_plugins": total,
            "enabled_plugins": enabled,
            "healthy_plugins": healthy,
            "execution_order": self._execution_order,
        }
