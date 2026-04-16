"""
示例插件：端口扫描检测器

这是一个完整的插件示例，展示如何：
1. 继承 BaseDetectionPlugin
2. 实现检测逻辑
3. 返回标准化结果
4. 导出 get_plugin() 函数

使用方式：
    1. 复制此文件到 plugins/external/ 目录
    2. 重命名并修改检测逻辑
    3. 重启分析器，插件会自动加载
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Optional

import pandas as pd

from plugins.base import (
    BaseDetectionPlugin,
    DetectionResult,
    PluginMetadata,
)
from core.models import Severity, ThreatType

logger = logging.getLogger(__name__)


class PortScanDetector(BaseDetectionPlugin):
    """
    端口扫描检测插件。

    检测逻辑：
    - 单个源 IP 在短时间内连接多个不同端口
    - 阈值可配置
    """

    def __init__(self, config: Optional[dict[str, Any]] = None):
        super().__init__(config)
        # 默认配置
        self._default_config = {
            "port_threshold": 10,  # 端口数量阈值
            "time_window_seconds": 60,  # 时间窗口（秒）
            "min_confidence": 0.7,  # 最小置信度
        }

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="port_scan_detector",
            version="1.0.0",
            description="端口扫描检测插件 - 检测 TCP/UDP 端口扫描行为",
            author="Custom Plugin",
            tags=["port_scan", "reconnaissance", "network"],
            priority=50,  # 较低优先级，在核心检测之后执行
        )

    def initialize(self) -> bool:
        """初始化插件"""
        # 合并默认配置
        for key, value in self._default_config.items():
            if key not in self._config:
                self._config[key] = value

        logger.info(f"端口扫描检测器初始化完成，阈值: {self._config['port_threshold']}")
        return True

    def run(
        self,
        df: pd.DataFrame,
        context: Optional[dict[str, Any]] = None
    ) -> list[DetectionResult]:
        """
        执行端口扫描检测。

        Args:
            df: 流量数据
            context: 上下文（可包含白名单 IP 等）

        Returns:
            检测结果列表
        """
        if df.empty:
            return []

        results = []
        port_threshold = self._config["port_threshold"]
        whitelist_ips = context.get("whitelist_ips", set()) if context else set()

        # 按源 IP 分组统计目标端口
        src_to_ports = defaultdict(set)
        src_to_dst = defaultdict(set)

        for _, row in df.iterrows():
            src_ip = row.get("src_ip")
            dst_port = row.get("dst_port")

            if src_ip and dst_port:
                src_to_ports[src_ip].add(dst_port)
                dst_ip = row.get("dst_ip")
                if dst_ip:
                    src_to_dst[src_ip].add(dst_ip)

        # 检测端口扫描
        for src_ip, ports in src_to_ports.items():
            if src_ip in whitelist_ips:
                continue

            port_count = len(ports)
            if port_count >= port_threshold:
                dst_count = len(src_to_dst.get(src_ip, set()))

                # 计算置信度
                confidence = min(1.0, port_count / (port_threshold * 2))

                results.append(DetectionResult(
                    engine_name=self.name,
                    engine_version=self.version,
                    threat_type=ThreatType.PORT_SCAN,
                    severity=Severity.MEDIUM,
                    description=f"检测到端口扫描行为: {src_ip} 扫描了 {port_count} 个端口",
                    evidence={
                        "source_ip": src_ip,
                        "port_count": port_count,
                        "target_count": dst_count,
                        "sample_ports": list(ports)[:20],
                    },
                    confidence=confidence,
                    ioc=[src_ip],
                    mitre_technique="T1046",  # Network Service Scanning
                    recommended_action="建议检查该 IP 的其他行为，考虑加入监控名单",
                ))

        logger.info(f"端口扫描检测完成，发现 {len(results)} 个可疑扫描")
        return results


# ==========================================
# 插件导出函数（必须）
# ==========================================

def get_plugin() -> BaseDetectionPlugin:
    """
    插件入口函数。

    插件管理器会调用此函数获取插件实例。

    Returns:
        插件实例
    """
    return PortScanDetector(config={
        "port_threshold": 15,  # 自定义配置
    })


# ==========================================
# 插件元数据（可选）
# ==========================================

PLUGIN_INFO = {
    "name": "port_scan_detector",
    "version": "1.0.0",
    "author": "Your Name",
    "license": "MIT",
    "homepage": "https://github.com/example/port-scan-plugin",
}
