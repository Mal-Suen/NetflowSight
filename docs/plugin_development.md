# NetflowSight 插件开发指南

## 📋 概述

NetflowSight 采用插件化架构，所有检测引擎都以插件形式实现。你可以：

1. **使用内置插件** - DNS/HTTP/隐蔽通道/行为异常检测
2. **添加外部插件** - 在 `plugins/external/` 目录放置自定义插件
3. **动态加载插件** - 从任意目录或 Python 模块加载

---

## 🏗️ 插件架构

```
src/plugins/
├── __init__.py          # 插件系统入口
├── base.py              # 插件基类和接口
├── manager.py           # 插件管理器
├── adapters.py          # 内置引擎适配器
└── external/            # 外部插件目录
    ├── __init__.py
    ├── port_scan_detector.py      # 示例：端口扫描检测
    └── data_exfil_detector.py     # 示例：数据泄露检测
```

---

## 🚀 快速开始

### 创建自定义插件

1. **创建插件文件**

在 `src/plugins/external/` 目录创建 `my_detector.py`：

```python
"""我的自定义检测插件"""

from typing import Any, Optional
import pandas as pd

from plugins.base import (
    BaseDetectionPlugin,
    DetectionResult,
    PluginMetadata,
)
from core.models import Severity, ThreatType


class MyDetector(BaseDetectionPlugin):
    """自定义检测插件"""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="my_detector",
            version="1.0.0",
            description="我的自定义检测插件",
            author="Your Name",
            tags=["custom", "example"],
            priority=100,  # 执行优先级（数字越小越先执行）
        )

    def initialize(self) -> bool:
        """初始化插件（可选覆盖）"""
        # 加载模型、初始化资源等
        return True

    def run(
        self,
        df: pd.DataFrame,
        context: Optional[dict[str, Any]] = None
    ) -> list[DetectionResult]:
        """
        执行检测逻辑

        Args:
            df: NFStream 解析的流量数据
            context: 上下文信息，包含：
                - safe_domains: 安全域名集合
                - threat_domains: 威胁域名集合
                - threat_ips: 威胁 IP 集合
                - datasource_manager: 数据源管理器

        Returns:
            检测结果列表
        """
        results = []
        context = context or {}

        # 你的检测逻辑
        for _, row in df.iterrows():
            # 示例：检测特定条件
            if self._is_suspicious(row):
                results.append(DetectionResult(
                    engine_name=self.name,
                    engine_version=self.version,
                    threat_type=ThreatType.SUSPICIOUS,
                    severity=Severity.MEDIUM,
                    description=f"检测到可疑行为",
                    evidence={"src_ip": row.get("src_ip")},
                    confidence=0.8,
                    ioc=[row.get("src_ip")],
                    mitre_technique="T0000",  # MITRE ATT&CK 技术 ID
                    recommended_action="建议进一步调查",
                ))

        return results

    def _is_suspicious(self, row) -> bool:
        """检测逻辑"""
        # 实现你的检测规则
        return False


# ==========================================
# 必须导出此函数
# ==========================================

def get_plugin() -> BaseDetectionPlugin:
    """插件入口函数"""
    return MyDetector(config={
        # 自定义配置
        "threshold": 100,
    })
```

2. **重启分析器**

插件会在分析器初始化时自动加载。

---

## 📚 API 参考

### BaseDetectionPlugin

所有插件必须继承的基类：

```python
class BaseDetectionPlugin(ABC):
    # 抽象方法（必须实现）
    @abstractmethod
    def run(self, df: pd.DataFrame, context: Optional[dict] = None) -> list[DetectionResult]:
        """执行检测"""
        pass

    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """返回插件元数据"""
        pass

    # 可选覆盖
    def initialize(self) -> bool:
        """初始化插件"""
        return True

    def cleanup(self) -> None:
        """清理资源"""
        pass

    def health_check(self) -> dict[str, Any]:
        """健康检查"""
        pass

    def get_config(self) -> dict[str, Any]:
        """获取配置"""
        pass

    def set_config(self, config: dict[str, Any]) -> None:
        """更新配置"""
        pass
```

### DetectionResult

标准化检测结果：

```python
@dataclass
class DetectionResult:
    engine_name: str           # 引擎名称
    engine_version: str        # 引擎版本
    threat_type: ThreatType    # 威胁类型
    severity: Severity         # 严重程度
    description: str           # 描述
    evidence: dict[str, Any]   # 证据
    confidence: float          # 置信度 (0.0-1.0)
    ioc: list[str]             # IOC 指标
    mitre_technique: str       # MITRE ATT&CK 技术 ID
    recommended_action: str    # 建议操作
    timestamp: str             # 时间戳
```

### PluginMetadata

插件元数据：

```python
@dataclass
class PluginMetadata:
    name: str                  # 唯一标识名
    version: str               # 版本号
    description: str           # 描述
    author: str = ""           # 作者
    tags: list[str] = []       # 标签
    priority: int = 100        # 执行优先级（越小越先执行）
    enabled: bool = True       # 是否启用
    requires: list[str] = []   # 依赖的其他插件
```

### ThreatType 枚举

```python
class ThreatType(str, Enum):
    PHISHING = "phishing"
    MALWARE = "malware"
    C2 = "c2"
    DNS_TUNNEL = "dns_tunnel"
    DGA = "dga"
    SUSPICIOUS = "suspicious"
    PORT_SCAN = "port_scan"
    DATA_EXFIL = "data_exfil"
    COVERT_CHANNEL = "covert_channel"
    BEHAVIOR_ANOMALY = "behavior_anomaly"
    # ...
```

### Severity 枚举

```python
class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
```

---

## 🔧 插件管理

### 通过代码管理

```python
from plugins import PluginManager

# 初始化
mgr = PluginManager()

# 加载插件
mgr.load_builtin_plugins()                    # 内置插件
mgr.load_external_plugins("path/to/plugins")  # 外部插件
mgr.load_plugin_from_module("my_package.my_plugin")  # 从模块加载

# 手动注册
from my_plugin import MyPlugin
mgr.register(MyPlugin())

# 执行检测
results = mgr.run_all(df, context)

# 管理插件
mgr.enable_plugin("my_detector")
mgr.disable_plugin("my_detector")
mgr.set_plugin_config("my_detector", {"threshold": 200})

# 查看状态
plugins = mgr.list_plugins()
stats = mgr.get_stats()
```

### 通过分析器管理

```python
from analyzer import NetflowSightAnalyzer

analyzer = NetflowSightAnalyzer("capture.pcap")

# 列出插件
plugins = analyzer.list_plugins()

# 启用/禁用
analyzer.enable_plugin("port_scan_detector")
analyzer.disable_plugin("behavior_detector")

# 获取统计
stats = analyzer.get_plugin_stats()
```

---

## 📊 执行顺序

插件按 `priority` 值排序执行：

| 插件 | Priority | 说明 |
|------|----------|------|
| dns_detector | 10 | DNS 检测（最先） |
| http_detector | 20 | HTTP 检测 |
| covert_detector | 30 | 隐蔽通道检测 |
| behavior_detector | 40 | 行为异常检测 |
| port_scan_detector | 50 | 端口扫描检测 |
| data_exfil_detector | 60 | 数据泄露检测 |

自定义插件建议使用 `priority >= 50`。

---

## 🧪 测试插件

```python
import pandas as pd
from plugins.base import DetectionResult

# 创建测试数据
df = pd.DataFrame({
    "src_ip": ["192.168.1.1", "192.168.1.2"],
    "dst_ip": ["10.0.0.1", "10.0.0.2"],
    "dst_port": [80, 443],
    # ...
})

# 测试插件
from my_plugin import get_plugin
plugin = get_plugin()
plugin.initialize()

results = plugin.run(df, context={})

# 验证结果
assert isinstance(results, list)
for r in results:
    assert isinstance(r, DetectionResult)
    assert 0 <= r.confidence <= 1
```

---

## ⚠️ 注意事项

### 1. 性能考虑

- 避免在 `run()` 中进行耗时操作
- 大流量数据时使用向量化操作
- 缓存重复计算结果

### 2. 错误处理

- 捕获异常并记录日志
- 返回空列表而非抛出异常
- 设置 `health_check()` 状态

### 3. 配置管理

- 使用 `get_config()` / `set_config()` 管理配置
- 提供合理的默认值
- 配置变更后重新初始化

### 4. 线程安全

- 插件可能在多线程环境执行
- 避免使用全局状态
- 使用实例变量存储状态

---

## 📁 示例插件

### 端口扫描检测器

```python
# plugins/external/port_scan_detector.py

from collections import defaultdict
from typing import Any, Optional
import pandas as pd

from plugins.base import BaseDetectionPlugin, DetectionResult, PluginMetadata
from core.models import Severity, ThreatType


class PortScanDetector(BaseDetectionPlugin):
    """端口扫描检测插件"""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="port_scan_detector",
            version="1.0.0",
            description="检测 TCP/UDP 端口扫描行为",
            priority=50,
        )

    def run(self, df: pd.DataFrame, context: Optional[dict] = None) -> list[DetectionResult]:
        results = []
        threshold = self._config.get("port_threshold", 10)

        # 统计每个源 IP 访问的端口数
        src_to_ports = defaultdict(set)
        for _, row in df.iterrows():
            src_ip = row.get("src_ip")
            dst_port = row.get("dst_port")
            if src_ip and dst_port:
                src_to_ports[src_ip].add(dst_port)

        # 检测端口扫描
        for src_ip, ports in src_to_ports.items():
            if len(ports) >= threshold:
                results.append(DetectionResult(
                    engine_name=self.name,
                    engine_version=self.version,
                    threat_type=ThreatType.PORT_SCAN,
                    severity=Severity.MEDIUM,
                    description=f"检测到端口扫描: {src_ip} 扫描了 {len(ports)} 个端口",
                    evidence={
                        "source_ip": src_ip,
                        "port_count": len(ports),
                        "sample_ports": list(ports)[:20],
                    },
                    confidence=min(1.0, len(ports) / (threshold * 2)),
                    ioc=[src_ip],
                    mitre_technique="T1046",
                    recommended_action="建议检查该 IP 的其他行为",
                ))

        return results


def get_plugin() -> BaseDetectionPlugin:
    return PortScanDetector(config={"port_threshold": 15})
```

---

**返回 [README](../README.md)**
