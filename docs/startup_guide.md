# NetflowSight 启动行为指南

## 🚀 启动行为逻辑

```
启动 NetflowSight
       ↓
检查 state.json 是否存在
       ↓
  ┌───────┴───────┐
  ↓               ↓
首次运行        后续运行
(无 state.json)  (有 state.json)
  ↓               ↓
自动更新数据    加载缓存
(无需询问)        ↓
                 interactive=True?
                 ┌─────┴─────┐
                 ↓           ↓
               是            否
                 ↓           ↓
            询问用户      使用缓存
            [Y/n]?         ↓
            ┌──┴──┐      结束
            ↓     ↓
           Y/N   跳过
            ↓
          更新数据
```

---

## 📊 行为对比

| 场景 | 首次运行 | 后续运行 (Interactive) | 后续运行 (Non-Interactive) |
|------|---------|----------------------|--------------------------|
| **检测** | state.json 不存在 | state.json 存在 | state.json 存在 |
| **更新** | ✅ 自动更新 | ❓ 询问用户 | ❌ 跳过 |
| **缓存** | 无缓存，下载全量 | 加载缓存 | 加载缓存 |
| **用户交互** | 无 | 有 [Y/n] 提示 | 无 |

---

## ⚙️ 配置参数

### `interactive` 参数

```python
manager = DataSourceManager(
    interactive=True,  # 默认值
)
```

| 值 | 行为 | 适用场景 |
|---|------|---------|
| `True` | 后续运行询问用户 | CLI 工具、交互式终端 |
| `False` | 后续运行跳过询问 | 脚本、API、自动化 |

### `auto_update_on_start` 参数

```python
manager = DataSourceManager(
    auto_update_on_start=True,  # 控制后续运行是否询问
)
```

| 值 | 首次运行 | 后续运行 (Interactive) | 后续运行 (Non-Interactive) |
|---|---------|----------------------|--------------------------|
| `True` | 自动更新 | 询问用户 | 跳过 |
| `False` | 自动更新 | 跳过 | 跳过 |

> **注意**: 首次运行**始终自动更新**，不受参数影响。

---

## 🎯 实际使用示例

### 示例 1: CLI 工具 (交互式)

```python
from netflowsight.datasource.manager import DataSourceManager

# 创建管理器
manager = DataSourceManager(
    data_dir="data/sources",
    interactive=True,         # 启用交互
    auto_update_on_start=True, # 后续运行时询问
)

# 首次运行输出:
# First run detected: Automatically updating data sources...
# Initial data source update complete

# 后续运行输出:
# ==================================================
# 📦 Data Source Update Check
# ==================================================
# Last update: 2025-06-13T15:34:00
# Enabled sources: 3
# 
# Check for updates now? [Y/n]: _
```

### 示例 2: Python 脚本 (非交互式)

```python
manager = DataSourceManager(
    interactive=False,         # 禁用交互
    auto_update_on_start=False, # 不询问，使用缓存
)

# 始终静默加载缓存
# 适合后台服务或自动化脚本
```

### 示例 3: 强制更新 (跳过询问)

```python
# 即使用户选择 "n"，也可以强制更新
manager.update_all()
```

### 示例 4: 重新触发首次运行

```python
import os
from pathlib import Path

# 删除状态文件
state_file = Path("data/sources/state.json")
if state_file.exists():
    state_file.unlink()

# 下次启动时会触发首次运行
manager = DataSourceManager()
```

---

## 💬 交互式提示示例

```
==================================================
📦 Data Source Update Check
==================================================
Last update: 2025-06-13T15:34:00
Enabled sources: 3

Check for updates now? [Y/n]: y

🔄 Updating data sources...
✅ Update complete: 3/3 sources updated
==================================================
```

---

## 🔄 更新频率建议

| 数据源 | 建议频率 | 原因 |
|--------|---------|------|
| Spamhaus DROP | 每天 | 恶意 IP 段变化频繁 |
| URLhaus | 每小时 | 恶意 URL 每小时更新 |
| Alexa Top 1M | 每周 | 域名排名变化较慢 |
| 自定义列表 | 按需 | 手动维护 |

---

## ❓ 常见问题

### Q: 如何跳过所有更新检查？

```python
# 方法 1: 创建时不启用更新
manager = DataSourceManager(
    auto_update_on_start=False,
)

# 方法 2: 禁用所有远程源
for source in manager._sources.values():
    if source.source_type.value != "generated":
        manager.disable_source(source.name)
```

### Q: 首次更新失败怎么办？

A: 系统会回退到内置规则，不影响基本功能。后续可以手动更新：
```python
manager.update_all()
```

### Q: 可以在后台自动更新吗？

A: 使用非交互式模式 + 定时任务：
```python
# 定时任务脚本
import schedule
import time

manager = DataSourceManager(interactive=False)

def update_sources():
    manager.update_all()

schedule.every().day.at("02:00").do(update_sources)

while True:
    schedule.run_pending()
    time.sleep(60)
```

---

## 📁 相关文件

| 文件 | 用途 |
|------|------|
| `datasource/manager.py` | 核心管理器 (包含启动逻辑) |
| `test_startup_behavior.py` | 启动行为测试 |
| `docs/startup_guide.md` | 本文档 |
