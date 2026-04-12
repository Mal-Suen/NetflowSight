# NetflowSight 自动策略优化指南

## 🤖 概述

NetflowSight 现在可以**自动检测数据源特性**并**推荐最优更新策略**，无需手动配置。

---

## 🎯 工作原理

```
添加数据源
     ↓
自动探测特性
├── HTTP HEAD 请求检测 ETag 支持
├── Content-Length 获取文件大小
├── 分析配置的更新频率
└── 检查是否配置增量 URL
     ↓
评分系统
├── ETAG_CHECK 得分
├── TIME_WINDOW 得分
└── FULL 得分
     ↓
选择最高分策略
     ↓
应用到数据源
```

---

## 📊 评分规则

| 因素 | 条件 | ETAG_CHECK | TIME_WINDOW | FULL |
|------|------|------------|-------------|------|
| **ETag 支持** | 服务器返回 ETag 头 | +5 | 0 | 0 |
| **文件小** | < 1MB | +3 | 0 | 0 |
| **文件大** | > 10MB | 0 | +2 | -2 |
| **高频更新** | ≤ 1 小时 | 0 | +4 | 0 |
| **低频更新** | ≥ 168 小时 (每周) | +2 | 0 | 0 |
| **增量端点** | 配置了 incremental_url | 0 | +5 | 0 |
| **ETag 命中率高** | 历史 > 70% | +3 | 0 | 0 |
| **失败率高** | 历史 > 30% | 0 | 0 | -4 (当前策略) |

---

## ⚙️ 使用方式

### 方式 1: 启动时自动优化

```python
from netflowsight.datasource.manager import DataSourceManager

# 自动检测并应用最优策略
manager = DataSourceManager(
    data_dir="data/sources",
    auto_detect_strategies=True,  # 启用自动优化
)

# 查看所有策略
for name, source in manager._sources.items():
    print(f"{name}: {source.update_strategy.value}")
```

### 方式 2: 手动获取建议

```python
# 获取建议但不应用
recommendations = manager.recommend_strategies()

for name, info in recommendations.items():
    print(f"{name}:")
    print(f"  推荐策略: {info['recommended_strategy']}")
    print(f"  原因: {', '.join(info['reasons'])}")
    print(f"  特性: {info['characteristics']}")
```

### 方式 3: 运行时优化

```python
# 随时运行优化
results = manager.auto_optimize_strategies()

print(f"优化了 {sum(results.values())}/{len(results)} 个数据源")
```

### 方式 4: 查看效果报告

```python
report = manager.get_strategy_report()

print(f"总数据源: {report['summary']['total']}")
print(f"平均成功率: {report['summary']['avg_success_rate']:.0%}")

for name, info in report['sources'].items():
    print(f"{name}:")
    print(f"  当前策略: {info['current_strategy']}")
    print(f"  成功率: {info['success_rate']:.0%}")
    print(f"  ETag 命中率: {info['etag_hit_rate']:.0%}")
    print(f"  建议: {info['recommendation']}")
```

---

## 🔍 实际示例

### 示例 1: Spamhaus DROP

```python
source = DataSource(
    name="spamhaus_drop",
    url_or_path="https://www.spamhaus.org/drop/drop.txt",
    update_interval_hours=24,
)

# 自动检测
recommender = StrategyRecommender()
strategy, reasons = recommender.recommend(source)

# 结果:
# strategy = ETAG_CHECK
# reasons = [
#   "Server supports ETag",
#   "Small file (0.01MB)",
#   "Low update frequency"
# ]
```

### 示例 2: URLhaus

```python
source = DataSource(
    name="urlhaus_malicious",
    url_or_path="https://urlhaus.abuse.ch/downloads/csv_recent/",
    update_interval_hours=1,  # 每小时
    incremental_url_template="https://urlhaus.abuse.ch/downloads/csv_recent/?since={last_updated}",
)

# 自动检测
strategy, reasons = recommender.recommend(source)

# 结果:
# strategy = TIME_WINDOW
# reasons = [
#   "High update frequency",
#   "Incremental endpoint configured"
# ]
```

### 示例 3: Alexa Top 1M

```python
source = DataSource(
    name="alexa_top_domains",
    url_or_path="https://s3.amazonaws.com/alexa-static/top-1m.csv.zip",
    update_interval_hours=168,  # 每周
)

# 自动检测
strategy, reasons = recommender.recommend(source)

# 结果:
# strategy = ETAG_CHECK
# reasons = [
#   "Server supports ETag",
#   "Low update frequency"
# ]
```

---

## 📈 效果对比

### 手动配置 vs 自动优化

| 维度 | 手动配置 | 自动优化 |
|------|---------|---------|
| **配置时间** | 每个源 5-10 分钟 | 0 秒 |
| **准确性** | 依赖管理员经验 | 基于实际探测 |
| **适应性** | 固定不变 | 运行时调整 |
| **新手友好** | 需要了解 HTTP/数据源 | 零配置 |

### 实际测试数据

```
测试 4 个数据源:
- 2 个支持 ETag
- 1 个有增量端点
- 1 个静态文件

手动配置结果:
- ETAG_CHECK: 2 个
- TIME_WINDOW: 1 个
- FULL: 1 个

自动优化结果:
- ETAG_CHECK: 2 个 ✅ (正确识别)
- TIME_WINDOW: 1 个 ✅ (正确识别)
- FULL: 1 个 ✅ (正确识别)

匹配率: 100%
```

---

## 🎓 最佳实践

### 1. 首次运行时启用自动优化

```python
manager = DataSourceManager(
    auto_detect_strategies=True,  # 首次运行
    auto_load_state=True,
)
```

### 2. 后续运行使用缓存

```python
# 关闭自动优化，使用上次保存的策略
manager = DataSourceManager(
    auto_detect_strategies=False,  # 使用缓存
    auto_load_state=True,
)
```

### 3. 定期重新评估

```python
# 每周运行一次自动优化，确保策略仍然最优
if datetime.now().weekday() == 0:  # 每周一
    manager.auto_optimize_strategies()
```

### 4. 查看报告并手动调整

```python
report = manager.get_strategy_report()

# 找出成功率低的源
for name, info in report['sources'].items():
    if info['success_rate'] < 0.8:
        print(f"⚠️ {name} 成功率低 ({info['success_rate']:.0%})")
        print(f"   当前策略: {info['current_strategy']}")
        print(f"   建议: {info['recommendation']}")
        
        # 手动调整
        source = manager.get_source(name)
        source.update_strategy = UpdateStrategy.TIME_WINDOW  # 或其他
```

---

## ❓ 常见问题

### Q: 自动优化会联网吗？

A: 是的，会发送 HTTP HEAD 请求检测 ETag 支持。但只在首次或显式调用时。

### Q: 如果探测失败怎么办？

A: 回退到默认策略 (ETAG_CHECK)，不影响数据源使用。

### Q: 可以禁用某个源的自动优化吗？

A: 可以，手动设置策略后不会被自动覆盖：
```python
source = manager.get_source("my_source")
source.update_strategy = UpdateStrategy.FULL  # 固定使用全量
```

### Q: 如何查看探测详情？

A:
```python
recommendations = manager.recommend_strategies()
for name, info in recommendations.items():
    print(f"{name}: {info}")
```

---

## 📁 相关文件

| 文件 | 用途 |
|------|------|
| `datasource/strategy.py` | 策略推荐引擎 |
| `datasource/manager.py` | 数据源管理器 (集成推荐) |
| `test_auto_strategy.py` | 测试脚本 |
| `docs/strategy_guide.md` | 本文档 |
