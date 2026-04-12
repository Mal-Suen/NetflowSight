# NetflowSight 增量更新策略指南

## 🔄 为什么需要增量更新？

| 场景 | 全量更新 | 增量更新 | 节省 |
|------|---------|---------|------|
| Alexa Top 1M 未变化 | 5MB 下载 | 0 字节 (304) | **100%** |
| URLhaus 每小时更新 | 50MB/天 | 500KB/天 | **99%** |
| Spamhaus DROP | 10KB/天 | 0 字节 (多数天) | **~90%** |

---

## 📊 支持的更新策略

### 1. ETAG_CHECK (推荐用于静态文件)

**原理**: HTTP 条件请求，服务器告诉客户端"数据是否变化"

```python
# 首次请求
GET /data.txt
→ 200 OK + ETag: "abc123" + 数据 (5MB)

# 后续请求
GET /data.txt
If-None-Match: "abc123"
→ 304 Not Modified (0 字节传输!)
```

**适用源**:
- Spamhaus DROP: https://www.spamhaus.org/drop/drop.txt
- Alexa Top 1M: https://s3.amazonaws.com/alexa-static/top-1m.csv.zip
- 任何支持 ETag/Last-Modified 的 HTTP 资源

**配置示例**:
```json
{
  "name": "spamhaus_drop",
  "update_strategy": "etag_check",
  "url_or_path": "https://www.spamhaus.org/drop/drop.txt"
}
```

---

### 2. TIME_WINDOW (推荐用于频繁更新的源)

**原理**: 只下载自上次更新以来的变更部分

```
首次: 下载完整列表 (100 万条)
      └── 保存时间戳: 2025-06-13T15:00:00

1小时后: 请求增量
      └── GET /data?since=2025-06-13T15:00:00
      └── 只返回新增的 5000 条
      └── 合并到现有数据

24小时后: 清理过期数据
      └── 删除超过 48 小时的旧条目
```

**适用源**:
- URLhaus: https://urlhaus.abuse.ch/downloads/csv_recent/
- PhishTank: https://data.phishtank.com/data/online-valid.csv.gz
- ThreatFox: https://threatfox-api.abuse.ch/api/

**配置示例**:
```json
{
  "name": "urlhaus_malicious",
  "update_strategy": "time_window",
  "url_or_path": "https://urlhaus.abuse.ch/downloads/csv_recent/",
  "incremental_window_hours": 24,
  "cleanup_expired": true,
  "expiry_hours": 168
}
```

---

### 3. API_INCREMENTAL (推荐用于 API 数据源)

**原理**: 使用 API 的分页/增量参数

```python
# AbuseIPDB 示例
GET /api/v2/blacklist
?ageInDays=1          # 只获取最近 1 天
&limit=10000          # 分页
&offset={last_offset} # 从上次位置继续
```

**适用源**:
- AbuseIPDB
- VirusTotal
- AlienVault OTX

---

### 4. DIFFERENTIAL (差分更新)

**原理**: 使用专门的差分文件

```
版本 1.0.abc123 → 版本 1.0.def456
下载: diff-abc123-def456.txt

内容:
+new_domain.com    # 新增
-old_domain.com    # 删除
```

---

## ⚙️ 配置增量更新

### 方法 1: JSON 配置文件

创建 `data/sources/sources.json`:

```json
{
  "sources": [
    {
      "name": "spamhaus_drop",
      "category": "threat_ips",
      "source_type": "remote_url",
      "url_or_path": "https://www.spamhaus.org/drop/drop.txt",
      "update_strategy": "etag_check",
      "update_interval_hours": 24
    },
    {
      "name": "urlhaus_malicious",
      "category": "threat_urls",
      "source_type": "remote_url",
      "url_or_path": "https://urlhaus.abuse.ch/downloads/csv_recent/",
      "update_strategy": "time_window",
      "incremental_window_hours": 1,
      "cleanup_expired": true,
      "expiry_hours": 168,
      "update_interval_hours": 1
    },
    {
      "name": "alexa_top_domains",
      "category": "whitelist_domains",
      "source_type": "remote_url",
      "url_or_path": "https://s3.amazonaws.com/alexa-static/top-1m.csv.zip",
      "update_strategy": "etag_check",
      "update_interval_hours": 168
    }
  ]
}
```

### 方法 2: Python API

```python
from netflowsight.datasource.manager import DataSourceManager, DataSource, DataSourceType, DataSourceCategory, UpdateStrategy

manager = DataSourceManager()

# 添加 ETag 源
spamhaus = DataSource(
    name="spamhaus_drop",
    category=DataSourceCategory.THREAT_IPS,
    source_type=DataSourceType.REMOTE_URL,
    url_or_path="https://www.spamhaus.org/drop/drop.txt",
    update_strategy=UpdateStrategy.ETAG_CHECK,
    update_interval_hours=24,
)
manager.add_source(spamhaus)

# 添加时间窗口增量源
urlhaus = DataSource(
    name="urlhaus_malicious",
    category=DataSourceCategory.THREAT_URLS,
    source_type=DataSourceType.REMOTE_URL,
    url_or_path="https://urlhaus.abuse.ch/downloads/csv_recent/",
    update_strategy=UpdateStrategy.TIME_WINDOW,
    incremental_window_hours=1,
    cleanup_expired=True,
    expiry_hours=168,
    update_interval_hours=1,
)
manager.add_source(urlhaus)

# 更新所有源（自动选择最佳策略）
results = manager.update_all()
```

---

## 📈 增量更新效果

### 测试数据

```
场景: 100 万域名列表，每天变化 5%

策略              下载量     处理时间    网络流量/月
────────────────────────────────────────────────
FULL (无 ETag)    5MB       ~2s        150MB
ETAG (未变化)     0 bytes   ~0.1s      0MB
ETAG (变化)       5MB       ~2s        150MB
TIME_WINDOW       250KB     ~0.3s      7.5MB
DIFFERENTIAL      50KB      ~0.1s      1.5MB
```

### 实际案例

| 源 | 策略 | 全量大小 | 增量大小 | 节省 |
|---|------|---------|---------|------|
| Spamhaus DROP | ETAG_CHECK | 10KB | 0 bytes (70% 的天) | 70% |
| URLhaus | TIME_WINDOW | 50MB/天 | 500KB/天 | 99% |
| Alexa Top 1M | ETAG_CHECK | 5MB | 0 bytes (未变) | 100% |
| PhishTank | TIME_WINDOW | 2MB/天 | 100KB/天 | 95% |

---

## 🧹 过期数据清理

增量更新会累积数据，需要定期清理：

```python
# 配置清理策略
source = DataSource(
    ...
    cleanup_expired=True,     # 启用清理
    expiry_hours=168,         # 168 小时 (7 天) 后过期
)

# 手动清理
manager._cleanup_expired_items(source)
# → 返回清理的条目数量

# 自动清理 (在每次增量更新后执行)
manager.update_source("urlhaus_malicious")
# → 内部自动调用 cleanup
```

---

## 🔄 回退机制

增量更新失败时自动回退到全量：

```python
def _update_with_time_window(self, source):
    try:
        # 尝试增量
        return self._update_incremental_from_url(source, url)
    except Exception as e:
        # 失败 → 全量
        logger.warning(f"Incremental failed, falling back to full: {e}")
        return self._update_with_etag(source)
```

---

## 📅 推荐更新计划

```bash
# crontab 配置示例

# 每小时: URLhaus (频繁更新)
0 * * * * /path/to/update.sh urlhaus_malicious

# 每天凌晨 2 点: Spamhaus + PhishTank
0 2 * * * /path/to/update.sh spamhaus_drop phishtank_urls

# 每周日凌晨 3 点: Alexa Top 1M
0 3 * * 0 /path/to/update.sh alexa_top_domains

# 每天凌晨 4 点: 全部更新 + 保存状态
0 4 * * * /path/to/update.sh --all --save-state
```

---

## ❓ 常见问题

### Q: 如何选择正确的策略？

**决策树**:
```
数据源支持 ETag 吗？
├── 是 → ETAG_CHECK (零配置，自动优化)
└── 否 → 提供增量 URL/API 吗？
         ├── 是 → TIME_WINDOW 或 API_INCREMENTAL
         └── 否 → FULL (首次下载后 ETag 缓存)
```

### Q: 增量更新失败了怎么办？

自动回退到全量更新，无需手动干预。

### Q: 如何查看更新效果？

```python
stats = manager.get_stats()
for name, source in manager._sources.items():
    print(f"{name}:")
    print(f"  Strategy: {source.update_strategy.value}")
    print(f"  Total updates: {source.total_updates}")
    print(f"  Avg duration: {source.last_update_duration_ms:.0f}ms")
    print(f"  Items: {source.item_count}")
```

### Q: 可以禁用某个策略吗？

```python
# 临时禁用增量，强制全量
source = manager.get_source("urlhaus")
source.update_strategy = UpdateStrategy.FULL
manager.update_source("urlhaus")

# 恢复
source.update_strategy = UpdateStrategy.TIME_WINDOW
```
