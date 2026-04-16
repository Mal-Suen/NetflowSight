# NetflowSight 数据源扩展指南

## 📋 概述

NetflowSight 使用 `DataSourceManager` 统一管理所有威胁情报数据源，支持本地文件和远程 URL 两种方式扩展。

---

## 📊 当前数据源

| 名称 | 类别 | 条目数 | 类型 | 更新间隔 |
|------|------|--------|------|----------|
| builtin_safe_domains | 白名单域名 | 97 | 内置 | 静态 |
| builtin_suspicious_ua | 可疑UA | 19 | 内置 | 静态 |
| builtin_phishing_keywords | 钓鱼关键词 | 26 | 内置 | 静态 |
| openphish_feed | 恶意域名 | 300 | 远程 | 4h |
| spamhaus_drop | 恶意IP | 1,595 | 远程 | 24h |
| urlhaus_malicious_gz | 恶意URL | 25,440 | 远程 | 24h |
| urlhaus_domains | 恶意域名 | 507 | 远程 | 12h |
| spamhaus_drop_extended | 恶意IP | 6 | 远程 | 24h |
| blocklist_de | 恶意IP | 10,957 | 远程 | 6h |
| firehol_level1 | 恶意IP | 4,415 | 远程 | 24h |

**总计：43,362 条威胁情报**

---

## 🔧 数据源配置结构

每个数据源由 `DataSource` 数据类定义，核心字段：

```python
@dataclass
class DataSource:
    name: str                    # 唯一标识名
    category: DataSourceCategory # 数据类别
    source_type: DataSourceType  # 来源类型
    url_or_path: str             # URL 或本地路径
    update_interval_hours: int   # 更新间隔（小时）
    format: str                  # 数据格式
    update_strategy: UpdateStrategy  # 更新策略
    expiry_hours: int            # 条目过期时间
    items: set[str]              # 数据条目集合
```

### 数据类别 (DataSourceCategory)

| 类别 | 说明 |
|------|------|
| `WHITELIST_DOMAINS` | 白名单域名 |
| `WHITELIST_IPS` | 白名单 IP |
| `WHITELIST_PORTS` | 白名单端口 |
| `THREAT_IPS` | 恶意 IP |
| `THREAT_DOMAINS` | 恶意域名 |
| `THREAT_URLS` | 恶意 URL |
| `SUSPICIOUS_UA` | 可疑 User-Agent |
| `PHISHING_KEYWORDS` | 钓鱼关键词 |
| `SUSPICIOUS_TLDS` | 可疑 TLD |

### 来源类型 (DataSourceType)

| 类型 | 说明 |
|------|------|
| `LOCAL_FILE` | 本地文件 |
| `REMOTE_URL` | 远程 URL |
| `GENERATED` | 内置生成 |
| `API` | API 接口 |
| `DNSBL` | DNS 黑名单 |

### 更新策略 (UpdateStrategy)

| 策略 | 说明 | 适用场景 |
|------|------|----------|
| `NONE` | 不更新 | 内置静态数据 |
| `ETAG_CHECK` | ETAG/Last-Modified 检查 | 远程 URL（推荐） |
| `FULL` | 每次全量下载 | 无 ETAG 支持的源 |
| `INCREMENTAL` | 增量更新 | 支持时间戳查询的源 |

### 数据格式 (format)

| 格式 | 说明 | 解析方式 |
|------|------|----------|
| `text` | 纯文本，每行一条 | 直接读取 |
| `csv` | CSV 格式 | 按列索引提取 |
| `json` | JSON 数组 | 解析数组 |
| `hosts` | Hosts 文件格式 | 提取域名部分 |
| `gzip` | Gzip 压缩 | 解压后按格式处理 |

---

## 📥 方法一：添加本地文件数据源

### 步骤 1：准备数据文件

将数据文件放入 `data/sources/` 目录：

```bash
# 示例：企业内部黑名单
data/sources/company_blacklist_ips.txt
data/sources/company_blacklist_domains.txt
```

文件格式（每行一条）：

```text
# IP 黑名单
192.168.100.1
10.0.0.50
203.0.113.0/24

# 域名黑名单
malware.example.com
phishing.test.net
```

### 步骤 2：在 manager.py 中注册

编辑 `src/datasource/manager.py`，在 `_create_default_sources()` 方法中添加：

```python
# ==========================================
# 企业自定义数据源
# ==========================================
DataSource(
    name="company_blacklist_ips",
    category=DataSourceCategory.THREAT_IPS,
    source_type=DataSourceType.LOCAL_FILE,
    url_or_path="data/sources/company_blacklist_ips.txt",
    update_strategy=UpdateStrategy.NONE,  # 本地文件不自动更新
    update_interval_hours=0,
    expiry_hours=0,  # 永不过期
    format="text",
),
DataSource(
    name="company_blacklist_domains",
    category=DataSourceCategory.THREAT_DOMAINS,
    source_type=DataSourceType.LOCAL_FILE,
    url_or_path="data/sources/company_blacklist_domains.txt",
    update_strategy=UpdateStrategy.NONE,
    update_interval_hours=0,
    expiry_hours=0,
    format="text",
),
```

---

## 🌐 方法二：添加远程 URL 数据源

### 步骤 1：确认数据源信息

需要确认：
- URL 地址
- 数据格式（text/csv/json/hosts）
- 是否支持 ETAG/Last-Modified
- 更新频率建议

### 步骤 2：在 manager.py 中注册

```python
# ==========================================
# 新增远程威胁情报源
# ==========================================
DataSource(
    name="emerging_threats",
    category=DataSourceCategory.THREAT_IPS,
    source_type=DataSourceType.REMOTE_URL,
    url_or_path="https://rules.emergingthreats.net/blocklist/compromised-ips.txt",
    update_strategy=UpdateStrategy.ETAG_CHECK,  # 支持 ETAG
    update_interval_hours=24,  # 每天更新
    expiry_hours=48,  # 条目 48 小时过期
    format="text",
),
DataSource(
    name="phishing_database",
    category=DataSourceCategory.THREAT_DOMAINS,
    source_type=DataSourceType.REMOTE_URL,
    url_or_path="https://phishing.database/list.txt",
    update_strategy=UpdateStrategy.FULL,  # 不支持 ETAG，全量下载
    update_interval_hours=12,
    expiry_hours=24,
    format="text",
),
```

### 步骤 3：测试数据源

```bash
cd src
python -c "
from datasource.manager import DataSourceManager
mgr = DataSourceManager()
mgr.update_source('emerging_threats')
print(mgr.get_source('emerging_threats').item_count)
"
```

---

## 📝 方法三：扩展内置白名单

### 直接编辑 manager.py

找到 `builtin_safe_domains` 数据源，在 `items` 集合中添加：

```python
DataSource(
    name="builtin_safe_domains",
    category=DataSourceCategory.WHITELIST_DOMAINS,
    source_type=DataSourceType.GENERATED,
    url_or_path="builtin",
    update_strategy=UpdateStrategy.NONE,
    update_interval_hours=0,
    items={
        # ... 现有条目 ...

        # 新增企业内部域名
        "internal.company.com",
        "api.company.com",
        "vpn.company.com",

        # 新增合作伙伴域名
        "partner.example.org",
    },
    version="3.1.0",  # 更新版本号
    last_updated=datetime.now().isoformat(),
    health_status="healthy",
),
```

---

## 🔄 数据源更新机制

### 自动更新

每次运行分析时，`DataSourceManager` 会：

1. 检查每个数据源的 `update_interval_hours`
2. 如果 `当前时间 - last_updated >= update_interval_hours`，触发更新
3. 使用 ETAG/Last-Modified 避免重复下载
4. 更新成功后保存到 `state.json`

### 手动更新

```bash
# 检查数据源状态
python scripts/check_sources.py

# 强制更新所有数据源
python scripts/update_sources.py --force

# 更新单个数据源
python scripts/update_sources.py --source openphish_feed
```

### 交互式更新

运行分析时会提示：

```
数据源更新检查:
  openphish_feed      : 需要更新 (距上次 5.2 小时)
  spamhaus_drop       : 需要更新 (距上次 26.1 小时)
  blocklist_de        : 需要更新 (距上次 7.5 小时)

是否更新这些数据源? [Y/n]:
```

---

## 📁 状态文件

`data/sources/state.json` 记录所有数据源状态：

```json
{
  "sources": {
    "openphish_feed": {
      "category": "threat_domains",
      "source_type": "remote_url",
      "url_or_path": "https://openphish.com/feed.txt",
      "update_interval_hours": 4,
      "enabled": true,
      "format": "text",
      "update_strategy": "etag_check",
      "version": "1.300.86eb4c",
      "last_updated": "2026-04-16T11:04:12.495902",
      "last_hash": "W/\"9a412a79...\"",
      "item_count": 300,
      "health_status": "healthy",
      "total_updates": 3
    }
  },
  "update_history": [...]
}
```

---

## ⚠️ 注意事项

### 1. 数据源可靠性

- 优先选择有 ETAG 支持的数据源
- 避免频率过高导致被限流
- 设置合理的 `expiry_hours` 避免过期数据

### 2. 数据格式兼容

- `text` 格式：每行一条，支持 `#` 注释
- `csv` 格式：需指定 `csv_column_index`
- `hosts` 格式：自动提取域名部分
- IP 支持 CIDR 格式（如 `192.168.0.0/24`）

### 3. 性能考虑

- 单个数据源建议不超过 100 万条
- 总数据量建议控制在 50 万条以内
- 使用 `expiry_hours` 自动清理过期条目

### 4. 错误处理

数据源更新失败时：
- `health_status` 设为 `degraded` 或 `unhealthy`
- 保留上次成功的数据
- 记录 `error_message`
- 不会中断分析流程

---

## 🧪 测试新增数据源

```python
from datasource.manager import DataSourceManager

# 初始化
mgr = DataSourceManager()

# 检查数据源
source = mgr.get_source('my_new_source')
print(f"状态: {source.health_status}")
print(f"条目数: {source.item_count}")
print(f"最后更新: {source.last_updated}")

# 测试查询
if "malicious.example.com" in source.items:
    print("命中！")

# 强制更新
mgr.update_source('my_new_source', force=True)
```

---

## 📚 推荐数据源

| 名称 | URL | 类别 | 格式 |
|------|-----|------|------|
| Emerging Threats | https://rules.emergingthreats.net/blocklist/compromised-ips.txt | THREAT_IPS | text |
| Alienvault OTX | https://otx.alienvault.com/api/v1/indicators/export | THREAT_IPS | csv |
| CINS Army | https://cinsscore.com/list/ci-badguys.txt | THREAT_IPS | text |
| Ransomware Tracker | https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt | THREAT_DOMAINS | text |
| Malware Domain List | https://www.malwaredomainlist.com/hostslist/hosts.txt | THREAT_DOMAINS | hosts |

---

**返回 [README](../README.md)**
