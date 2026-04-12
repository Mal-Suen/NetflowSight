# NetflowSight 数据源管理指南

## 📋 数据源分类

NetflowSight 使用四类数据源来确保检测准确性：

| 类别 | 用途 | 示例 |
|------|------|------|
| **白名单** | 减少误报 | 企业内部域名、可信 IP、常用端口 |
| **威胁情报** | 发现恶意活动 | AbuseIPDB、VirusTotal、AlienVault OTX |
| **攻击特征** | 检测规则 | 钓鱼关键词、可疑 UA、恶意 TLD |
| **自定义规则** | 企业特定需求 | 内部服务域名、合作伙伴 IP |

---

## 🔧 数据源获取渠道

### 1. 白名单数据

#### 免费自动更新源

| 源名称 | URL | 更新频率 | 数据量 |
|--------|-----|---------|--------|
| **Alexa Top 1M** | https://s3.amazonaws.com/alexa-static/top-1m.csv.zip | 每周 | 100 万域名 |
| **Cisco Umbrella** | http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip | 每月 | 100 万域名 |
| **Microsoft 365** | https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-87b2-4d2e-b0a5-8b5e5f5f5f5f | 每周 | ~3000 端点 |
| **Google IP Ranges** | https://www.gstatic.com/ipranges/goog.json | 每周 | ~1000 IP 段 |

#### 企业自定义白名单

创建文件 `data/sources/custom_whitelist.txt`：
```
# 企业内部域名
company.com
intranet.company.com
sharepoint.company.com

# 合作伙伴域名
partner.com
vendor.net

# 可信 IP 段
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
```

### 2. 威胁情报源

#### 免费源（无需 API Key）

| 源名称 | 类型 | URL | 更新频率 |
|--------|------|-----|---------|
| **Spamhaus DROP** | 恶意 IP 段 | https://www.spamhaus.org/drop/drop.txt | 每天 |
| **URLhaus** | 恶意 URL | https://urlhaus.abuse.ch/downloads/csv_recent/ | 每小时 |
| **ThreatFox** | malware IOC | https://threatfox-api.abuse.ch/api/ | 实时 |
| **PhishTank** | 钓鱼 URL | https://data.phishtank.com/data/online-valid.csv.gz | 每天 |
| **OpenPhish** | 钓鱼 URL | https://openphish.com/feed.txt | 每天 |

#### 免费源（需要 API Key）

| 源名称 | 类型 | 免费额度 | 注册链接 |
|--------|------|---------|---------|
| **AbuseIPDB** | IP 信誉 | 1000 次/天 | https://www.abuseipdb.com/api |
| **VirusTotal** | 文件/URL/IP/域名 | 500 次/天 | https://www.virustotal.com/gui/join-us |
| **AlienVault OTX** | IOC 订阅 | 无限 | https://otx.alienvault.com/api |
| **Shodan** | 设备指纹 | 100 次/月 | https://account.shodan.io/register |

#### 付费源（企业级）

| 源名称 | 类型 | 价格 | 特点 |
|--------|------|------|------|
| **Recorded Future** | 威胁情报 | $$$ | 实时、高覆盖率 |
| **CrowdStrike Falcon** | 端点+网络 | $$$ | 集成 EDR |
| **FireEye iSIGHT** | 威胁情报 | $$$ | 政府级 |

### 3. 攻击特征库

| 源名称 | 内容 | 格式 | 链接 |
|--------|------|------|------|
| **MITRE ATT&CK** | 攻击技术 | STIX | https://attack.mitre.org/ |
| **Sigma Rules** | 检测规则 | YAML | https://github.com/SigmaHQ/sigma |
| **YARA Rules** | 恶意软件特征 | YARA | https://github.com/Yara-Rules/rules |
| **Suricata Rules** | 网络威胁检测 | Suricata | https://rules.emergingthreats.net/ |

---

## ⚙️ 配置数据源

### 方法 1: 使用配置文件（推荐）

创建 `data/sources/sources.json`：

```json
{
  "version": "1.0",
  "sources": [
    {
      "name": "alexa_top_domains",
      "category": "whitelist_domains",
      "source_type": "remote_url",
      "url_or_path": "https://s3.amazonaws.com/alexa-static/top-1m.csv.zip",
      "update_interval_hours": 168,
      "enabled": true,
      "format": "csv"
    },
    {
      "name": "spamhaus_drop",
      "category": "threat_ips",
      "source_type": "remote_url",
      "url_or_path": "https://www.spamhaus.org/drop/drop.txt",
      "update_interval_hours": 24,
      "enabled": true,
      "format": "text"
    },
    {
      "name": "urlhaus_malicious",
      "category": "threat_urls",
      "source_type": "remote_url",
      "url_or_path": "https://urlhaus.abuse.ch/downloads/csv_recent/",
      "update_interval_hours": 1,
      "enabled": true,
      "format": "csv"
    },
    {
      "name": "enterprise_whitelist",
      "category": "whitelist_domains",
      "source_type": "local_file",
      "url_or_path": "data/sources/custom_whitelist.txt",
      "update_interval_hours": 0,
      "enabled": true,
      "format": "text"
    }
  ]
}
```

### 方法 2: Python API

```python
from netflowsight.datasource.manager import DataSourceManager, DataSource, DataSourceType, DataSourceCategory

# 初始化
manager = DataSourceManager(data_dir="data/sources")

# 添加远程源
alexa_source = DataSource(
    name="alexa_top_1m",
    category=DataSourceCategory.WHITELIST_DOMAINS,
    source_type=DataSourceType.REMOTE_URL,
    url_or_path="https://s3.amazonaws.com/alexa-static/top-1m.csv.zip",
    update_interval_hours=168,
    format="csv"
)
manager.add_source(alexa_source)

# 添加本地源
custom_source = DataSource(
    name="my_company_domains",
    category=DataSourceCategory.WHITELIST_DOMAINS,
    source_type=DataSourceType.LOCAL_FILE,
    url_or_path="data/sources/my_company_domains.txt",
    format="text"
)
manager.add_source(custom_source)

# 更新所有源
results = manager.update_all()
print(f"Updated: {sum(results.values())}/{len(results)} succeeded")

# 查看状态
stats = manager.get_stats()
print(stats)
```

---

## 🔄 自动更新策略

### 推荐更新频率

| 数据源类型 | 推荐频率 | 原因 |
|-----------|---------|------|
| **白名单域名** | 每周 | 变化不频繁 |
| **威胁 IP** | 每天 | 新恶意 IP 不断出现 |
| **恶意 URL** | 每小时 | 钓鱼网站生命周期短 |
| **攻击特征** | 每月 | 新攻击手法出现 |
| **企业自定义** | 按需 | 内部变化时更新 |

### 自动更新脚本

创建 `update_sources.sh`（Linux/Mac）或 `update_sources.bat`（Windows）：

```bash
#!/bin/bash
# 添加到 crontab: 0 2 * * 0 /path/to/update_sources.sh (每周日凌晨 2 点)

cd /path/to/NetflowSight
D:\ProgramData\anaconda3\python.exe -c "
from netflowsight.datasource.manager import DataSourceManager
manager = DataSourceManager()
results = manager.update_all()
manager.save_state()
print(f'Updated {sum(results.values())}/{len(results)} sources')
"
```

---

## 📊 数据源健康监控

### 查看数据源状态

```python
from netflowsight.datasource.manager import DataSourceManager

manager = DataSourceManager()

# 列出所有源
for src in manager.list_sources():
    status_icon = {"healthy": "✅", "degraded": "⚠️", "unhealthy": "❌"}.get(src["health_status"], "❓")
    print(f"{status_icon} {src['name']}: {src['item_count']} items (last: {src['last_updated']})")

# 查看统计
stats = manager.get_stats()
print(f"Total: {stats['total_sources']}, Healthy: {stats['healthy_sources']}")
```

### 告警规则

| 状态 | 含义 | 处理建议 |
|------|------|---------|
| **healthy** | 正常 | 无需处理 |
| **degraded** | 部分失败 | 检查 API Key 或网络 |
| **unhealthy** | 完全失败 | 检查 URL 是否有效 |
| **unknown** | 未更新 | 手动触发更新 |

---

## 🛡️ 最佳实践

### 1. 多层白名单策略
```
Level 1: 全球 Top 100 万域名（Alexa/Umbrella）
Level 2: 企业域名 + 合作伙伴
Level 3: 部门特定域名（手动维护）
Level 4: 临时白名单（事件调查时添加）
```

### 2. 威胁情报交叉验证
```
不要依赖单一情报源！
- AbuseIPDB 说恶意 + VirusTotal 说恶意 = 高置信度
- AbuseIPDB 说恶意 + VirusTotal 说干净 = 调查中
- 多个源都说恶意 = 立即封禁
```

### 3. 版本控制与回滚
```python
# 保存当前状态
manager.save_state("data/sources/state_2025-06-13.json")

# 如果更新后误报增加，可以回滚
manager.load_state("data/sources/state_2025-06-13.json")
```

### 4. 定期审查
- **每周**: 检查误报 Top 10，添加白名单
- **每月**: 审查威胁情报源有效性
- **每季度**: 评估数据源覆盖率和准确性

---

## 📁 目录结构

```
data/
└── sources/
    ├── example_sources.json        # 配置示例
    ├── custom_whitelist.txt        # 企业自定义白名单
    ├── custom_threat_ips.txt       # 企业威胁 IP 列表
    ├── exported_config.json        # 导出的配置
    └── state.json                  # 当前状态（自动保存）
```

---

## ❓ 常见问题

### Q: 免费源够用吗？
A: 对于中小企业，免费源覆盖 80%+ 的威胁。建议至少配置：
- Alexa Top 1M（白名单）
- AbuseIPDB（IP 信誉）
- URLhaus（恶意 URL）
- 企业内部白名单

### Q: 如何减少误报？
A: 
1. 添加更多白名单源
2. 调整检测引擎阈值
3. 使用多源情报交叉验证
4. 定期审查误报并添加白名单

### Q: 数据源更新失败怎么办？
A:
1. 检查网络连接
2. 验证 API Key 是否过期
3. 查看错误日志
4. 使用上一次成功状态（自动回滚）

### Q: 可以自建威胁情报平台吗？
A: 可以！推荐：
- **MISP** (https://www.misp-project.org/) - 开源威胁情报平台
- **OpenCTI** (https://www.opencti.io/) - 网络安全知识管理
- **Yeti** (https://yeti-platform.github.io/) - 威胁情报管理
