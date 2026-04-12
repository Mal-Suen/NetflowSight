# NetflowSight 数据源管理指南

## 📋 概述

NetflowSight 使用本地威胁情报库来实现**零误报**的威胁检测。所有数据源由 `DataSourceManager` 统一管理。

---

## 📊 数据源分类

| 类别 | 用途 | 示例 |
|------|------|------|
| **白名单** | 减少误报 | 企业内部域名、可信 IP、常用端口 |
| **威胁情报** | 发现恶意活动 | PhishTank, URLhaus, Spamhaus |
| **攻击特征** | 检测规则 | 钓鱼关键词、可疑 UA、恶意 TLD |
| **自定义规则** | 企业特定需求 | 内部服务域名、合作伙伴 IP |

---

## 🔄 默认数据源

| 名称 | 类别 | 更新频率 | 状态 |
|------|------|---------|------|
| **PhishTank** | 钓鱼域名 | 24h | ✅ 已启用 |
| **URLhaus** | 恶意 URL | 12h | ✅ 已启用 |
| **Spamhaus DROP** | 恶意 IP 段 | 24h | ✅ 已启用 |
| **微步在线** | 域名威胁 | 按需 | ⚠️ 需 API Key |
| **AbuseIPDB** | IP 信誉 | 按需 | ⚠️ 需 API Key |

---

## 📁 数据存储

```
data/sources/
├── state.json                     # 数据源状态（元数据）
├── abuseipdb_whitelist.json       # AbuseIPDB 白名单（永久）
├── abuseipdb_safe_cache.json      # AbuseIPDB 安全缓存（30 天）
├── threatbook_whitelist.json      # 微步白名单（永久）
├── threatbook_safe_cache.json     # 微步安全缓存（30 天）
├── custom_enterprise-domains.txt  # 企业自定义域名
└── example_sources.json           # 示例配置
```

---

## 🔧 智能缓存机制

### 微步在线 ThreatBook

```
查询域名 → 微步 API
        ↓
judgments 包含 "Whitelist" → ✅ 加入白名单（永久保存）
        ↓
安全但未标记白名单         → 🔒 加入安全缓存（30 天过期）
        ↓
可疑/恶意                  → 🔴 生成告警
```

### AbuseIPDB

```
查询 IP → AbuseIPDB API
        ↓
abuse_score == 0 且是知名云服务 → ✅ 加入白名单（永久）
        ↓
abuse_score < 10               → 🔒 加入安全缓存（30 天）
        ↓
abuse_score >= 10              → 🔴 生成告警
```

---

## ⚙️ 启动行为

### 首次运行

自动更新所有数据源（无需询问）：

```
First run detected: Automatically updating data sources...
✅ Initial data source update complete
```

### 后续运行

交互式模式下会询问：

```
==================================================
📦 Data Source Update Check
==================================================
Last update: 2026-04-12T09:23:54
Enabled sources: 9

Check for updates now? [Y/n]:
```

---

## 💡 最佳实践

### 1. 定期更新

建议每周至少运行一次完整更新：

```bash
python update_sources.py
```

### 2. 监控缓存状态

```python
from engines.smart_threat import SmartThreatDetector
from engines.abuseipdb_detector import AbuseIPDBSmartDetector

# 查看微步缓存状态
detector = SmartThreatDetector()
print(detector.get_stats())

# 查看 AbuseIPDB 缓存状态
detector = AbuseIPDBSmartDetector()
print(detector.get_stats())
```

### 3. 自定义白名单

创建 `data/sources/custom_enterprise-domains.txt`：

```
# 企业内部域名
company.com
intranet.company.com

# 合作伙伴域名
partner.com
vendor.net
```

---

## ❓ 常见问题

**Q: 为什么有些数据源显示"从未更新"？**

A: 这些数据源（如微步/AbuseIPDB）是按需查询的，不是定期拉取的。它们通过智能缓存机制工作。

**Q: 如何清理过期缓存？**

A: 系统会自动清理超过 30 天的缓存条目。也可以手动删除 `data/sources/` 下的缓存文件。

**Q: 状态文件过大怎么办？**

A: 已优化。状态文件只保存元数据，不保存实际条目。正常情况应 <10KB。

---

**更多文档**: 查看 [QUICK_START.md](QUICK_START.md) 和 [ENGINEERING_REPORT.md](ENGINEERING_REPORT.md)
