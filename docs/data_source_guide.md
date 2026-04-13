# NetflowSight 数据源与威胁情报指南

## 📋 概述

NetflowSight 使用多层威胁情报体系实现自动化威胁检测：本地黑名单、ML 域名分类器、以及 API 智能缓存。

---

## 📊 检测层级

| 层级 | 来源 | 是否需要 API | 说明 |
|------|------|-------------|------|
| **1. 黑名单** | DataSourceManager | ❌ | 本地维护的已知恶意域名/IP 库 |
| **2. ML 分类器** | LightGBM 模型 | ❌ | 自动识别可疑域名（AUC 0.903） |
| **3. 规则引擎** | 内置规则 | ❌ | DNS 隧道、DGA、HTTP 异常、行为异常 |
| **4. API 复核** | ThreatBook | ✅ | ML 高危域名自动发送 API 复核 |
| **5. API 查询** | AbuseIPDB | ✅ | 外部 IP 信誉查询（三级缓存） |

---

## 🔄 本地数据源

| 名称 | 类别 | 更新频率 | 状态 |
|------|------|---------|------|
| **PhishTank** | 钓鱼域名 | 24h | ✅ 已启用 |
| **URLhaus** | 恶意 URL | 12h | ✅ 已启用 |
| **Spamhaus DROP** | 恶意 IP 段 | 24h | ✅ 已启用 |
| **内置安全域名** | 白名单 | 静态 | ✅ 已启用 |
| **内置可疑 UA** | 特征库 | 静态 | ✅ 已启用 |

---

## 📁 数据存储

```
data/sources/
├── state.json                            # 数据源状态（元数据）
├── abuseipdb_whitelist.json              # AbuseIPDB 白名单（永久）
├── abuseipdb_safe_cache.json             # AbuseIPDB 安全缓存（30 天）
├── abuseipdb_malicious_cache.json        # AbuseIPDB 恶意缓存（90 天）
├── threatbook_whitelist.json             # ThreatBook 白名单（永久）
├── threatbook_safe_cache.json            # ThreatBook 安全缓存（30 天）
├── custom_enterprise-domains.txt         # 企业自定义域名
└── example_sources.json                  # 示例配置
```

---

## 🤖 ML 域名分类器

### 模型信息

| 属性 | 值 |
|------|---|
| **算法** | LightGBM |
| **训练数据** | PhiUSIIL Phishing URL Dataset (235,795 样本) |
| **特征数** | 15 个域名结构特征 |
| **模型大小** | 286 KB |
| **AUC** | 0.903 |
| **精确率** | 95.2% |

### 特征列表

| 特征 | 说明 |
|------|------|
| `domain_length` | 域名总长度 |
| `sld_length` | 二级域名长度 |
| `tld_length` | TLD 长度 |
| `subdomain_count` | 子域名层数 |
| `tld_is_common` | TLD 是否常见 |
| `sld_entropy` | 二级域名信息熵（DGA 检测） |
| `digit_ratio` | 数字占比 |
| `alpha_ratio` | 字母占比 |
| `hyphen_count` | 连字符数量 |
| `max_consecutive` | 最大连续相同字符 |
| `transition_ratio` | 数字/字母交替率 |
| `vowel_ratio` | 元音占比 |
| `is_ip` | 是否为 IP 地址 |

### 重新训练

```bash
pip install lightgbm scikit-learn
python scripts/train_domain_classifier.py
```

模型会保存到 `models/domain_classifier_v1.pkl`。

---

## 🔐 AbuseIPDB 三级缓存

| 缓存类型 | 有效期 | 说明 |
|---------|--------|------|
| **白名单** | 永久 | 知名云服务 IP（Google/AWS/Cloudflare），abuse_score = 0 |
| **安全缓存** | 30 天 | 本次查询未发现异常，abuse_score < 10 |
| **恶意缓存** | 90 天 | abuse_score >= 10，避免重复查询和告警 |

> 三级缓存完全隔离，安全条目和恶意条目不会互相覆盖。

---

## 📝 手动更新数据源

```bash
# 使用 CLI 分析时会自动检查和更新
python -m cli analyze data/capture.pcap

# 交互式模式下会询问是否更新
# 非交互式模式（--no-threat-intel）跳过更新
```

---

## ⚙️ 自定义数据源

编辑 `data/sources/example_sources.json` 作为模板：

```json
{
  "name": "my_custom_source",
  "category": "threat_domains",
  "source_type": "remote_url",
  "url_or_path": "https://example.com/threats.txt",
  "update_interval_hours": 24,
  "format": "text"
}
```

支持格式：`text`（每行一个）、`csv`、`json`。

---

**返回 [快速开始](QUICK_START.md)**
