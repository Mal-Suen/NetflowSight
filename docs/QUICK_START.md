# NetflowSight 快速开始指南

## 📋 概述

NetflowSight 是一个 AI 驱动的网络流量分析平台，专为 **AI 预处理 PCAP 数据** 而设计。

---

## 🚀 5 分钟快速上手

### 1. 安装

```bash
# 克隆仓库
git clone https://github.com/Mal-Suen/NetflowSight.git
cd NetflowSight

# 安装依赖
pip install -e .
```

### 2. 配置

```bash
# 复制环境变量文件
cp .env.example .env

# 编辑 .env 添加 API Keys（可选）
ABUSEIPDB_API_KEY=your_key_here
THREATBOOK_API_KEY=your_key_here
```

### 3. 运行分析

```bash
# 将 PCAP 文件放入 data/ 目录
# 运行测试脚本
python test_pcap.py
```

---

## 📊 分析结果示例

```
📊 Analysis Summary
   Total Flows:       412
   Total Packets:     48,615
   Total Bytes:       41103.8 KB
   Unique Src IPs:    7
   Unique Dst IPs:    77
   ML Anomalies:      21

🚨 Threat Summary
   🔴 High:   14
   🟡 Medium: 30
   Total:     44

   Top 15 Threats:
   1. [HIGH] DNS_TUNNEL - 检测到潜在的 DNS 隧道行为
   2. [HIGH] DGA_DOMAIN - 检测到 DGA 特征域名
   3. [MEDIUM] HTTP_EXFILTRATION - 检测到 HTTP 响应异常
   ...
```

---

## 🔧 核心功能

### 本地威胁检测（零 API 消耗）

| 引擎 | 检测内容 |
|------|---------|
| DNS | 黑名单域名、DNS 隧道、钓鱼域名、DGA 域名 |
| HTTP | 异常流量、非常用端口、可疑 User-Agent |
| Covert | ICMP 隧道、DNS 外泄、未知 TLS、单向传输 |
| Behavior | 大流量传输、可疑通信、端口扫描 |

### API 威胁情报（智能缓存）

| 数据源 | 用途 | 缓存机制 |
|--------|------|---------|
| 微步在线 | 域名威胁情报 | 白名单永久 + 安全缓存 30 天 |
| AbuseIPDB | IP 信誉检查 | 白名单永久 + 安全缓存 30 天 |

---

## 📁 项目结构

```
NetflowSight/
├── src/                    # 核心源码
│   ├── core/               # 核心解析层
│   ├── engines/            # 威胁检测引擎
│   ├── datasource/         # 威胁情报管理
│   ├── intel/              # 威胁情报客户端
│   ├── ml/                 # 机器学习层
│   ├── report/             # 报告生成
│   └── analyzer.py         # 主协调器
├── data/                   # 数据存储
├── docs/                   # 工程文档
├── .env                    # 环境变量
└── README.md               # 项目说明
```

---

## 🎯 数据更新机制

### 首次运行

系统会**自动更新**所有数据源，无需手动干预：

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

### 手动更新

```bash
python update_sources.py
```

---

## 📝 生成报告

### 人类可读报告

```markdown
# 🔍 NetflowSight Analysis Report

## 📊 Summary
- **Total Flows**: 412
- **Total Packets**: 48,615

## 🚨 Threat Summary
- **High Severity**: 14
- **Medium Severity**: 30
```

### AI 优化报告

```json
{
  "context": {
    "traffic_summary": {...},
    "threat_summary": {...}
  },
  "threats": {
    "by_type": {...},
    "top_threats": [...]
  },
  "suggested_ai_prompts": [
    "检测到 DNS 隧道迹象，请分析是否为数据外泄...",
    ...
  ],
  "ai_analysis_instructions": "你是一位高级网络安全分析师..."
}
```

---

## 📞 常见问题

**Q: 没有 API Key 可以使用吗？**

A: 可以！本地威胁检测引擎（DNS/HTTP/Covert/Behavior）不需要任何 API Key，只有智能威胁检测（微步/AbuseIPDB）需要 API Key。

**Q: API 额度不够怎么办？**

A: 智能检测器会自动缓存查询结果，白名单永久保存，安全缓存 30 天有效。缓存命中不消耗 API 额度。

**Q: 如何添加自定义数据源？**

A: 编辑 `data/sources/example_sources.json`，添加你的数据源配置。

---

**更多文档请查看 `docs/` 目录**
