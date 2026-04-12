# 🔍 NetflowSight

**AI-Powered Network Traffic Analysis Platform** | **AI 驱动的网络流量分析平台**

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/status-active-brightgreen)]()

---

## 🇬🇧 English | 🇨🇳 中文

<details>
<summary>🇨🇳 点击切换到中文版 / Click to switch to Chinese version</summary>

## 📖 项目简介

NetflowSight 是一个基于 **NFStream** 高性能解析引擎的智能网络流量分析平台。该项目旨在解决传统抓包工具（如 Wireshark）在大规模数据下分析困难、误报率高、缺乏关联分析的问题。

> **核心目标**：在 AI 处理数据包之前，先对 PCAP 进行一次智能预处理，生成结构化的分析报告，为 AI 深度分析提供高质量上下文。

### ✨ 核心特性

*   **🚀 高性能解析**：基于 NFStream C 语言底层，支持 GB 级 PCAP 秒级处理，100+ 自动流特征提取。
*   **🎯 零误报策略**：采用本地黑名单情报库 + 微步/AbuseIPDB 智能缓存，只对已知威胁告警。
*   **🤖 双报告生成**：同时生成人类可读报告和 AI 优化报告，自动包含建议分析提示词。
*   **💾 智能情报缓存**：
    *   **白名单**：知名服务永久保存（Google/AWS/Cloudflare 等）
    *   **安全缓存**：安全 IP/域名 30 天缓存，避免重复 API 查询
*   **🔌 插件化架构**：支持自定义检测引擎，轻松扩展新威胁类型。

---

## 🚀 快速开始

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

# 编辑 .env 添加 API Keys（可选，本地检测无需 API Key）
ABUSEIPDB_API_KEY=your_key_here
THREATBOOK_API_KEY=your_key_here
```

### 3. 运行分析

```bash
# 将 PCAP 文件放入 data/ 目录
# 运行测试脚本
python test_pcap.py
```

### 4. 查看结果

分析完成后会生成两份报告：

```
data/reports/
├── test_analysis_20260412_112007.json    # 人类可读报告
└── test_analysis_20260412_112007_ai.json # AI 优化报告
```

---

## 🏗️ 架构概览

```
NetflowSight/
├── src/                          # 核心源码
│   ├── core/                     # 核心解析层 (NFStream 封装)
│   ├── engines/                  # 威胁检测引擎 (5 大引擎)
│   │   ├── dns/                  # DNS 威胁检测 (黑名单、隧道、钓鱼、DGA)
│   │   ├── http/                 # HTTP 威胁检测 (异常流量、端口、UA)
│   │   ├── covert/               # 隐蔽通道检测 (ICMP/DNS 隧道、TLS)
│   │   ├── behavior/             # 行为异常检测 (大流量、端口扫描)
│   │   ├── smart_threat.py       # 微步在线 ThreatBook 智能检测
│   │   └── abuseipdb_detector.py # AbuseIPDB 智能检测
│   ├── datasource/               # 威胁情报管理 (数据源管理器)
│   ├── intel/                    # 威胁情报客户端 (API 集成)
│   ├── ml/                       # 机器学习层 (Isolation Forest)
│   ├── report/                   # 报告生成 (人类 + AI 报告)
│   ├── analyzer.py               # 主协调器
│   └── cli.py                    # CLI 接口
├── data/                         # 数据存储 (情报源 + 报告)
└── docs/                         # 工程文档
```

---

## 📊 分析流程

```
[1] 初始化数据源管理器
    └→ 首次运行自动更新，后续询问用户
        ↓
[2] 加载本地威胁情报
    └→ PhishTank, URLhaus, Spamhaus, 白名单缓存
        ↓
[3] 解析 PCAP 文件 (NFStream)
    └→ 100+ 流特征提取
        ↓
[4] ML 异常检测 (Isolation Forest)
        ↓
[5] 🟢 本地威胁检测
    └→ DNS, HTTP, Covert, Behavior 引擎
        ↓
[6] 🔵 API 威胁情报 (智能缓存)
    └→ 微步在线 (域名) + AbuseIPDB (IP)
        ↓
[7] 生成报告
    └→ 人类可读报告 + AI 优化报告
```

---

## 🔧 配置说明

### 环境变量

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `ABUSEIPDB_API_KEY` | AbuseIPDB API Key | 无 |
| `THREATBOOK_API_KEY` | 微步在线 API Key | 无 |
| `OPENAI_API_KEY` | OpenAI API Key (AI 报告) | 无 |
| `STATISTICAL_ANALYSIS` | 启用统计分析 | `true` |
| `N_DISSECTIONS` | DPI 解析包数 | `20` |
| `DECODE_TUNNELS` | 启用隧道解码 | `true` |

### 获取免费 API Key

| 服务 | 免费额度 | 申请地址 |
|------|---------|---------|
| **AbuseIPDB** | 1,000 次/天 | https://www.abuseipdb.com/register |
| **微步在线** | 1,000 次/天 | https://x.threatbook.com/register |

---

## 📚 文档

*   [🚀 快速开始](docs/QUICK_START.md) - 5 分钟上手指南
*   [📊 工程报告](docs/ENGINEERING_REPORT.md) - 完整架构设计
*   [📁 数据源管理](docs/DATA_SOURCE_GUIDE.md) - 威胁情报配置指南

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

---

## 📄 许可证

本项目基于 [MIT License](LICENSE) 开源。

---

**Made with ❤️ by Prometheus Projects Team**

</details>

---

## 📖 Overview

NetflowSight is an intelligent network traffic analysis platform based on the **NFStream** high-performance parsing engine. It aims to solve the problems of traditional packet capture tools (like Wireshark) such as difficulty in large-scale data analysis, high false positive rates, and lack of correlation analysis.

> **Core Objective**: Perform intelligent preprocessing on PCAP data before AI processing, generating structured analysis reports to provide high-quality context for AI deep analysis.

### ✨ Key Features

*   **🚀 High-Performance Parsing**: Built on NFStream C-based engine, supports GB-level PCAP second-level processing with 100+ automatic flow feature extraction.
*   **🎯 Zero False Positive Strategy**: Uses local blacklist intelligence library + ThreatBook/AbuseIPDB smart caching, only alerts on known threats.
*   **🤖 Dual Report Generation**: Generates both human-readable and AI-optimized reports simultaneously, automatically includes suggested analysis prompts.
*   **💾 Smart Intelligence Caching**:
    *   **Whitelist**: Well-known services permanently saved (Google/AWS/Cloudflare, etc.)
    *   **Safe Cache**: Safe IPs/domains cached for 30 days, avoiding repeated API queries
*   **🔌 Plugin Architecture**: Supports custom detection engines, easily extensible for new threat types.

---

## 🚀 Quick Start

### 1. Installation

```bash
# Clone repository
git clone https://github.com/Mal-Suen/NetflowSight.git
cd NetflowSight

# Install dependencies
pip install -e .
```

### 2. Configuration

```bash
# Copy environment variables file
cp .env.example .env

# Edit .env to add API Keys (optional, local detection requires no API Key)
ABUSEIPDB_API_KEY=your_key_here
THREATBOOK_API_KEY=your_key_here
```

### 3. Run Analysis

```bash
# Place PCAP file in data/ directory
# Run test script
python test_pcap.py
```

### 4. View Results

After analysis, two reports will be generated:

```
data/reports/
├── test_analysis_20260412_112007.json    # Human-readable report
└── test_analysis_20260412_112007_ai.json # AI-optimized report
```

---

## 🏗️ Architecture Overview

```
NetflowSight/
├── src/                          # Core source code
│   ├── core/                     # Core parsing layer (NFStream wrapper)
│   ├── engines/                  # Threat detection engines (5 major engines)
│   │   ├── dns/                  # DNS threat detection (blacklist, tunnel, phishing, DGA)
│   │   ├── http/                 # HTTP threat detection (anomaly traffic, ports, UA)
│   │   ├── covert/               # Covert channel detection (ICMP/DNS tunnel, TLS)
│   │   ├── behavior/             # Behavioral anomaly detection (large traffic, port scan)
│   │   ├── smart_threat.py       # ThreatBook smart detection
│   │   └── abuseipdb_detector.py # AbuseIPDB smart detection
│   ├── datasource/               # Threat intelligence management (DataSourceManager)
│   ├── intel/                    # Threat intelligence clients (API integration)
│   ├── ml/                       # Machine learning layer (Isolation Forest)
│   ├── report/                   # Report generation (Human + AI reports)
│   ├── analyzer.py               # Main orchestrator
│   └── cli.py                    # CLI interface
├── data/                         # Data storage (intelligence sources + reports)
└── docs/                         # Engineering documentation
```

---

## 📊 Analysis Pipeline

```
[1] Initialize DataSourceManager
    └→ Auto-update on first run, prompt user on subsequent runs
        ↓
[2] Load local threat intelligence
    └→ PhishTank, URLhaus, Spamhaus, whitelist cache
        ↓
[3] Parse PCAP file (NFStream)
    └→ 100+ flow feature extraction
        ↓
[4] ML Anomaly Detection (Isolation Forest)
        ↓
[5] 🟢 Local Threat Detection
    └→ DNS, HTTP, Covert, Behavior engines
        ↓
[6] 🔵 API Threat Intelligence (Smart Caching)
    └→ ThreatBook (domains) + AbuseIPDB (IPs)
        ↓
[7] Generate Reports
    └→ Human-readable report + AI-optimized report
```

---

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ABUSEIPDB_API_KEY` | AbuseIPDB API Key | None |
| `THREATBOOK_API_KEY` | ThreatBook API Key | None |
| `OPENAI_API_KEY` | OpenAI API Key (AI reports) | None |
| `STATISTICAL_ANALYSIS` | Enable statistical analysis | `true` |
| `N_DISSECTIONS` | Number of packets for DPI | `20` |
| `DECODE_TUNNELS` | Enable tunnel decoding | `true` |

### Get Free API Keys

| Service | Free Quota | Registration |
|---------|-----------|--------------|
| **AbuseIPDB** | 1,000 queries/day | https://www.abuseipdb.com/register |
| **ThreatBook** | 1,000 queries/day | https://x.threatbook.com/register |

---

## 📚 Documentation

*   [🚀 Quick Start](docs/QUICK_START.md) - 5-minute getting started guide
*   [📊 Engineering Report](docs/ENGINEERING_REPORT.md) - Complete architecture design
*   [📁 Data Source Guide](docs/DATA_SOURCE_GUIDE.md) - Threat intelligence configuration guide

---

## 🤝 Contributing

Pull Requests and Issues are welcome!

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is open-sourced under the [MIT License](LICENSE).

---

**Made with ❤️ by Prometheus Projects Team**
