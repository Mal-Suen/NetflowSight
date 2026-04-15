# 🔍 NetflowSight

**AI-Powered Network Traffic Analysis Platform** | **AI 驱动的网络流量分析平台**

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/status-active-brightgreen)]()

---

<div align="center">

**[🇬🇧 English](#-english)** &nbsp;|&nbsp; **[🇨🇳 中文](#-中文)**

</div>

---

<a name="-english"></a>

## 🇬🇧 English

### 📖 Overview

NetflowSight is an intelligent network traffic analysis platform based on the **NFStream** high-performance parsing engine. Combined with **LightGBM** machine learning domain classifier and multi-engine threat detection, it achieves automated and intelligent analysis of PCAP traffic data.

> **Core Objective**: Perform intelligent preprocessing on PCAP data before AI processing, generating structured analysis reports with visual charts to provide high-quality context for AI deep analysis.

### ✨ Key Features

*   **🚀 High-Performance Parsing**: Built on NFStream C-based engine, supports GB-level PCAP second-level processing with 100+ automatic flow feature extraction.
*   **🤖 ML Domain Classifier**: LightGBM trained on 235K+ samples (AUC 0.903), automatically identifies phishing/malicious domains.
*   **🎯 Zero False Positive Strategy**: Local blacklist intelligence + AbuseIPDB three-tier cache (whitelist/safe/malicious), only alerts on known threats.
*   **📊 Visual HTML Reports**: Chart.js interactive charts, collapsible alerts, Top 10 threats display, API usage statistics.
*   **🔌 Plugin Architecture**: Protocol-based detection engine interface, easily extensible for new threat types.
*   **🔬 Complete Test Suite**: 61 unit tests covering core modules, ensuring code quality.

### 🚀 Quick Start

#### 1. Installation

```bash
# Clone repository
git clone https://github.com/Mal-Suen/NetflowSight.git
cd NetflowSight

# Install dependencies
pip install -e .

# Optional: ML dependencies (for domain classifier)
pip install lightgbm scikit-learn
```

#### 2. Configuration

```bash
# Copy environment variables file
cp .env.example .env

# Edit .env to add API Keys (optional, local detection requires no API Key)
ABUSEIPDB_API_KEY=your_key_here
THREATBOOK_API_KEY=your_key_here
```

#### 3. Run Analysis

```bash
# CLI method (recommended)
cd src
python -m cli analyze ../data/capture.pcap

# Local detection only (no API calls)
python -m cli analyze ../data/capture.pcap --no-threat-intel

# Specify output path
python -m cli analyze ../data/capture.pcap -o reports/my_report.html
```

#### 4. View Results

After analysis, HTML and JSON reports are automatically generated:

```
data/reports/
├── 20260413_084406_capture_report.html  # HTML visual report
└── 20260413_084406_capture_report.json  # JSON data report
```

### 🏗️ Architecture

```
NetflowSight/
├── src/                          # Core source code
│   ├── core/                     # Core layer (config, models, NFStream, interfaces)
│   ├── engines/                  # Threat detection engines
│   │   ├── dns/                  # DNS detection engine
│   │   ├── http/                 # HTTP detection engine
│   │   ├── covert/               # Covert channel detection
│   │   └── behavior/             # Behavioral anomaly detection
│   ├── intel/                    # Threat intelligence
│   │   ├── abuseipdb_detector.py # AbuseIPDB smart detection (3-tier cache)
│   │   └── smart_threat.py       # ThreatBook domain verification
│   ├── ml/                       # Machine learning
│   │   ├── anomaly_detector.py   # Isolation Forest anomaly classifier
│   │   └── domain_classifier.py  # LightGBM domain classifier
│   ├── datasource/               # Threat intelligence data source management
│   ├── report/                   # Report generation (HTML + JSON)
│   ├── plugins/                  # Plugin system entry point
│   ├── analyzer.py               # Main analysis orchestrator
│   └── cli.py                    # CLI command-line interface
├── scripts/                      # Utility scripts
│   ├── train_domain_classifier.py  # Domain classifier training
│   ├── check_sources.py          # Check intelligence update status
│   ├── update_sources.py         # Manual intelligence update
│   ├── run.py                    # Interactive test runner
│   └── test_pcap.py              # End-to-end PCAP analysis test
├── models/                       # Trained ML models
│   └── domain_classifier_v1.pkl  # LightGBM domain classifier (286 KB)
├── tests/                        # Unit tests (61 test cases)
├── data/                         # Data storage
│   ├── samples/                  # PCAP sample files
│   ├── reports/                  # Generated analysis reports
│   └── sources/                  # Threat intelligence data
├── logs/                         # Runtime logs
└── .cache/                       # Runtime cache
```

### 📊 Analysis Pipeline

```
[1] Initialize DataSourceManager
    └→ Auto-update on first run, use cache on subsequent runs
        ↓
[2] Load local threat intelligence
    └→ PhishTank, URLhaus, Spamhaus, built-in safe domains
        ↓
[3] Parse PCAP file (NFStream)
    └→ 100+ flow feature extraction
        ↓
[4] ML Anomaly Detection (Isolation Forest)
    └→ Unsupervised learning, no labeled data required
        ↓
[5] 🟢 Local Threat Detection
    └→ DNS (blacklist + ML classification + tunnel + DGA)
    └→ HTTP (anomaly response + suspicious UA)
    └→ Covert (ICMP/DNS tunnel + unknown TLS)
    └→ Behavior (large traffic + port scan + internal/external communication)
        ↓
[6] 🔵 API Threat Intelligence (Smart Caching)
    └→ ML high-risk domains → ThreatBook automatic verification
    └→ External IPs → AbuseIPDB three-tier cache query
        ↓
[7] Generate HTML + JSON Reports
    └→ Chart.js visualization + collapsible alerts + API statistics
```

### 🔧 CLI Commands

```bash
# Basic usage
python -m cli analyze <pcap_file>

# Options
--output, -o          Specify output report path (auto-generated by default)
--format, -f          Report format: html(default), json, markdown, text
--no-ml               Disable ML anomaly detection
--no-threat-intel     Disable threat intelligence API calls
--verbose, -v         Enable verbose logging
```

### 📚 Documentation

*   [📊 Engineering Report](docs/ENGINEERING_REPORT.md) - Complete architecture design
*   [📁 Data Source Guide](docs/data_source_guide.md) - Threat intelligence configuration guide
*   [🚀 Quick Start](docs/QUICK_START.md) - 5-minute getting started guide

### 🤝 Contributing

Pull Requests and Issues are welcome!

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

#### Running Tests

```bash
pip install pytest
pytest tests/ -v
```

Current test status: **61 passed, 0 failed**

### 📄 License

This project is open-sourced under the [MIT License](LICENSE).

---

<a name="-中文"></a>

## 🇨🇳 中文

### 📖 项目简介

NetflowSight 是一个基于 **NFStream** 高性能解析引擎的智能网络流量分析平台。结合 **LightGBM** 机器学习域名分类器与多引擎威胁检测，实现对 PCAP 流量的自动化、智能化分析。

> **核心目标**：在 AI 处理数据包之前，先对 PCAP 进行智能预处理，生成包含可视化图表的结构化分析报告。

### ✨ 核心特性

*   **🚀 高性能解析**：基于 NFStream C 语言底层，GB 级 PCAP 秒级处理，100+ 自动流特征提取。
*   **🤖 ML 域名分类器**：基于 LightGBM 训练 23 万+样本（AUC 0.903），自动识别钓鱼/恶意域名。
*   **🎯 零误报策略**：本地黑名单情报 + AbuseIPDB 三级缓存（白名单/安全/恶意），只对已知威胁告警。
*   **📊 可视化 HTML 报告**：Chart.js 交互式图表、可折叠告警列表、Top 10 威胁展示、API 使用统计。
*   **🔌 插件化架构**：基于 Protocol 的检测引擎接口，轻松扩展新威胁类型。
*   **🔬 完整测试套件**：61 个单元测试覆盖核心模块，确保代码质量。

### 🚀 快速开始

#### 1. 安装

```bash
# 克隆仓库
git clone https://github.com/Mal-Suen/NetflowSight.git
cd NetflowSight

# 安装依赖
pip install -e .

# 可选：ML 依赖（域名分类器需要）
pip install lightgbm scikit-learn
```

#### 2. 配置

```bash
# 复制环境变量文件
cp .env.example .env

# 编辑 .env 添加 API Keys（可选，本地检测无需 API Key）
ABUSEIPDB_API_KEY=your_key_here
THREATBOOK_API_KEY=your_key_here
```

#### 3. 运行分析

```bash
# CLI 方式（推荐）
cd src
python -m cli analyze ../data/capture.pcap

# 纯本地检测（不调用 API）
python -m cli analyze ../data/capture.pcap --no-threat-intel

# 指定输出路径
python -m cli analyze ../data/capture.pcap -o reports/my_report.html
```

#### 4. 查看结果

分析完成后自动生成 HTML 和 JSON 报告：

```
data/reports/
├── 20260413_084406_capture_report.html  # HTML 可视化报告
└── 20260413_084406_capture_report.json  # JSON 数据报告
```

### 🏗️ 架构概览

```
NetflowSight/
├── src/                          # 核心源码
│   ├── core/                     # 核心层（配置、模型、NFStream、接口）
│   ├── engines/                  # 威胁检测引擎
│   │   ├── dns/                  # DNS 检测引擎
│   │   ├── http/                 # HTTP 检测引擎
│   │   ├── covert/               # 隐蔽通道检测
│   │   └── behavior/             # 行为异常检测
│   ├── intel/                    # 威胁情报
│   │   ├── abuseipdb_detector.py # AbuseIPDB 智能检测 (三级缓存)
│   │   └── smart_threat.py       # ThreatBook 域名复核
│   ├── ml/                       # 机器学习
│   │   ├── anomaly_detector.py   # Isolation Forest 异常分类器
│   │   └── domain_classifier.py  # LightGBM 域名分类器
│   ├── datasource/               # 威胁情报数据源管理
│   ├── report/                   # 报告生成 (HTML + JSON)
│   ├── plugins/                  # 插件系统入口
│   ├── analyzer.py               # 主分析协调器
│   └── cli.py                    # CLI 命令行接口
├── scripts/                      # 工具脚本
│   ├── train_domain_classifier.py  # 模型训练
│   ├── check_sources.py          # 检查情报更新状态
│   ├── update_sources.py         # 手动更新情报
│   ├── run.py                    # 交互式测试运行
│   └── test_pcap.py              # 端到端 PCAP 分析测试
├── models/                       # 训练好的 ML 模型
│   └── domain_classifier_v1.pkl  # LightGBM 域名分类器 (286 KB)
├── tests/                        # 单元测试 (61 个用例)
├── data/                         # 数据存储
│   ├── samples/                  # PCAP 样本文件
│   ├── reports/                  # 生成的分析报告
│   └── sources/                  # 威胁情报数据
├── logs/                         # 运行日志
└── .cache/                       # 运行时缓存
```

### 📊 分析流程

```
[1] 初始化数据源管理器
    └→ 首次运行自动更新，后续使用缓存
        ↓
[2] 加载本地威胁情报
    └→ PhishTank, URLhaus, Spamhaus, 内置安全域名
        ↓
[3] 解析 PCAP 文件 (NFStream)
    └→ 100+ 流特征自动提取
        ↓
[4] ML 异常检测 (Isolation Forest)
    └→ 无监督学习，无需标注数据
        ↓
[5] 🟢 本地威胁检测
    └→ DNS (黑名单 + ML分类 + 隧道 + DGA)
    └→ HTTP (异常响应 + 可疑UA)
    └→ 隐蔽通道 (ICMP/DNS隧道 + 未知TLS)
    └→ 行为异常 (大流量 + 端口扫描 + 内外网通信)
        ↓
[6] 🔵 API 威胁情报 (智能缓存)
    └→ ML 高危域名 → ThreatBook 自动复核
    └→ 外部 IP → AbuseIPDB 三级缓存查询
        ↓
[7] 生成 HTML + JSON 报告
    └→ Chart.js 可视化 + 可折叠告警 + API 统计
```

### 🔧 CLI 命令

```bash
# 基本用法
python -m cli analyze <pcap文件>

# 选项
--output, -o          指定输出报告路径（默认自动生成）
--format, -f          报告格式: html(默认), json, markdown, text
--no-ml               禁用 ML 异常检测
--no-threat-intel     禁用威胁情报 API 调用
--verbose, -v         启用详细日志输出
```

### 📚 文档

*   [📊 工程报告](docs/ENGINEERING_REPORT.md) - 完整架构设计
*   [📁 数据源管理](docs/data_source_guide.md) - 威胁情报配置指南
*   [🚀 快速开始](docs/QUICK_START.md) - 5 分钟上手指南

### 🤝 贡献

欢迎提交 Issue 和 Pull Request！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

#### 运行测试

```bash
pip install pytest
pytest tests/ -v
```

当前测试状态：**61 passed, 0 failed**

### 📄 许可证

本项目基于 [MIT License](LICENSE) 开源。

