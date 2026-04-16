# 🔍 NetflowSight

> **AI-Powered Network Traffic Analysis Platform** | **AI 驱动的网络流量分析平台**

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

| Feature | Detail |
| :--- | :--- |
| **🚀 High-Performance Parsing** | Built on NFStream C-based engine. GB-level PCAP processing in seconds with 100+ automatic flow feature extraction. |
| **🤖 ML Domain Classifier** | LightGBM trained on 235K+ samples (AUC 0.903). Automatically identifies phishing/malicious domains. |
| **🎯 Zero False Positive** | Local blacklist + AbuseIPDB 3-tier cache (whitelist/safe/malicious). Only alerts on known threats. |
| **📊 Visual Reports** | Chart.js interactive charts, collapsible alerts, Top 10 threats, API usage statistics. |
| **🔌 Plugin Architecture** | Extensible detection via `BaseDetectionPlugin`. Add custom detectors in `plugins/external/`. |
| **📁 Extensible Data Sources** | 10 sources, 43K+ threat indicators. Add local files or remote URLs via `DataSourceManager`. |
| **🔬 Complete Test Suite** | 61 unit tests covering core modules. `pytest tests/ -v` |

### 📊 Detection Capabilities

| Detection Type | Engine | Methods |
| :--- | :--- | :--- |
| **DNS Threats** | `dns_detector` | Blacklist matching, ML classification, DNS tunnel, DGA detection |
| **HTTP Threats** | `http_detector` | Anomaly responses, suspicious User-Agent, malicious URLs |
| **Covert Channels** | `covert_detector` | ICMP/DNS tunneling, unknown TLS protocols |
| **Behavior Anomalies** | `behavior_detector` | Large traffic, port scanning, internal/external communication |
| **Port Scanning** | `port_scan_detector` | Multi-port connection detection (external plugin) |
| **Data Exfiltration** | `data_exfil_detector` | Large outbound transfer detection (external plugin) |

### 🚀 Quick Start

#### Installation

```bash
# Clone repository
git clone https://github.com/Mal-Suen/NetflowSight.git
cd NetflowSight

# Install dependencies
pip install -e .

# Optional: ML dependencies
pip install lightgbm scikit-learn
```

#### Run Analysis

```bash
cd src

# Basic analysis
python -m cli analyze ../data/capture.pcap

# Local detection only (no API calls)
python -m cli analyze ../data/capture.pcap --no-threat-intel

# Specify output path
python -m cli analyze ../data/capture.pcap -o reports/my_report.html
```

#### View Results

```
data/reports/
├── 20260413_084406_capture_report.html  # HTML visual report
└── 20260413_084406_capture_report.json  # JSON data report
```

### 🏗️ Architecture

```
NetflowSight/
├── src/                          # Core source code
│   ├── core/                     # Config, models, NFStream parser
│   ├── engines/                  # Built-in detection engines
│   ├── intel/                    # Threat intelligence (AbuseIPDB, ThreatBook)
│   ├── ml/                       # ML classifiers (LightGBM, Isolation Forest)
│   ├── datasource/               # Threat data source management
│   ├── plugins/                  # Plugin system
│   │   ├── base.py               # BaseDetectionPlugin
│   │   ├── manager.py            # PluginManager
│   │   └── external/             # External plugins directory
│   ├── report/                   # Report generation (HTML + JSON)
│   └── cli.py                    # CLI entry point
├── data/sources/                 # Threat intelligence data (43K+ indicators)
├── models/                       # Trained ML models
└── tests/                        # Unit tests (61 cases)
```

### 📊 Analysis Pipeline

```
[1] Initialize DataSourceManager
    └→ Auto-update on first run, use cache on subsequent runs
        ↓
[2] Parse PCAP file (NFStream)
    └→ 100+ flow feature extraction
        ↓
[3] ML Anomaly Detection (Isolation Forest)
    └→ Unsupervised learning, no labeled data required
        ↓
[4] 🟢 Plugin-based Threat Detection
    └→ DNS / HTTP / Covert / Behavior / Custom plugins
        ↓
[5] 🔵 API Threat Intelligence (Smart Caching)
    └→ ML high-risk domains → ThreatBook verification
    └→ External IPs → AbuseIPDB 3-tier cache query
        ↓
[6] Generate HTML + JSON Reports
```

### 🔧 CLI Commands

```bash
# Basic usage
python -m cli analyze <pcap_file>

# Options
--output, -o          Specify output report path
--format, -f          Report format: html(default), json, markdown, text
--no-ml               Disable ML anomaly detection
--no-threat-intel     Disable threat intelligence API calls
--verbose, -v         Enable verbose logging
```

### 📚 Documentation

| Document | Description |
| :--- | :--- |
| [📊 Engineering Report](docs/ENGINEERING_REPORT.md) | Complete architecture design |
| [📁 Data Source Guide](docs/data_source_guide.md) | Threat intelligence configuration |
| [🔌 Plugin Development](docs/plugin_development.md) | Plugin system and custom detection |
| [🚀 Quick Start](docs/QUICK_START.md) | 5-minute getting started guide |

### 🤝 Contributing

```bash
# Run tests
pip install pytest
pytest tests/ -v
```

Pull Requests and Issues are welcome!

### 📄 License

This project is open-sourced under the [MIT License](LICENSE).

---

<a name="-中文"></a>

## 🇨🇳 中文

### 📖 项目简介

NetflowSight 是一个基于 **NFStream** 高性能解析引擎的智能网络流量分析平台。结合 **LightGBM** 机器学习域名分类器与多引擎威胁检测，实现对 PCAP 流量的自动化、智能化分析。

> **核心目标**：在 AI 处理数据包之前，先对 PCAP 进行智能预处理，生成包含可视化图表的结构化分析报告。

### ✨ 核心特性

| 特性 | 细节 |
| :--- | :--- |
| **🚀 高性能解析** | 基于 NFStream C 语言底层。GB 级 PCAP 秒级处理，100+ 自动流特征提取。 |
| **🤖 ML 域名分类器** | LightGBM 训练 23 万+样本（AUC 0.903）。自动识别钓鱼/恶意域名。 |
| **🎯 零误报策略** | 本地黑名单 + AbuseIPDB 三级缓存（白名单/安全/恶意）。只对已知威胁告警。 |
| **📊 可视化报告** | Chart.js 交互式图表、可折叠告警、Top 10 威胁、API 使用统计。 |
| **🔌 插件化架构** | 通过 `BaseDetectionPlugin` 扩展检测。在 `plugins/external/` 添加自定义检测器。 |
| **📁 可扩展数据源** | 10 个数据源，43K+ 威胁指标。通过 `DataSourceManager` 添加本地/远程源。 |
| **🔬 完整测试套件** | 61 个单元测试覆盖核心模块。`pytest tests/ -v` |

### 📊 检测能力

| 检测类型 | 引擎 | 方法 |
| :--- | :--- | :--- |
| **DNS 威胁** | `dns_detector` | 黑名单匹配、ML 分类、DNS 隧道、DGA 检测 |
| **HTTP 威胁** | `http_detector` | 异常响应、可疑 User-Agent、恶意 URL |
| **隐蔽通道** | `covert_detector` | ICMP/DNS 隧道、未知 TLS 协议 |
| **行为异常** | `behavior_detector` | 大流量、端口扫描、内外网通信 |
| **端口扫描** | `port_scan_detector` | 多端口连接检测（外部插件） |
| **数据泄露** | `data_exfil_detector` | 大流量外传检测（外部插件） |

### 🚀 快速开始

#### 安装

```bash
# 克隆仓库
git clone https://github.com/Mal-Suen/NetflowSight.git
cd NetflowSight

# 安装依赖
pip install -e .

# 可选：ML 依赖
pip install lightgbm scikit-learn
```

#### 运行分析

```bash
cd src

# 基本分析
python -m cli analyze ../data/capture.pcap

# 纯本地检测（不调用 API）
python -m cli analyze ../data/capture.pcap --no-threat-intel

# 指定输出路径
python -m cli analyze ../data/capture.pcap -o reports/my_report.html
```

#### 查看结果

```
data/reports/
├── 20260413_084406_capture_report.html  # HTML 可视化报告
└── 20260413_084406_capture_report.json  # JSON 数据报告
```

### 🏗️ 架构概览

```
NetflowSight/
├── src/                          # 核心源码
│   ├── core/                     # 配置、模型、NFStream 解析器
│   ├── engines/                  # 内置检测引擎
│   ├── intel/                    # 威胁情报 (AbuseIPDB, ThreatBook)
│   ├── ml/                       # ML 分类器 (LightGBM, Isolation Forest)
│   ├── datasource/               # 威胁数据源管理
│   ├── plugins/                  # 插件系统
│   │   ├── base.py               # BaseDetectionPlugin
│   │   ├── manager.py            # PluginManager
│   │   └── external/             # 外部插件目录
│   ├── report/                   # 报告生成 (HTML + JSON)
│   └── cli.py                    # CLI 入口
├── data/sources/                 # 威胁情报数据 (43K+ 指标)
├── models/                       # 训练好的 ML 模型
└── tests/                        # 单元测试 (61 个用例)
```

### 📊 分析流程

```
[1] 初始化数据源管理器
    └→ 首次运行自动更新，后续使用缓存
        ↓
[2] 解析 PCAP 文件 (NFStream)
    └→ 100+ 流特征自动提取
        ↓
[3] ML 异常检测 (Isolation Forest)
    └→ 无监督学习，无需标注数据
        ↓
[4] 🟢 插件化威胁检测
    └→ DNS / HTTP / 隐蔽通道 / 行为 / 自定义插件
        ↓
[5] 🔵 API 威胁情报 (智能缓存)
    └→ ML 高危域名 → ThreatBook 复核
    └→ 外部 IP → AbuseIPDB 三级缓存查询
        ↓
[6] 生成 HTML + JSON 报告
```

### 🔧 CLI 命令

```bash
# 基本用法
python -m cli analyze <pcap文件>

# 选项
--output, -o          指定输出报告路径
--format, -f          报告格式: html(默认), json, markdown, text
--no-ml               禁用 ML 异常检测
--no-threat-intel     禁用威胁情报 API 调用
--verbose, -v         启用详细日志输出
```

### 📚 文档

| 文档 | 说明 |
| :--- | :--- |
| [📊 工程报告](docs/ENGINEERING_REPORT.md) | 完整架构设计 |
| [📁 数据源管理](docs/data_source_guide.md) | 威胁情报配置 |
| [🔌 插件开发](docs/plugin_development.md) | 插件系统与自定义检测 |
| [🚀 快速开始](docs/QUICK_START.md) | 5 分钟上手指南 |

### 🤝 贡献

```bash
# 运行测试
pip install pytest
pytest tests/ -v
```

欢迎提交 Issue 和 Pull Request！

### 📄 许可证

本项目基于 [MIT License](LICENSE) 开源。
