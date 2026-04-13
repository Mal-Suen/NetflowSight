# NetflowSight 项目工程报告

**版本**: v1.1.0 (Refactored)
**日期**: 2026-04-13
**维护者**: Prometheus Projects Team

---

## 1. 项目概况

NetflowSight 是一个基于 **NFStream** 高性能解析引擎的智能网络流量分析平台。结合 **LightGBM** 机器学习域名分类器与多引擎威胁检测，实现对 PCAP 流量的自动化、智能化分析。

### 核心特性
*   **高性能解析**：基于 C 语言底层，GB 级 PCAP 秒级处理，100+ 自动流特征。
*   **ML 域名分类器**：LightGBM 训练 23 万+样本（AUC 0.903），自动识别钓鱼/恶意域名。
*   **可视化 HTML 报告**：Chart.js 交互式图表、可折叠告警、API 使用统计。
*   **智能情报缓存**：AbuseIPDB 三级缓存（白名单/安全/恶意），缓存命中零 API 消耗。
*   **完整测试套件**：61 个单元测试，确保代码质量。

---

## 2. 架构设计

```text
NetflowSight/
├── src/                          # 核心源码
│   ├── core/                     # 核心层
│   │   ├── parser.py             # NFStream 封装 (100+ 自动特征)
│   │   ├── models.py             # 数据模型 (统一来源)
│   │   └── config.py             # 全局配置管理
│   │
│   ├── engines/                  # 威胁检测引擎
│   │   ├── domain_classifier.py  # ML 域名分类器 (LightGBM)
│   │   ├── abuseipdb_detector.py # AbuseIPDB 智能检测 (三级缓存)
│   │   ├── smart_threat.py       # ThreatBook 域名复核
│   │   ├── dns/                  # DNS 检测 (黑名单+ML+隧道+DGA)
│   │   ├── http/                 # HTTP 检测
│   │   ├── covert/               # 隐蔽通道检测
│   │   └── behavior/             # 行为异常检测
│   │
│   ├── datasource/               # 威胁情报管理
│   │   ├── manager.py            # 数据源管理器 (ETag、增量更新)
│   │   └── strategy.py           # 策略推荐引擎
│   │
│   ├── intel/                    # 威胁情报客户端
│   │   ├── client.py             # AbuseIPDB API
│   │   ├── cache.py              # IP 威胁缓存
│   │   └── threatbook.py         # 微步 API
│   │
│   ├── ml/                       # 机器学习层
│   │   └── classifier.py         # Isolation Forest 异常检测
│   │
│   ├── report/                   # 报告生成
│   │   ├── generator.py          # JSON/Markdown/Text 报告
│   │   └── html_generator.py     # HTML 可视化报告 (Chart.js)
│   │
│   ├── analyzer.py               # 主分析协调器
│   └── cli.py                    # CLI 命令行接口
│
├── scripts/                      # 工具脚本
│   └── train_domain_classifier.py  # 域名分类模型训练
├── models/                       # 训练好的 ML 模型
│   └── domain_classifier_v1.pkl  # LightGBM 域名分类器 (286 KB)
├── tests/                        # 单元测试 (61 个用例)
├── data/                         # 数据存储
└── docs/                         # 工程文档
```

---

## 3. 分析流程

```
[1] 初始化 DataSourceManager
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

---

## 4. 代码质量

### 清理记录

| 操作 | 文件 | 原因 |
|------|------|------|
| 删除 | `intel/fusion.py` | 从未被调用，AbuseIPDB 逻辑与 client.py 重复 |
| 删除 | `report/ai_report.py` | AIAnalysisReport 从未使用，与 generator.py 功能重复 |
| 删除 | `plugins/registry.py` | EngineRegistry/PluginManager 从未实例化 |
| 删除 | `PluginBase` 类 | 无引擎继承，所有引擎使用 Protocol 模式 |
| 修复 | `analyzer.py` | 删除重复的 DataSourceManager 实例化 |
| 整合 | `smart_threat.py` | 域名规则检查委托给 domain_classifier.py |

### 测试覆盖

| 模块 | 测试数 | 状态 |
|------|--------|------|
| 数据模型 | 14 | ✅ 通过 |
| 数据源管理 | 17 | ✅ 通过 |
| 域名分类器 | 10 | ✅ 通过 |
| ML 分类器 | 10 | ✅ 通过 |
| AbuseIPDB | 9 | ✅ 通过 |
| 威胁缓存 | 7 | ✅ 通过 |
| **总计** | **61** | **全部通过** |

---

## 5. ML 域名分类器

### 训练数据

| 属性 | 值 |
|------|---|
| **数据集** | PhiUSIIL Phishing URL Dataset |
| **样本数** | 235,795 (正常 134,850 / 恶意 100,945) |
| **特征数** | 15 个域名结构特征 |

### 模型性能

| 指标 | 值 |
|------|---|
| **算法** | LightGBM |
| **AUC** | 0.903 |
| **准确率** | 87.3% |
| **精确率** | 95.2% |
| **召回率** | 74.1% |
| **模型大小** | 286 KB |

### 特征重要性 (Top 5)

| 特征 | 重要性 | 说明 |
|------|--------|------|
| `domain_length` | 1,192 | 域名总长度 |
| `sld_length` | 943 | 二级域名长度 |
| `subdomain_count` | 764 | 子域名层数 |
| `tld_length` | 735 | TLD 长度 |
| `vowel_ratio` | 659 | 元音占比 |

---

## 6. HTML 报告设计

### 布局结构

```
┌─────────────────────────────────────────────┐
│  🔍 NetflowSight 分析报告                     │
│  生成时间 | PCAP 文件 | 处理耗时               │
├─────────────────────────────────────────────┤
│  [统计卡片] 流量数 / 数据包 / 字节 / 威胁数    │
│  [API 统计] AbuseIPDB / ThreatBook 使用情况   │
├──────────────────┬──────────────────────────┤
│  [协议分布]       │  [威胁类型分布]            │
│   环形图          │   柱状图                   │
├──────────────────┼──────────────────────────┤
│  [检测引擎分布]    │  [威胁严重程度]             │
│   水平柱状图       │   饼图                     │
├─────────────────────────────────────────────┤
│  🚨 Top 10 威胁 (详细展示)                    │
├─────────────────────────────────────────────┤
│  📋 全部告警 (可折叠展开)                      │
│  每条包含: 描述、证据、IOC、处置建议            │
└─────────────────────────────────────────────┘
```

---

## 7. 依赖项

### 核心依赖

| 包 | 版本 | 用途 |
|---|------|------|
| `nfstream` | >=6.5.0 | PCAP 解析引擎 |
| `pandas` | >=2.0.0 | 数据处理 |
| `numpy` | >=1.24.0 | 数值计算 |
| `scikit-learn` | >=1.3.0 | ML 异常检测 |
| `lightgbm` | latest | 域名分类器 |
| `click` | >=8.1.0 | CLI 框架 |
| `rich` | >=13.0.0 | 终端输出 |
| `requests` | >=2.31.0 | HTTP 客户端 |
| `python-dotenv` | >=1.0.0 | 环境变量 |

### 开发依赖

| 包 | 用途 |
|---|------|
| `pytest` | 单元测试 |
| `black` | 代码格式化 |
| `ruff` | 代码检查 |

---

**返回 [README](../README.md)** | [快速开始](QUICK_START.md) | [数据源指南](data_source_guide.md)
