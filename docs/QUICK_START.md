# NetflowSight 快速开始指南

## 📋 概述

NetflowSight 是一个 AI 驱动的网络流量分析平台，结合 LightGBM 机器学习与多引擎威胁检测，实现对 PCAP 流量的自动化智能分析。

---

## 🚀 5 分钟快速上手

### 1. 安装

```bash
# 克隆仓库
git clone https://github.com/Mal-Suen/NetflowSight.git
cd NetflowSight

# 安装依赖
pip install -e .

# 可选：安装 ML 依赖（域名分类器需要）
pip install lightgbm scikit-learn
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
# 使用 CLI（推荐）
cd src
python -m cli analyze ../data/capture.pcap

# 纯本地检测（不调用 API）
python -m cli analyze ../data/capture.pcap --no-threat-intel
```

---

## 📊 分析结果

分析完成后自动生成两份报告：

```
data/reports/
├── 20260413_084406_capture_report.html  # HTML 可视化报告
└── 20260413_084406_capture_report.json  # JSON 数据报告
```

### HTML 报告包含

*   **统计卡片**：流量数、数据包、字节数、威胁数量
*   **4 个交互式图表**：协议分布、威胁类型、检测引擎、严重程度
*   **Top 10 威胁**：详细展示前 10 条高危/中危告警
*   **全部告警**：可折叠展开，包含证据、IOC 和处置建议
*   **API 使用统计**：AbuseIPDB 和 ThreatBook 的查询/缓存情况

### 终端输出示例

```
🔍 NetflowSight 分析报告

📊 流量摘要
   总流量数: 412
   总数据包数: 48,615
   总字节数: 42.09 MB

🚨 威胁摘要
   高危: 24
   中危: 30
   低危: 0

   Top 5 威胁:
   1. [HIGH] UNKNOWN_DOMAIN — ML 域名分类器检测到可疑域名
   2. [HIGH] DNS_TUNNEL — 检测到潜在的 DNS 隧道行为
   3. [HIGH] DGA_DOMAIN — 检测到 DGA 特征域名
   4. [MEDIUM] HTTP_EXFILTRATION — 检测到 HTTP 响应异常
   5. [MEDIUM] SUSPICIOUS_USER_AGENT — 检测到可疑 User-Agent

💾 报告已保存:
   🌐 HTML: data/reports/20260413_084406_capture_report.html
   📋 JSON: data/reports/20260413_084406_capture_report.json

🌐 AbuseIPDB API 使用情况:
   已查询: 0 次 | 缓存命中: 72 次 | 白名单: 44 个
```

---

## 🔧 CLI 命令

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

---

## 🎯 核心功能

### 本地威胁检测（零 API 消耗）

| 引擎 | 检测内容 |
|------|---------|
| **DNS** | 黑名单域名、ML 域名分类、DNS 隧道、DGA 域名 |
| **HTTP** | 异常响应流量、非常用端口、可疑 User-Agent |
| **Covert** | ICMP 隧道、DNS 外泄、未知 TLS、单向传输 |
| **Behavior** | 大流量传输、可疑通信、端口扫描 |

### ML 域名分类器

*   **模型**: LightGBM (286 KB)
*   **训练数据**: PhiUSIIL 数据集 (235,795 样本)
*   **性能**: AUC 0.903，准确率 87.3%，精确率 95.2%
*   **用途**: 自动识别钓鱼/恶意域名，无需人工维护规则

### API 威胁情报（智能缓存）

| 数据源 | 用途 | 缓存机制 |
|--------|------|---------|
| **AbuseIPDB** | IP 信誉检查 | 白名单永久 + 安全缓存 30 天 + 恶意缓存 90 天 |
| **ThreatBook** | 域名威胁复核 | 白名单永久 + 安全缓存 30 天 |

> ML 检测出的高危域名会自动发送给 ThreatBook API 复核，无需手动配置。

---

## 📁 项目结构

```
NetflowSight/
├── src/                    # 核心源码
│   ├── core/               # 核心解析层 (配置、模型、NFStream)
│   ├── engines/            # 威胁检测引擎
│   │   ├── domain_classifier.py  # ML 域名分类器
│   │   ├── abuseipdb_detector.py # AbuseIPDB 智能检测
│   │   ├── smart_threat.py       # ThreatBook 域名复核
│   │   ├── dns/                  # DNS 检测引擎
│   │   ├── http/                 # HTTP 检测引擎
│   │   ├── covert/               # 隐蔽通道检测
│   │   └── behavior/             # 行为异常检测
│   ├── datasource/         # 威胁情报数据源管理
│   ├── intel/              # 威胁情报客户端
│   ├── ml/                 # ML 异常分类器
│   ├── report/             # 报告生成 (HTML + JSON)
│   ├── analyzer.py         # 主分析协调器
│   └── cli.py              # CLI 命令行接口
├── scripts/                # 工具脚本
│   └── train_domain_classifier.py  # 模型训练
├── models/                 # 训练好的 ML 模型
├── tests/                  # 单元测试 (61 个用例)
├── data/                   # 数据存储 (情报源 + 报告)
└── docs/                   # 工程文档
```

---

## 📝 运行测试

```bash
pip install pytest
pytest tests/ -v
```

当前测试状态：**61 passed, 0 failed**

---

## 📞 常见问题

**Q: 没有 API Key 可以使用吗？**

A: 可以！本地威胁检测引擎（DNS/HTTP/Covert/Behavior）和 ML 域名分类器不需要任何 API Key。只有 API 情报查询需要 Key。

**Q: API 额度不够怎么办？**

A: AbuseIPDB 采用三级缓存（白名单永久 / 安全 30 天 / 恶意 90 天），缓存命中不消耗额度。ThreatBook 同理。

**Q: 如何重新训练域名分类器？**

A: 运行 `python scripts/train_domain_classifier.py`，需要 PhiUSIIL Phishing URL Dataset。

**Q: HTML 报告在哪里查看？**

A: 用浏览器打开 `data/reports/*.html` 即可。需要联网加载 Chart.js（CDN）。

---

**更多文档请查看 `docs/` 目录**
