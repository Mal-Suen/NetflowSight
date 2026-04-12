# NetflowSight 项目工程报告

**版本**: v1.0.0 (Stable)
**日期**: 2026-04-12
**维护者**: Prometheus Projects Team

---

## 1. 项目概况

NetflowSight 是一个基于 **NFStream** 高性能解析引擎的智能网络流量分析平台。该项目旨在解决传统抓包工具（如 Wireshark）在大规模数据下分析困难、误报率高、缺乏关联分析的问题。

### 核心特性
*   **高性能解析**：基于 C 语言底层，支持 GB 级 PCAP 秒级处理。
*   **智能降噪**：采用**本地黑名单情报库** + **微步/AbuseIPDB 智能缓存**，实现"零误报"。
*   **双报告生成**：同时生成人类可读报告和 AI 优化报告，为 AI 预处理 PCAP 数据而设计。
*   **智能情报缓存**：白名单永久保存，安全 IP/域名 30 天缓存，避免重复 API 查询。

---

## 2. 架构设计

```text
NetflowSight/
├── src/                          # 核心源码
│   ├── core/                     # 核心解析层
│   │   ├── parser.py             # NFStream 封装 (100+ 自动特征)
│   │   ├── models.py             # 数据模型 (ThreatFinding, AnalysisResult)
│   │   └── config.py             # 全局配置管理
│   │
│   ├── engines/                  # 威胁检测引擎 (5 大引擎)
│   │   ├── dns/                  # DNS 威胁检测 (黑名单、隧道、钓鱼、DGA)
│   │   ├── http/                 # HTTP 威胁检测 (异常流量、端口、UA)
│   │   ├── covert/               # 隐蔽通道检测 (ICMP/DNS 隧道、TLS、单向传输)
│   │   ├── behavior/             # 行为异常检测 (大流量、可疑通信、端口扫描)
│   │   ├── smart_threat.py       # 微步在线 ThreatBook 智能检测
│   │   └── abuseipdb_detector.py # AbuseIPDB 智能检测
│   │
│   ├── datasource/               # 威胁情报管理
│   │   ├── manager.py            # 数据源管理器 (ETag、增量更新、版本控制)
│   │   └── strategy.py           # 策略推荐引擎 (自动优化更新策略)
│   │
│   ├── intel/                    # 威胁情报客户端
│   │   ├── client.py             # AbuseIPDB API 集成
│   │   ├── cache.py              # 本地缓存 (减少 API 调用)
│   │   ├── threatbook.py         # 微步在线 ThreatBook API
│   │   └── fusion.py             # 情报融合 (预留)
│   │
│   ├── ml/                       # 机器学习层
│   │   └── classifier.py         # Isolation Forest 异常检测
│   │
│   ├── visualization/            # 可视化引擎
│   │   └── topology.py           # 网络拓扑图生成 (IP-域名混合节点)
│   │
│   ├── report/                   # 报告生成
│   │   ├── generator.py          # 多格式报告 (JSON/Markdown/Text + AI 报告)
│   │   └── ai_report.py          # AI 辅助报告 (预留)
│   │
│   ├── ai/                       # AI 集成
│   │   └── mcp_server.py         # MCP AI 服务器 (预留)
│   │
│   ├── plugins/                  # 插件系统
│   │   ├── interfaces.py         # 插件接口定义
│   │   └── registry.py           # 插件注册表
│   │
│   ├── analyzer.py               # 主协调器 (编排所有组件)
│   └── cli.py                    # CLI 接口 (Click)
│
├── data/                         # 数据存储
│   ├── sources/                  # 威胁情报源
│   │   ├── state.json            # 数据源状态
│   │   ├── abuseipdb_whitelist.json  # AbuseIPDB 白名单
│   │   ├── abuseipdb_safe_cache.json # AbuseIPDB 安全缓存
│   │   └── threatbook_*.json     # 微步在线白名单/缓存
│   └── reports/                  # 分析报告输出
│
├── docs/                         # 工程文档
├── .env                          # 环境变量配置
├── pyproject.toml                # 项目配置
└── README.md                     # 项目说明
```

---

## 3. 核心工程设计细节

### 3.1 DNS 检测引擎 (`engines/dns/dns_detector.py`)

**设计理念**：零误报策略

*   **黑名单匹配**：只检测已知威胁域名（来自本地数据源）
*   **移除未知域名检测**：避免对正常但未收录的域名产生误报
*   **DGA 检测**：基于信息熵识别算法生成域名
*   **DNS 隧道检测**：基于向同一 DNS 服务器发送的包数量

### 3.2 智能威胁检测引擎

#### 微步在线 ThreatBook (`engines/smart_threat.py`)

*   **双名单机制**：
    *   **白名单**：`judgments` 包含 "Whitelist" 的域名，永久保存
    *   **安全缓存**：安全但未标记白名单的域名，30 天过期
*   **API 节省**：缓存命中不消耗 API 额度
*   **智能筛选**：只查询可疑域名到 API，避免滥用额度

#### AbuseIPDB (`engines/abuseipdb_detector.py`)

*   **双名单机制**：
    *   **白名单**：知名云服务 IP（Google/AWS/Cloudflare 等），永久保存
    *   **安全缓存**：abuse_score < 10 的 IP，30 天过期
*   **恶意 IP 检测**：abuse_score >= 10 生成告警
*   **自动分类**：根据 ISP 信息自动识别云服务提供商

### 3.3 数据源管理 (`datasource/manager.py`)

**启动行为**：
1.  **首次运行**：自动更新所有数据源（无需询问）
2.  **后续运行**：交互式询问是否更新（`[Y/n]`）
3.  **非交互模式**：使用缓存数据，不询问

**更新策略**：
*   **ETAG_CHECK**：HTTP 条件请求（零流量）
*   **TIME_WINDOW**：时间窗口增量更新
*   **FULL**：全量更新

**状态文件优化**：
*   不再持久化大型 items 集合
*   只保存元数据，状态文件从 3.5MB 减少到 <10KB

### 3.4 双报告生成 (`report/generator.py`)

**人类可读报告**：
*   Markdown/JSON/Text 格式
*   摘要 + Top 威胁列表 + 统计信息
*   适合安全分析师阅读

**AI 优化报告**：
*   结构化 JSON 格式
*   包含建议分析提示词（根据检测到的威胁类型自动生成）
*   压缩上下文，减少 Token 使用
*   包含 6 步分析任务的中文指令
*   适合发送给 ChatGPT/Claude 等 LLM 进行深度分析

---

## 4. 数据流与处理逻辑

```
初始化 NetflowSightAnalyzer
        ↓
[1] 初始化 DataSourceManager
    ├── 检查 state.json 是否存在
    ├── 首次运行 → 自动更新所有数据源
    └── 后续运行 → 询问用户是否更新
        ↓
[2] 加载本地威胁情报
    ├── PhishTank（钓鱼域名）
    ├── URLhaus（恶意 URL）
    ├── Spamhaus DROP（恶意 IP 段）
    └── 微步/AbuseIPDB 白名单/安全缓存
        ↓
[3] 解析 PCAP 文件
        ↓
[4] ML 异常检测 (Isolation Forest)
        ↓
[5] 🟢 本地威胁检测（先执行）
    ├── DNS 检测（本地威胁域名黑名单）
    ├── HTTP 检测
    ├── 隐蔽通道检测
    └── 行为异常检测
        ↓
[6] 🔵 API 威胁情报（后执行）
    ├── 微步在线域名查询（智能缓存）
    └── AbuseIPDB IP 信誉检查（智能缓存）
        ↓
[7] 生成报告
    ├── 人类可读报告（Markdown/JSON/Text）
    └── AI 优化报告（JSON + 提示词）
```

---

## 5. 部署与运行

### 环境要求
*   Python 3.10+ (推荐 Anaconda)
*   依赖库：`nfstream`, `pandas`, `scikit-learn`, `click`, `rich`

### 快速开始

```bash
# 安装依赖
pip install -e .

# 配置环境变量
cp .env.example .env
# 编辑 .env 添加 API Keys

# 运行分析
python test_pcap.py
```

### 环境变量配置

```ini
# 威胁情报 API
ABUSEIPDB_API_KEY=your_key_here
THREATBOOK_API_KEY=your_key_here

# AI 配置（可选）
OPENAI_API_KEY=your_key_here
```

### 情报源更新

系统默认集成了以下数据源：

| 数据源 | 类型 | 更新频率 | 状态 |
|--------|------|---------|------|
| **PhishTank** | 钓鱼域名 | 24h | ✅ 已启用 |
| **URLhaus** | 恶意 URL | 12h | ✅ 已启用 |
| **Spamhaus DROP** | 恶意 IP 段 | 24h | ✅ 已启用 |
| **微步在线** | 域名威胁 | 按需 | ✅ 已配置 |
| **AbuseIPDB** | IP 信誉 | 按需 | ✅ 已配置 |

---

## 6. 已知问题与待改进

### 已修复
- ✅ Windows 多进程兼容性
- ✅ 路径遍历漏洞
- ✅ 数据源状态文件过大
- ✅ 172.x IP 正则误判
- ✅ 重复 web/app.py 文件
- ✅ CSV 列索引配置失效

### 待改进
- 🔲 添加单元测试覆盖
- 🔲 恢复 Web 模块
- 🔲 Docker 容器化支持
- 🔲 插件系统完善

---

**Made with ❤️ by Prometheus Projects Team**
