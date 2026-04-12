# NetflowSight 项目工程报告

**版本**: v1.0.0 (Stable)  
**日期**: 2026-04-12  
**维护者**: Prometheus Projects Team

---

## 1. 项目概况

NetflowSight 是一个基于 **NFStream** 高性能解析引擎的智能网络流量分析平台。该项目旨在解决传统抓包工具（如 Wireshark）在大规模数据下分析困难、误报率高、缺乏关联分析的问题。

### 核心特性
*   **高性能解析**：基于 C 语言底层，支持 GB 级 PCAP 秒级处理。
*   **智能降噪**：摒弃传统的“白名单”逻辑，采用**本地黑名单情报库**比对，实现“零误报”。
*   **关联拓扑**：首创“IP-域名”混合节点拓扑图，直观展示恶意域名与主机的通信关系。
*   **Web 集成**：开箱即用的 FastAPI + ECharts 可视化界面。

---

## 2. 架构设计

```text
NetflowSight/
├── src/netflowsight/
│   ├── core/             # 核心解析逻辑 (NFStream Wrapper)
│   ├── engines/          # 检测引擎 (DNS, HTTP, Covert, Behavior)
│   ├── datasource/       # 威胁情报管理 (DataSourceManager)
│   ├── visualization/    # 拓扑图生成逻辑 (Topology Generator)
│   └── web/              # Web 服务 (FastAPI)
├── data/                 # 数据源与报告存储
├── docs/                 # 工程文档
└── web/                  # 前端静态文件 (Index.html)
```

---

## 3. 核心工程设计细节

### 3.1 拓扑图生成引擎 (`visualization/topology.py`)

**挑战**：传统拓扑图仅展示 IP 通信，无法直接关联到 DNS 查询到的恶意域名。

**解决方案**：实现 `get_anomaly_topology` 混合图算法。
1.  **IOCs 提取**：新增 `extract_alert_iocs_from_threats` 函数，使用正则从告警中提取 IP 和 域名。
2.  **动态节点构建**：
    *   **IP 节点**：基于通信流量大小动态调整尺寸。
    *   **Domain 节点**：新增橙色节点类型。当检测到访问恶意域名时，系统会自动在图中创建一个 Domain 节点。
3.  **虚线关联**：使用橙色虚线将 **Source IP** 连接到 **Malicious Domain**，直观展示"谁访问了哪个恶意网站"。

### 3.2 DNS 检测逻辑重构 (`engines/dns/dns_detector.py`)

**挑战**：原有的“未知域名”和“关键词钓鱼”逻辑误报率极高（例如 `login.microsoft.com` 被误报）。

**解决方案**：
*   **移除白名单**：不再依赖有限的白名单列表。
*   **黑名单匹配**：`run()` 方法现在接收 `threat_domains` 集合。
    *   只有当请求的域名存在于本地威胁情报库（如 Spamhaus, PhishTank）时，才触发 `Severity.HIGH` 告警。
    *   对于不在黑名单中的域名，视为正常流量，保持静默。

### 3.3 Web 服务稳定性修复 (`web/app.py`)

**挑战**：Windows 环境下中文注释导致 `UnicodeDecodeError`，且 Python 进程缓存导致模块导入错误 (`ImportError`)。

**解决方案**：
*   **纯 ASCII 编码**：后端代码彻底移除中文注释，强制 UTF-8 兼容。
*   **动态导入修正**：修正了 `run_engines_on_df` 中 DNS 引擎的参数传递，确保 `threat_domains` 被正确注入。
*   **Numpy 序列化**：引入 `NumpyEncoder` 解决 Pandas/Numpy 数据类型无法直接转为 JSON 的问题。

---

## 4. 数据流与处理逻辑

1.  **输入**：用户上传 `.pcap` 文件。
2.  **解析**：NFStream 提取 100+ 特征（流量、SNI、User-Agent 等）。
3.  **情报加载**：`intel_manager` 从 `data/sources` 加载最新的恶意 IP/域名列表。
4.  **引擎并行检测**：
    *   **DNS**：比对 SNI/DNS 响应与黑名单。
    *   **HTTP**：检测异常流量比例 (Response > 10x Request)。
    *   **Covert**：检测 ICMP/DNS 隧道。
    *   **Behavior**：检测端口扫描、大流量传输。
5.  **输出**：
    *   **JSON 报告**：结构化告警数据。
    *   **拓扑图**：节点/边关系数据，供前端 ECharts 渲染。

---

## 5. 部署与运行

### 环境要求
*   Python 3.10+ (推荐 Anaconda)
*   依赖库：`fastapi`, `nfstream`, `pandas`, `uvicorn`

### 启动命令
```bash
# 启动 Web 服务 (端口 8000)
D:\ProgramData\anaconda3\python.exe run_web.py
```
访问地址：`http://127.0.0.1:8000`

### 情报源更新
系统默认集成了 `Spamhaus` (IP) 和 `OpenPhish` (Domains) 的自动更新配置。首次运行会自动拉取数据至 `data/sources/` 目录。
