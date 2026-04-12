# 🔍 NetflowSight

> **AI-Powered Network Traffic Analysis Platform**
> 
> A fusion of high-performance PCAP parsing, multi-engine threat detection, and intelligent reporting.

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/status-beta-orange)]()

---

## ✨ Features

### 🚀 High-Performance Parsing
- **C-based NFStream engine**: 10x faster than pure Python parsers
- **100+ automatic flow features**: Statistical metrics, DPI recognition, TCP flags
- **Stream-based processing**: Memory efficient, handles GB-sized files
- **Multi-core parallel**: Auto-scales to available CPU cores

### 🛡️ Multi-Engine Threat Detection
- **DNS Threat Detection**: Unknown domains, tunneling, phishing indicators
- **HTTP/HTTPS Detection**: POST anomalies, unusual ports, suspicious User-Agents
- **Covert Channel Detection**: ICMP/DNS tunnels, unknown TLS, one-way exfiltration
- **Behavioral Anomaly Detection**: Large transfers, suspicious comms, port scanning

### 🌐 Threat Intelligence
- **AbuseIPDB Integration**: Real-time IP reputation checking
- **Local Caching**: Reduces API calls, improves performance
- **Configurable TTL**: Automatic cache expiration

### 🤖 ML Anomaly Detection
- **Isolation Forest**: Unsupervised learning, no labeled data required
- **Automatic Feature Selection**: 11 optimized features
- **Anomaly Scoring**: Ranked by suspiciousness

### 💬 AI-Powered Reporting (Optional)
- **MCP Integration**: Natural language query support
- **Smart Context Compression**: ~99% token reduction vs raw data
- **Cost-Effective**: 10GB PCAP analysis costs ~$0.02

### 📊 Rich Reporting
- **Multiple Formats**: JSON, Markdown, Text
- **CLI Output**: Beautiful terminal output with Rich
- **Web API**: RESTful API for integration

---

## 🚀 Quick Start

### Installation

#### Option 1: Using pip

```bash
pip install netflowsight
```

#### Option 2: Using Conda (Recommended)

```bash
# Clone repository
git clone https://github.com/prometheus-projects/NetflowSight.git
cd NetflowSight

# Create conda environment
conda env create -f environment.yml
conda activate netflowsight
```

### Configuration

```bash
# Copy example environment file
cp .env.example .env

# Edit .env and add your API keys (optional)
ABUSEIPDB_API_KEY=your_key_here
OPENAI_API_KEY=your_key_here
```

### Usage

#### CLI: Analyze PCAP File

```bash
# Basic analysis with text output
netflowsight analyze capture.pcap

# Save as Markdown report
netflowsight analyze capture.pcap -o report.md -f markdown

# Save as JSON
netflowsight analyze capture.pcap -o report.json -f json

# Disable ML or threat intel
netflowsight analyze capture.pcap --no-ml
netflowsight analyze capture.pcap --no-threat-intel

# Verbose output
netflowsight analyze capture.pcap -v
```

#### CLI: Explore PCAP

```bash
# Show top flows
netflowsight explore capture.pcap

# Filter by port
netflowsight explore capture.pcap --port 443

# Filter by IP
netflowsight explore capture.pcap --ip 192.168.1.100

# Filter by protocol
netflowsight explore capture.pcap --protocol DNS
```

#### CLI: Check IP Reputation

```bash
netflowsight check-ip 8.8.8.8
```

#### Python API

```python
from netflowsight.analyzer import NetflowSightAnalyzer

# Initialize analyzer
analyzer = NetflowSightAnalyzer(
    pcap_file="capture.pcap",
    enable_ml=True,
    enable_threat_intel=True,
)

# Run analysis
result = analyzer.analyze()

# Print summary
print(f"Total flows: {result.total_flows}")
print(f"Threats found: {len(result.threats)}")
print(f"ML anomalies: {result.anomaly_count}")

# Generate report
report = analyzer.generate_report(format="markdown", output_path="report.md")
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│  User Interface (CLI / Web API / Python API)    │
└───────────────────┬─────────────────────────────┘
                    │
┌───────────────────▼─────────────────────────────┐
│  NetflowSightAnalyzer (Orchestrator)            │
│  ┌───────────────────────────────────────────┐  │
│  │ 1. FlowStreamAnalyzer (NFStream Engine)   │  │
│  │ 2. Threat Detection Engines               │  │
│  │    - DNS, HTTP, Covert, Behavioral        │  │
│  │ 3. ML Anomaly Classifier                  │  │
│  │ 4. Threat Intelligence Client             │  │
│  │ 5. Report Generator                       │  │
│  └───────────────────────────────────────────┘  │
└───────────────────┬─────────────────────────────┘
                    │
┌───────────────────▼─────────────────────────────┐
│  Output: JSON / Markdown / Text Reports         │
└─────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
NetflowSight/
├── src/
│   └── netflowsight/
│       ├── __init__.py
│       ├── analyzer.py              # Main orchestrator
│       ├── cli.py                   # CLI interface
│       ├── core/
│       │   ├── parser.py            # NFStream wrapper
│       │   ├── models.py            # Data models
│       │   └── config.py            # Configuration
│       ├── engines/
│       │   ├── dns/                 # DNS threat detection
│       │   ├── http/                # HTTP threat detection
│       │   ├── covert/              # Covert channel detection
│       │   └── behavior/            # Behavioral anomaly detection
│       ├── intel/
│       │   ├── client.py            # Threat intelligence API
│       │   └── cache.py             # Local cache
│       ├── ml/
│       │   └── classifier.py        # ML anomaly detection
│       ├── ai/
│       │   └── mcp_server.py        # MCP AI server
│       └── report/
│           └── generator.py         # Report generation
├── tests/
├── examples/
├── docs/
├── pyproject.toml
├── environment.yml
└── README.md
```

---

## 🎯 Detection Engines

### DNS Threat Detection
| Detection | Description |
|-----------|-------------|
| Unknown Domains | Queries to domains not in safe list |
| DNS Tunneling | Excessive queries to same domain |
| Phishing Domains | Domains with suspicious TLDs or keywords |

### HTTP Threat Detection
| Detection | Description |
|-----------|-------------|
| POST Anomalies | Unusual response-to-request ratios |
| Unusual Ports | Traffic on non-standard ports |
| Suspicious UA | Automated tooling User-Agents |

### Covert Channel Detection
| Detection | Description |
|-----------|-------------|
| ICMP Tunnel | Large ICMP payloads |
| DNS Exfiltration | Large DNS flows |
| Unknown TLS | Unidentified encrypted traffic |
| One-Way Transfer | Asymmetric data flows |

### Behavioral Anomaly Detection
| Detection | Description |
|-----------|-------------|
| Large Transfers | Flows exceeding threshold |
| Suspicious Comms | Internal → unknown external |
| Port Scanning | Many ports, few destinations |

---

## 💰 Cost Analysis

| PCAP Size | Local Processing | AI Tokens | AI Cost (GPT-4o-mini) |
|-----------|-----------------|-----------|----------------------|
| 1 GB | $0 | ~3,000 | $0.003 |
| 10 GB | $0 | ~5,000 | $0.005 |
| 100 GB | $0 | ~10,000 | $0.01 |

**Key Optimization**: AI only receives compressed context (summary + top threats), not raw packet data.

---

## 🔧 Configuration

See `.env.example` for all available options:

```bash
# Threat Intelligence
ABUSEIPDB_API_KEY=your_key_here

# AI Configuration
OPENAI_API_KEY=your_key_here
AI_MODEL=gpt-4o-mini

# Analysis Settings
STATISTICAL_ANALYSIS=true
N_DISSECTIONS=20
DECODE_TUNNELS=true

# Performance
NFSTREAM_N_METERS=0  # 0 = auto-detect

# Caching
THREAT_CACHE_ENABLED=true
THREAT_CACHE_TTL_HOURS=24
```

---

## 🧪 Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Run with coverage
pytest --cov=netflowsight tests/

# Format code
black src/
ruff check src/
```

---

## 📚 References

This project draws inspiration and design patterns from:

- **NFStream**: High-performance flow parsing
- **PCAP-Investigator**: Threat detection engines
- **AdvancePcapXray**: Threat intelligence integration
- **PCAP-Analyzer**: MCP AI integration
- **Network-Anomaly-Detection**: ML classification

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 🙏 Acknowledgments

- NFStream team for the excellent parsing engine
- AbuseIPDB for threat intelligence API
- Open source PCAP analysis community

---

**Made with ❤️ by Prometheus Projects Team**
