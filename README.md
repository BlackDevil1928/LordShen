<p align="center">
<img width="200" height="200" align="center" alt="ChatGPT_Image_Sep_18__2026__11_45_44_AM-removebg-preview" src="https://github.com/user-attachments/assets/8e310615-6e91-44be-9b25-5c3ff88ba297" />
</p>
<h1 align="center">AutoPentest AI</h1>

<p align="center">
  <b>Professional AI-Powered CLI Penetration Testing Framework</b><br>
  <i>Built for Bug Bounty Hunters & Security Researchers</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-557C94?logo=kalilinux&logoColor=white" alt="Kali Linux">
  <img src="https://img.shields.io/badge/AI-Groq%20%2B%20Ollama-orange?logo=openai&logoColor=white" alt="AI">
  <img src="https://img.shields.io/badge/Tools-35+-red" alt="Tools">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/Cost-$0-brightgreen" alt="Zero Cost">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/CLI-Terminal%20Only-black?logo=gnometerminal&logoColor=white" alt="CLI">
  <img src="https://img.shields.io/badge/No%20Docker-Required-lightgrey" alt="No Docker">
  <img src="https://img.shields.io/badge/Reports-PDF%20%7C%20MD%20%7C%20SARIF-blueviolet" alt="Reports">
</p>

---

## 🔥 Overview

**AutoPentest AI** is a professional-grade, zero-cost, AI-powered penetration testing framework designed exclusively for the terminal. It integrates **35+ industry-standard security tools** into a unified CLI pipeline with **Groq AI analysis** and **Ollama local inference** — giving bug bounty hunters the power of automated reconnaissance, vulnerability scanning, and professional report generation in a single command.

> 🎯 **Built by hunters, for hunters.** Designed with HackerOne, Bugcrowd, and Intigriti workflows in mind.

### Key Highlights

- 🤖 **AI-Powered Analysis** — Groq API (free tier) for vuln analysis, report generation, and autonomous agent decisions
- 🔒 **Privacy First** — Sensitive data NEVER leaves your machine (Ollama for local tasks, anonymization for cloud)
- 🎯 **Scope-Aware** — Mandatory scope validation prevents accidental out-of-scope testing
- ⚡ **Parallel Execution** — Async pipeline runs multiple tools simultaneously
- 📊 **Professional Reports** — PDF, Markdown (H1/Bugcrowd ready), SARIF, JSON export
- 🧠 **ML False Positive Detection** — Random Forest classifier + rule engine reduces noise
- 🤖 **Autonomous Agent Mode** — AI decides what tools to run next (ReAct loop)

---

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Commands Reference](#-commands-reference)
- [Scan Profiles](#-scan-profiles)
- [Architecture](#-architecture)
- [Tool Integrations](#-tool-integrations)
- [AI Integration](#-ai-integration)
- [Scope Management](#-scope-management)
- [Report Generation](#-report-generation)
- [Privacy & Safety](#-privacy--safety)
- [Configuration](#%EF%B8%8F-configuration)
- [Examples](#-examples)
- [Requirements](#-requirements)
- [Contributing](#-contributing)
- [Disclaimer](#%EF%B8%8F-disclaimer)

---

## 🚀 Quick Start

```bash
# 1. Clone & Install
git clone https://github.com/yourusername/LordShen.git
cd LordShen
sudo bash install.sh

# 2. Configure AI
autopentest config --groq-key gsk_YOUR_FREE_KEY_HERE

# 3. Define your target scope
autopentest scope create bugcrowd_target \
  -d "*.target.com" \
  -d "api.target.com" \
  --platform bugcrowd

# 4. Launch a scan
autopentest scan target.com --scope bugcrowd_target --profile standard

# 5. Export professional report
autopentest export --scan-id <SCAN_ID> --format pdf -o report.pdf
```

---

## 🛠 Installation

### Prerequisites

| Requirement | Details |
|-------------|---------|
| **OS** | Kali Linux 2023+ (or Debian-based with security tools) |
| **Python** | 3.10 or higher |
| **Disk** | ~5 GB (tools + AI models) |
| **RAM** | 4 GB minimum, 8 GB recommended |
| **API Key** | Groq API (free at [console.groq.com](https://console.groq.com)) |

### Automated Installation

```bash
git clone https://github.com/yourusername/LordShen.git
cd LordShen
sudo bash install.sh
```

The installer automatically:
- ✅ Installs system packages (nmap, masscan, nikto, whatweb, sqlmap, hydra, etc.)
- ✅ Installs Go tools (subfinder, nuclei, httpx, dalfox, ffuf, etc.)
- ✅ Sets up Python dependencies
- ✅ Installs Playwright + Chromium for JS analysis
- ✅ Downloads Nuclei templates
- ✅ Installs Ollama + pulls mistral:7b model
- ✅ Creates `~/.autopentest` config directory

### Manual Installation

```bash
# Install Python package
pip install -e .

# Install specific tools you need
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Check tool status
autopentest tools --check
```

---

## 📖 Commands Reference

### Core Commands

| Command | Description | Example |
|---------|-------------|---------|
| `scan` | Full pipeline scan | `autopentest scan target.com -s scope_name -p deep` |
| `agent` | Autonomous AI agent mode | `autopentest agent target.com -s scope_name -t 30` |
| `recon` | Passive recon only | `autopentest recon target.com -s scope_name` |
| `vuln` | Vulnerability scanning | `autopentest vuln https://target.com -s scope_name` |
| `webapp` | Web app testing | `autopentest webapp https://target.com -s scope_name` |
| `network` | Network/port scanning | `autopentest network 10.0.0.1 -s scope_name` |
| `dorking` | Google dorking | `autopentest dorking target.com -s scope_name -c credentials` |

### Management Commands

| Command | Description | Example |
|---------|-------------|---------|
| `scope create` | Create target scope | `autopentest scope create h1_pgm -d '*.target.com'` |
| `scope list` | List saved scopes | `autopentest scope list` |
| `scope parse` | AI-parse program page | `autopentest scope parse https://hackerone.com/company -n h1` |
| `scope delete` | Remove a scope | `autopentest scope delete old_scope` |
| `config` | Manage settings | `autopentest config --groq-key gsk_xxx` |
| `history` | Browse scan history | `autopentest history --scan-id abc123 --findings` |
| `tools` | Check/install tools | `autopentest tools --check` |
| `status` | System dashboard | `autopentest status` |

### Reporting Commands

| Command | Description | Example |
|---------|-------------|---------|
| `export` | Export full scan report | `autopentest export --scan-id abc123 -f pdf -o report.pdf` |
| `report` | AI-generate single finding report | `autopentest report --scan-id abc123 -i 0 -s scope_name` |

---

## 📊 Scan Profiles

| Profile | Stages | Estimated Time | Use Case |
|---------|--------|---------------|----------|
| **`quick`** | Passive Recon | ~3-5 min | Fast subdomain discovery |
| **`standard`** | Passive → Active → Vuln Scan | ~15-30 min | Standard bug bounty recon |
| **`deep`** | All 6 stages (passive, active, vuln, webapp, network, cloud) | ~1-2 hours | Full assessment |

### Pipeline Stages

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  1. Passive      │────▶│  2. Active       │────▶│  3. Vuln Scan    │
│  Recon           │     │  Recon           │     │                  │
│  subfinder,amass │     │  httpx,nmap      │     │  nuclei,nikto    │
│  crtsh,gau       │     │  masscan,dnsx    │     │  testssl,subjack │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                         │
                  ┌──────────────────────────────────────┘
                  ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  4. Web App      │────▶│  5. Network      │────▶│  6. Cloud        │
│  Testing         │     │  Testing         │     │  Security        │
│  ffuf,dalfox     │     │  netexec,hydra   │     │  s3_check,trivy  │
│  sqlmap,arjun    │     │                  │     │                  │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

---

## 🏗 Architecture

```
LordShen/
├── assets/                  # Project logos and images
│   ├── banner.png           # Banner logo (dark background)
│   └── logo.png             # Transparent logo
├── pyproject.toml            # Package configuration
├── requirements.txt          # Python dependencies
├── install.sh                # Kali Linux auto-installer
├── README.md                 # This file
│
└── autopentest/              # Main package
    │
    ├── cli/                  # 🖥  Click CLI — 14 commands
    │   └── main.py           # Entry point & all command definitions
    │
    ├── core/                 # ⚙️  Core infrastructure
    │   ├── console.py        # Rich terminal UI (banners, tables, colors)
    │   ├── config.py         # Configuration management (~/.autopentest/)
    │   ├── database.py       # SQLAlchemy + SQLite (scans, findings, audit)
    │   └── exceptions.py     # Custom exception hierarchy
    │
    ├── scope/                # 🎯 Scope management
    │   ├── models.py         # Pydantic v2 ProgramScope model
    │   ├── validator.py      # Domain wildcard + CIDR IP matching
    │   ├── guard.py          # @require_scope_check decorator
    │   └── store.py          # Save/load scopes to ~/.autopentest/scopes/
    │
    ├── llm/                  # 🤖 AI integration
    │   ├── groq_client.py    # Groq API (cache, retry, anonymize, track)
    │   ├── ollama_client.py  # Ollama local inference
    │   ├── router.py         # Smart routing: Groq vs Ollama
    │   └── prompts.py        # 12 expert prompt templates
    │
    ├── tools/                # 🔧 35+ tool wrappers
    │   ├── runner.py         # Async subprocess execution engine
    │   ├── installer.py      # Tool registry & install checker
    │   ├── passive/          # 9 passive recon wrappers
    │   ├── active/           # 6 active recon wrappers
    │   ├── vuln/             # 5 vulnerability scanner wrappers
    │   ├── webapp/           # 11 web app testing wrappers
    │   ├── network/          # 3 network testing wrappers
    │   ├── osint/            # 4 OSINT wrappers (dorking, JS intel, etc.)
    │   └── cloud/            # 3 cloud security wrappers
    │
    ├── pipeline/             # 🔄 Scan orchestration
    │   ├── stages.py         # Stage definitions & profiles
    │   ├── orchestrator.py   # Parallel stage execution engine
    │   └── agent_loop.py     # Autonomous ReAct AI agent
    │
    ├── ml/                   # 🧠 Machine learning
    │   ├── fp_classifier.py  # Random Forest false positive classifier
    │   ├── fp_rules.py       # Rule-based FP detection engine
    │   └── seed_data.json    # 30+ training examples
    │
    ├── report/               # 📄 Report generation
    │   ├── groq_writer.py    # AI-powered report section writer
    │   ├── pdf_builder.py    # ReportLab PDF generator
    │   ├── md_builder.py     # Markdown (H1/Bugcrowd format)
    │   └── sarif_builder.py  # SARIF 2.1.0 for GitHub integration
    │
    └── data/                 # 📦 Bundled data files
        ├── ghdb.json         # 70+ Google Hacking Database dorks
        ├── fp_rules.json     # 15 false positive detection rules
        ├── fingerprints.json # Web framework/WAF/DB fingerprints
        └── wordlists/        # Password lists for credential testing
```

---

## 🔧 Tool Integrations

### Passive Recon (9 tools)

| Tool | Purpose | Type |
|------|---------|------|
| **Subfinder** | Fast subdomain discovery | Go binary |
| **Amass** | Deep passive enumeration (60+ sources) | Go binary |
| **crt.sh** | Certificate transparency logs | HTTP API |
| **GAU** | Fetch known URLs from AlienVault/Wayback/Common Crawl | Go binary |
| **Waybackurls** | Wayback Machine URL extraction | Go binary |
| **theHarvester** | Email, subdomain, and host gathering | Python |
| **ParamSpider** | Parameter discovery from web archives | Python |
| **Shodan CLI** | Internet-wide scan data | Python |
| **HIBP** | Breach data lookup | HTTP API |

### Active Recon (6 tools)

| Tool | Purpose | Type |
|------|---------|------|
| **httpx** | HTTP probing & technology detection | Go binary |
| **Nmap** | Port scanning & service fingerprinting | System |
| **Masscan** | Ultra-fast port scanning | System |
| **dnsx** | DNS resolution & brute-force | Go binary |
| **WhatWeb** | Web technology identification | System |
| **wafw00f** | WAF detection & fingerprinting | Python |

### Vulnerability Scanners (5 tools)

| Tool | Purpose | Type |
|------|---------|------|
| **Nuclei** | Template-based vuln scanning (9000+ templates) | Go binary |
| **Nikto** | Web server misconfiguration scanner | System |
| **testssl.sh** | TLS/SSL configuration auditing | Bash |
| **Subjack** | Subdomain takeover detection | Go binary |
| **ssh-audit** | SSH server configuration auditing | Python |

### Web App Testing (11 tools)

| Tool | Purpose | Type |
|------|---------|------|
| **FFuf** | Web fuzzing (dirs, params, vhosts) | Go binary |
| **Feroxbuster** | Recursive content discovery | Rust binary |
| **SQLMap** | Automated SQL injection testing | Python |
| **Dalfox** | XSS vulnerability scanner | Go binary |
| **XSStrike** | Advanced XSS detection | Python |
| **Arjun** | Hidden HTTP parameter discovery | Python |
| **Wapiti** | Black-box web app scanner | Python |
| **jwt_tool** | JWT token analysis & exploitation | Python |
| **GraphQL-Cop** | GraphQL endpoint security testing | Python |
| **SSRFmap** | SSRF exploitation framework | Python |
| **CORScanner** | CORS misconfiguration detection | Python |

### Network & OSINT (7 tools)

| Tool | Purpose | Type |
|------|---------|------|
| **NetExec** | Network service exploitation | Python |
| **Hydra** | Brute-force authentication | System |
| **smtp-user-enum** | SMTP user enumeration | System |
| **Google Dorking** | 70+ dork patterns across 7 categories | Built-in |
| **Trufflehog** | Secret scanning in repos | Go binary |
| **JS Intel** | JavaScript secret/endpoint extraction | Playwright |
| **Interactsh** | Out-of-band interaction detection | Go binary |

### Cloud Security (3 tools)

| Tool | Purpose | Type |
|------|---------|------|
| **S3 Check** | Public S3 bucket enumeration | boto3 |
| **ScoutSuite** | Cloud security posture assessment | Python |
| **Trivy** | Container & IaC vulnerability scanning | Go binary |

---

## 🤖 AI Integration

AutoPentest AI uses a **dual-LLM architecture** for maximum capability with zero data leakage:

| Provider | Use Case | Privacy | Model |
|----------|----------|---------|-------|
| **Groq** (cloud) | Report writing, vuln analysis, agent decisions, scope parsing | Data **anonymized** before sending — IPs/domains replaced | llama-3.1-70b-versatile |
| **Ollama** (local) | Sensitive payloads, WAF bypass generation | Data **never** leaves your machine | mistral:7b / deepseek-coder:6.7b |

### AI Features

- **🔍 Smart Recon Analysis** — AI prioritizes discovered targets by attack surface
- **📝 Report Generation** — 6 AI-written sections: title, description, repro steps, impact, CVSS, remediation
- **🧠 Autonomous Agent** — ReAct loop: Observe findings → Think (Groq) → Act (run tool) → Repeat
- **🎯 Scope Parsing** — Paste a HackerOne/Bugcrowd URL, AI extracts the scope automatically
- **⚔️ Attack Chain Detection** — AI identifies multi-step vulnerability chains
- **🛡 WAF Bypass** — AI generates WAF-specific bypass payloads (locally via Ollama)
- **📊 CVSS Calculation** — AI computes CVSS 3.1 vectors and scores

### Token Management

```bash
# Check daily usage
autopentest status

# Groq free tier: 500,000 tokens/day
# Responses are cached for 24h to minimize usage
```

---

## 🎯 Scope Management

Scope enforcement is **mandatory** — every tool checks scope before execution.

```bash
# Create scope manually
autopentest scope create hackerone_target \
  -d "*.target.com" \
  -d "api.target.com" \
  --oos "admin.target.com" \
  --ips "10.0.0.0/8" \
  --platform hackerone

# AI-parse from program page
autopentest scope parse https://hackerone.com/target -n h1_target

# Import from JSON
autopentest scope create my_scope --from-file scope.json

# List all scopes
autopentest scope list

# View scope details
autopentest scope show hackerone_target
```

### Scope Features

- ✅ **Wildcard domains** — `*.example.com` matches `sub.example.com` and `deep.sub.example.com`
- ✅ **CIDR IP ranges** — `192.168.1.0/24` matches `192.168.1.50`
- ✅ **Deny-list priority** — Out-of-scope rules checked FIRST
- ✅ **Vuln class filtering** — Exclude vuln types (e.g., `self_xss`, `csv_injection`)
- ✅ **Guard decorator** — `@require_scope_check` enforces scope on every tool
- ✅ **Audit logging** — All scope violations logged to SQLite

---

## 📄 Report Generation

### Export Formats

| Format | Use Case | Command |
|--------|----------|---------|
| **PDF** | Professional client reports | `--format pdf` |
| **Markdown** | HackerOne/Bugcrowd submissions | `--format md` |
| **SARIF** | GitHub Advanced Security integration | `--format sarif` |
| **JSON** | Programmatic analysis | `--format json` |

### AI-Powered Reports

```bash
# Generate AI report for a specific finding
autopentest report --scan-id abc123 --finding-index 0 --scope my_scope

# Generates 6 sections:
# 1. Professional title
# 2. Technical description (3 paragraphs)
# 3. Exact reproduction steps
# 4. Business impact statement
# 5. CVSS 3.1 calculation with vector
# 6. Remediation guide with code examples
```

---

## 🔒 Privacy & Safety

| Feature | How It Works |
|---------|-------------|
| **Scope Guard** | Every tool validates targets against scope before execution |
| **Data Anonymization** | IPs & domains replaced with `x.x.x.x` / `target.com` before Groq API calls |
| **Local AI** | Sensitive tasks (payloads, WAF bypass) use Ollama — data stays on your machine |
| **Rate Limiting** | Respects program-defined rate limits |
| **Audit Trail** | All actions logged to SQLite database |
| **No Telemetry** | Zero data collection, no phone-home |

---

## ⚙️ Configuration

```bash
# Set Groq API key (stored in system keyring)
autopentest config --groq-key gsk_YOUR_KEY

# Set Ollama host
autopentest config --set ollama-host http://localhost:11434

# Set default scan profile
autopentest config --set default-profile standard

# Set rate limiting
autopentest config --set rate-limit-rps 10

# View all settings
autopentest config --show
```

### Config Location

All data stored in `~/.autopentest/`:
```
~/.autopentest/
├── config.json          # Settings
├── scopes/              # Saved scope files
├── data/app.db          # SQLite database
├── reports/             # Generated reports
├── cache/groq/          # Response cache (24h TTL)
└── models/              # Trained ML models
```

---

## 💡 Examples

### Full Deep Scan

```bash
autopentest scan example.com --scope my_scope --profile deep
```

### AI Agent Mode (Autonomous)

```bash
autopentest agent example.com --scope my_scope --max-turns 30
```

### Quick Subdomain Recon

```bash
autopentest recon example.com --scope my_scope
```

### Google Dorking for Credentials

```bash
autopentest dorking example.com --scope my_scope --category credentials
```

### Export PDF Report

```bash
autopentest export --scan-id abc123 --format pdf -o ~/Desktop/report.pdf
```

### View Scan History

```bash
# List all scans
autopentest history

# View findings for a scan
autopentest history --scan-id abc123 --findings

# Filter by severity
autopentest history --scan-id abc123 --findings --severity critical
```

---

## 📦 Requirements

### Python Dependencies

```
click>=8.1          # CLI framework
rich>=13.0          # Terminal UI
groq>=0.4           # Groq AI API
httpx[http2]>=0.25  # HTTP client
sqlalchemy>=2.0     # Database ORM
pydantic>=2.0       # Data validation
keyring>=24.0       # Secure key storage
diskcache>=5.6      # Response caching
scikit-learn>=1.3   # ML classifier
reportlab>=4.0      # PDF generation
boto3>=1.28         # AWS S3 scanning
playwright>=1.40    # JS analysis
```

### System Tools

All tools are automatically installed by `install.sh`. Check status:
```bash
autopentest tools --check
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-tool`)
3. Add your tool wrapper in `autopentest/tools/`
4. Register it in `pipeline/orchestrator.py` TOOL_MAP
5. Submit a Pull Request

### Adding a New Tool Wrapper

```python
# autopentest/tools/category/my_tool.py
from autopentest.tools import ToolFinding
from autopentest.tools.runner import run_tool, check_binary

class MyToolWrapper:
    name = "my_tool"
    binary = "mytool"

    async def run(self, target: str, **kwargs) -> list[ToolFinding]:
        result = await run_tool(["mytool", target], timeout=300)
        return self.parse_output(result.stdout)

    def parse_output(self, raw: str, **kwargs) -> list[ToolFinding]:
        # Parse tool output into ToolFinding objects
        return []

    @staticmethod
    def is_installed() -> bool:
        return check_binary("mytool")
```

---

## ⚠️ Disclaimer

> **AutoPentest AI is intended for authorized security testing only.**
>
> - Always obtain **written permission** before testing any target
> - Respect **program scope** and **rules of engagement**
> - The developers are **not responsible** for any misuse of this tool
> - Use responsibly and ethically

---

<p align="center">
  <img width="80" height="80" alt="ChatGPT_Image_Sep_18__2026__11_45_44_AM-removebg-preview" src="https://github.com/user-attachments/assets/331073e4-a113-4c83-a51a-9845df7efe78" />
  <br>
  <b>AutoPentest AI</b> — Hunt smarter, not harder.
  <br>
  <sub>Built with ❤️ for the bug bounty community</sub>
</p>
