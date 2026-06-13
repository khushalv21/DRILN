<h1 align="center">
<pre>
██████╗ ██████╗ ██╗██╗     ███╗   ██╗
██╔══██╗██╔══██╗██║██║     ████╗  ██║
██║  ██║██████╔╝██║██║     ██╔██╗ ██║
██║  ██║██╔══██╗██║██║     ██║╚██╗██║
██████╔╝██║  ██║██║███████╗██║ ╚████║
╚═════╝ ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═══╝
</pre>
</h1>

<p align="center">
  <b>Find it before they do.</b>
</p>

<p align="center">
  <em>Automated penetration testing engine with AI-powered intelligence.</em>
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#%EF%B8%8F-how-it-works">How It Works</a> •
  <a href="#-features">Features</a> •
  <a href="#-performance">Performance</a> •
  <a href="#-upcoming-features">Roadmap</a>
</p>

---

## What is Driln?

Driln is an **automated penetration testing engine** that chains together industry-standard offensive security tools (`nmap`, `subfinder`, `httpx`, `nuclei`) and runs them against a target in a single command. An intelligence layer deduplicates findings across tools, scores risk on a 0–100 scale, correlates attack paths, and generates clean reports — optionally enriched with AI summaries.

```
Target → Subdomain Discovery → Live Host Probing → Vulnerability Scanning → Intelligence Analysis → Report
            (subfinder)            (httpx)              (nuclei/nmap)         (dedup + risk + AI)
```

---

## ⚡ Quick Start

### Prerequisites

```bash
# macOS
brew install nmap
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### Install

```bash
git clone https://github.com/khushalv21/DRILN.git
cd DRILN
pip install -e ".[dev]"
cp .env.example .env
```

> Add your OpenAI API key to `.env` if you want AI-powered report summaries.

### Run

```bash
# Full scan (recon + vuln)
driln scan example.com --type full

# Recon only
driln scan example.com --type recon

# Generate report
driln report <scan-id> --format html
```

---

## ⚙️ How It Works

```
                          ┌──────────────┐
                          │   CLI / API  │
                          └──────┬───────┘
                                 │
                          ┌──────▼───────┐
                          │  Scan Engine │
                          │  (Pipeline)  │
                          └──────┬───────┘
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
       ┌──────▼──────┐   ┌──────▼──────┐   ┌──────▼──────┐
       │  subfinder   │   │    httpx    │   │   nuclei    │
       │  (subdomains)│   │ (live hosts)│   │   (vulns)   │
       └──────┬──────┘   └──────┬──────┘   └──────┬──────┘
              │                  │                  │
              └──────────────────┼──────────────────┘
                                 │
                          ┌──────▼───────┐
                          │ Intelligence │
                          │   Pipeline   │
                          ├──────────────┤
                          │ • Dedup      │
                          │ • Correlate  │
                          │ • Risk Score │
                          │ • AI Summary │
                          └──────┬───────┘
                                 │
                          ┌──────▼───────┐
                          │    Report    │
                          │  (MD / HTML) │
                          └──────────────┘
```

1. **Tool Chaining** — Subfinder discovers subdomains → httpx probes for live hosts → nuclei scans for vulnerabilities. Each tool's output automatically feeds into the next.
2. **Intelligence Layer** — Deduplicates findings across tools, detects technology stacks, correlates related vulnerabilities into attack paths, and assigns a composite risk score (0–100).
3. **AI Analysis** — Optionally sends findings to an LLM for executive summaries, remediation steps, and false-positive flagging.
4. **Report Generation** — Renders everything into clean Markdown or HTML reports via Jinja2 templates.

---

## 🔥 Features

| Feature | Description |
|---------|-------------|
| **Automated Tool Chaining** | Pipes `subfinder` → `httpx` → `nuclei` → `nmap` with zero manual wiring |
| **Intelligence Engine** | Deduplication, correlation groups, technology profiling, and 0–100 risk scoring |
| **AI-Powered Summaries** | Executive summaries and remediation advice via OpenAI (pluggable provider architecture) |
| **REST API + CLI** | Full FastAPI server with Swagger docs, or use the terminal — your choice |
| **Actionable Recommendations** | Rule engine generates prioritized next steps, not just a list of CVEs |
| **Workflow Engine** | Automatic scan expansion based on discovered technologies |
| **Input Validation** | SSRF protection, shell injection prevention, private IP blocking by default |
| **Async Architecture** | Fully `asyncio`-native with `aiosqlite` connection pooling |

---

## 🚀 Performance

Driln is built for speed. The async engine and SQLite connection pooling handle extreme concurrency without locking.

| Metric | Result |
|--------|--------|
| Concurrent scans | **500** |
| Tool executions | **1,000** |
| Findings processed | **5,000** |
| Success rate | **100%** (zero DB locks) |
| Total time | **3.78 seconds** |

---

## 🗺️ Upcoming Features

- **Terminal UI (TUI) & Dockerization:** Moving from a CLI to an interactive TUI, with official Docker images and PyPI publication.
- **AI Containment & Adversarial Testing:** Proving efficacy against hardened targets using strict LLM governance to ensure hallucination-free exploitation paths and aggressive false-positive filtering.

---

## 🧰 CLI Reference

```
driln scan <target> --type <recon|vuln|full>     Run a scan
driln report <scan-id> --format <markdown|html>  Generate report
driln tools list                                  Show tool status
driln tools check                                 Verify installations
driln intel summary <scan-id>                     Full intelligence report
driln intel recommendations <scan-id>             View recommendations
driln intel tech <scan-id>                        Technology profile
driln serve --host 0.0.0.0 --port 8000           Start API server
driln setup                                       Auto-install tools
```

---

## 📁 Project Structure

```
driln/
├── ai/              # Pluggable AI provider abstraction (OpenAI, custom)
├── api/             # FastAPI REST endpoints + validators
├── core/            # Config, logging, exceptions, path utilities
├── db/              # SQLAlchemy models, repos, migrations
├── engine/          # Scan lifecycle manager + tool pipeline
├── intelligence/    # Dedup, correlation, risk scoring, tech profiling
├── reports/         # Jinja2 report generator (MD + HTML templates)
├── schemas/         # Pydantic request/response models
├── tools/           # Tool wrappers (nmap, subfinder, httpx, nuclei)
└── workflow/        # Rule-based scan expansion engine
```

---

## ⚠️ Disclaimer

Driln is intended for **authorized security testing only**. Always obtain explicit written permission before scanning any target. Unauthorized scanning is illegal and unethical. The developers assume no liability for misuse.

---

## 📄 License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
