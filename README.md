# Driln

Automated penetration testing engine. Chains offensive security tools, deduplicates findings, scores risk, and generates reports — with optional AI summaries.

> *Find it before they do.*

---

## Install

```bash
# Tools
brew install nmap
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Driln
git clone https://github.com/khushalv21/DRILN.git && cd DRILN
pip install -e ".[dev]"
cp .env.example .env
```

## Usage

```bash
driln scan example.com --type full        # recon + vuln scan
driln report <scan-id> --format html      # generate report
driln intel summary <scan-id>             # intelligence breakdown
driln tools list                          # check tool status
driln serve                               # start API server
```

## What it does

- Chains `subfinder` → `httpx` → `nuclei` → `nmap` automatically
- Deduplicates findings across tools and assigns 0–100 risk scores
- Correlates related vulnerabilities into attack paths
- Detects technology stacks from scan data
- Generates prioritized remediation recommendations
- AI-powered executive summaries (OpenAI, pluggable to any provider)
- REST API via FastAPI with full Swagger docs
- Async-native — handles 500 concurrent scans with zero DB locks

## Upcoming

- Terminal UI (TUI) with interactive dashboard
- Docker images and PyPI publication
- AI containment layer for hallucination-free exploitation paths

## ⚠️ Disclaimer

For **authorized security testing only**. Always obtain written permission before scanning any target.

## License

[GNU General Public License v3.0](LICENSE)
