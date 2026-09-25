```
    ██████╗ ██████╗ ██╗██╗     ███╗   ██╗
    ██╔══██╗██╔══██╗██║██║     ████╗  ██║
    ██║  ██║██████╔╝██║██║     ██╔██╗ ██║
    ██║  ██║██╔══██╗██║██║     ██║╚██╗██║
    ██████╔╝██║  ██║██║███████╗██║ ╚████║
    ╚═════╝ ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═══╝
```
> **Find it before they do.**

[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-GPL--3.0-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-orange.svg)](driln/__init__.py)

**Driln** is a lightweight, automated penetration testing engine. It orchestrates industry-standard offensive security tools, deduplicates findings, scores risks, correlates results via scan intelligence, and generates clean markdown reports.

---

## Features

- **Automated Tool Chaining**: Seamlessly pipes outputs from `subfinder` to `httpx` to `nmap` and `nuclei`.
- **Intelligence Layer**: Merges duplicate findings across different tools, correlates related issues, and assigns a 0-100 risk score.
- **AI-Powered Summaries (BYOK)**: Bring your own API key — generates executive summaries and remediation steps using LLMs. Works without a key too.
- **CLI & REST API**: Run scans, view status, list tools, and generate reports from the terminal or via the built-in API server.

---

## Getting Started

### 1. Install Prerequisites

Driln orchestrates external security tools. Ensure they are installed and available in your `PATH`:

```bash
# macOS (using Homebrew and Go)
brew install nmap
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### 2. Install Driln

Clone the repository and install the package:

```bash
pip install -e ".[dev]"
cp .env.example .env
```

### 3. Bring Your Own API Key (Optional)

Driln does **not** ship with an API key. AI features (executive summaries, remediation advice) are optional and require you to provide your own key:

```bash
# In your .env file:
DRILN_AI_API_KEY=sk-your-openai-key-here
```

Supports any OpenAI-compatible endpoint (OpenAI, Ollama, vLLM, LM Studio). Scans work perfectly fine without a key — you just won't get AI-generated summaries.

### 4. Usage Examples

#### Run a full scan against a target:
```bash
driln scan example.com --type full
```
*Expected Output:*
```
✓ Scan complete · 4 findings · 1 critical · 1 medium · 2 low
Report: ./output/example.com_2026-07-07_18-30/example.com_report.md
Scan ID: 550e8400-e29b-41d4-a716-446655440000
```

#### List supported security tools and their status:
```bash
driln tools list
```

#### Regenerate a markdown report:
```bash
driln report 550e8400-e29b-41d4-a716-446655440000
```

#### Start the local API server:
```bash
driln serve --host 127.0.0.1 --port 8000
```

---

## License

This project is licensed under the **GNU General Public License v3** - see the [LICENSE](LICENSE) file for details.
