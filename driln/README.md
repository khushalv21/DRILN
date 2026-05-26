# Driln

> Intelligent automated pentesting engine — modular, async, AI-powered.

## Features

- **Modular tool abstraction** — nmap, subfinder, httpx, nuclei (add your own in one file)
- **AI-assisted analysis** — OpenAI-compatible provider (works with GPT-4, Ollama, vLLM)
- **Async execution** — concurrent tool runs with configurable limits
- **Structured persistence** — SQLite-backed scan history, findings, reports
- **REST API + CLI** — FastAPI server and Typer CLI
- **Report generation** — Markdown and HTML reports with AI summaries

## Quick Start

### Prerequisites

Install the pentesting tools you want to use:

```bash
# macOS (Homebrew)
brew install nmap
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### Installation

```bash
pip install -e ".[dev]"
cp .env.example .env
# Edit .env with your AI API key
```

### Usage

**CLI:**

```bash
# Check available tools
driln tools list
driln tools check

# Run a scan
driln scan example.com --type full

# Generate a report
driln report <scan-id> --format markdown

# Start the API server
driln serve
```

**API:**

```bash
# Health check
curl http://localhost:8000/health

# Start a scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "scan_type": "recon"}'

# Get scan results
curl http://localhost:8000/api/v1/scans/<scan-id>
```

## Architecture

```
driln/
├── core/        # Config, logging, exceptions
├── db/          # SQLAlchemy models, repos, engine
├── schemas/     # Pydantic request/response models
├── tools/       # Tool abstraction + implementations
├── ai/          # AI provider abstraction
├── engine/      # Scan orchestration + pipelines
├── reports/     # Report generation + templates
├── api/         # FastAPI routes
├── cli.py       # Typer CLI
└── main.py      # App factory
```

## Adding a New Tool

Create `driln/tools/my_tool.py`:

```python
from driln.tools.base import BaseTool, ToolResult

class MyTool(BaseTool):
    name = "mytool"
    description = "Description of what it does"
    binary = "mytool"

    def build_command(self, target: str, options: dict) -> list[str]:
        return [self.binary, "-target", target]

    def parse_output(self, raw_output: str, exit_code: int) -> ToolResult:
        # Parse raw_output into structured data
        ...
```

Add `"mytool"` to `DRILN_TOOLS_ENABLED` in your `.env`.

## License

MIT
