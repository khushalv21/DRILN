# Architecture Overview

Driln is designed to be a modular, asynchronous execution engine. Instead of running security tools manually and piecing the data together, Driln automates the entire pipeline.

Here is a simple breakdown of how data flows through the system.

---

## 1. The Core Engine
When a scan is initiated (via CLI or API), the **ScanEngine** takes over. It creates a record in the local SQLite database and resolves which pipeline of tools should be run based on the scan type (e.g., `recon`, `vuln`, `full`).

## 2. The Tool Layer
Driln runs industry-standard tools sequentially. The system is designed to "chain" outputs—meaning the results of one tool feed directly into the next:
1. **Subfinder** finds subdomains.
2. **Httpx** takes those subdomains and probes them to find live web servers.
3. **Nmap** scans those live servers for open ports.
4. **Nuclei** runs vulnerability templates against the live servers.

## 3. The Intelligence Layer
Raw output from tools is messy. Once the tools finish running, Driln passes the data through its Intelligence Layer to clean it up:
- **Deduplication:** If Nmap and Nuclei both report the same open port or vulnerability, Driln merges them into a single finding.
- **Correlation:** It groups related findings together (e.g., matching a vulnerable service version with a known exploit finding).
- **Risk Scoring:** Every finding is assigned a composite risk score from 0 to 100 based on severity, exploitability, and exposure.

## 4. Report Generation & AI
Finally, the processed data is passed to the **Report Generator**.
If an AI provider (like OpenAI) is configured in your `.env` file, Driln sends the cleaned findings to the AI to generate an executive summary, attack paths, and remediation steps. The final output is rendered into an HTML or Markdown file.

---

### Codebase Structure

If you want to explore the code, here is where everything lives:

- `driln/cli.py` - The command-line interface.
- `driln/main.py` - The FastAPI server entry point.
- `driln/engine/` - Contains the logic that runs the scans and chains tools.
- `driln/tools/` - The wrappers for external tools (Nmap, Nuclei, etc.).
- `driln/intelligence/` - The logic for deduplication, risk scoring, and correlation.
- `driln/api/` - The REST API endpoints.
- `driln/db/` - SQLite database models and queries.
