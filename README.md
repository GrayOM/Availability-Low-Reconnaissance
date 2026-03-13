# ALR — Availability Low Reconnaissance

> **Passive-first, low-noise OSINT reconnaissance framework.**
> Collects publicly available intelligence, analyzes the external attack surface,
> and generates a professional PDF report — no AI API required.

---

## Overview

ALR performs passive-first reconnaissance against a target domain or IP address using only public data sources. It produces a structured **PDF report** as its primary deliverable — suitable for direct review or optional upload to ChatGPT for further manual interpretation.

**No external AI API key is required.** The report is generated entirely from collected data.

---

## ⚠️ Legal Notice

- **Only run against targets you have explicit written authorization to assess.**
- This tool is NOT an exploit framework or vulnerability scanner.
- All findings are heuristic pattern indicators — no confirmed vulnerabilities are asserted.

---

## Quick Start

```bash
git clone https://github.com/GrayOM/Availability-Low-Reconnaissance.git
cd Availability-Low-Reconnaissance/alr_project/alr

# 1. Install Python dependencies
pip install python-dotenv reportlab

# 2. Install reconnaissance tools (requires Go 1.19+)
bash ./scripts/bootstrap_tools.sh

# 3. Verify tools are found
python3 -m cli.main --doctor

# 4. Run reconnaissance
python3 -m cli.main --domain example.com
```

**Output:** JSON + Markdown + PDF in `data/outputs/<run_id>/`

---

## How It Works

```
Target Input
    │
    ▼
passive subdomain discovery (subfinder)
    │
    ▼
Certificate Transparency enrichment (crt.sh — passive)
    │
    ▼
RDAP / WHOIS / ASN enrichment (passive)
    │
    ▼
HTTP asset verification (httpx — lightweight)
    │
    ▼
Heuristic tech detection (from HTTP metadata)
    │
    ▼
Surface Analysis (pattern-based, conservative)
    │
    ▼
┌──────────────────────────────────┐
│  JSON  │  Markdown  │  PDF       │ ← primary deliverable
└──────────────────────────────────┘
```

---

## Requirements

### Python
- Python 3.10+
- `python-dotenv` — for `.env` loading
- `reportlab` — for PDF generation (primary artifact)
- `PyGithub` — optional, for live `--enable-github-check`

### Go (required for external tool installation)
- Go 1.19+ → https://go.dev/dl/

### External CLI Tools

| Tool | Purpose | Default Path |
|------|---------|-------------|
| subfinder | Passive subdomain discovery | ✅ Required |
| httpx | Lightweight HTTP verification | ✅ Required |

> **Not part of the default path:** dnsx, naabu, wappalyzer
> These may be present in code as disabled future modules.

---

## Installation

### Python packages

```bash
pip install python-dotenv reportlab
```

### Reconnaissance tools (bootstrap script)

```bash
# Linux / macOS / WSL
bash ./scripts/bootstrap_tools.sh

# Windows (PowerShell)
.\scripts\bootstrap_tools.ps1
```

Tools are installed into `.tools/bin/` inside the project directory.
Your shell profile is **never modified**.

### Manual tool installation

```bash
export GOBIN=$(pwd)/.tools/bin
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

---

## Usage

```bash
# Tool diagnostics
python3 -m cli.main --doctor

# Basic passive + light-active run (recommended)
python3 -m cli.main --domain example.com

# Include optional GitHub public exposure hints
python3 -m cli.main --domain example.com --enable-github-check

# IP target
python3 -m cli.main --ip 203.0.113.10

# Skip PDF export
python3 -m cli.main --domain example.com --no-pdf

# Demo/dev with mock data (no tools required)
python3 -m cli.main --domain example.com --allow-mock

# Verbose output
python3 -m cli.main --domain example.com --verbose
```

### All CLI flags

| Flag | Description |
|------|-------------|
| `--domain` / `--ip` | Target (required) |
| `--output-dir` | Output directory (default: `data/outputs`) |
| `--timeout` | Timeout in seconds (default: 60) |
| `--enable-github-check` | Enable GitHub public exposure hints |
| `--no-pdf` | Skip PDF export |
| `--allow-mock` | Allow mock/fallback data (demo/dev only) |
| `--strict-tools` | Hard fail if required tools are missing |
| `--doctor` | Run tool diagnostics and exit |
| `--verbose` | Verbose logging |

---

## Output Files

Each run produces a timestamped output directory:

```
data/outputs/<run_id>/
├── output.json     ← structured data: all collected fields + surface findings
├── report.md       ← Markdown summary
└── report.pdf      ← PRIMARY DELIVERABLE — professional structured report
```

### Using the PDF with ChatGPT

The PDF is designed to be uploaded directly to ChatGPT or another AI assistant
for manual interpretation. The PDF contains:

- Executive summary
- Data collection scope and reliability
- Reconnaissance summary (counts, sources)
- Surface analysis findings table
- Priority review targets
- Infrastructure / ownership context (RDAP/ASN)
- HTTP exposure summary
- Public exposure hints (if enabled)
- Limitations and notes
- Output references

**No AI API calls are made by ALR itself.**

---

## Configuration (`.env`)

Copy `.env.example` to `.env` to customize:

```bash
cp .env.example .env
```

Available settings:

```env
# Tool binary paths (override if not on PATH / .tools/bin)
SUBFINDER_BIN=subfinder
HTTPX_BIN=httpx

# Output directory
ALR_OUTPUT_DIR=data/outputs

# Timeout in seconds
ALR_TIMEOUT=60

# GitHub token (optional — for --enable-github-check live search)
# GITHUB_TOKEN=ghp_xxx

# OpenAI settings (NOT required — reserved for future optional integration)
# OPENAI_API_KEY=sk-...
# OPENAI_MODEL=gpt-4o-mini
```

---

## Report Philosophy

ALR enforces conservative language throughout:

| Use | Avoid |
|-----|-------|
| "possible", "review recommended" | "confirmed vulnerability" |
| "exposure candidate" | "definitely exploitable" |
| "pattern suggests" | "breach", "compromised" |
| "manual validation required" | "proven to be vulnerable" |

**Findings are clue-based patterns, not proof of vulnerability.**

---

## Architecture

```
alr/
├── cli/main.py                      # Entry point
├── config/settings.py               # Environment-based config
├── core/
│   ├── target_manager.py            # Target validation + context
│   └── orchestrator.py              # Pipeline coordinator
├── collectors/
│   ├── subdomain_collector.py       # subfinder (passive)
│   ├── ct_collector.py              # crt.sh CT (passive)
│   ├── rdap_collector.py            # RDAP/WHOIS/ASN (passive)
│   ├── http_collector.py            # httpx (light_active)
│   ├── tech_collector.py            # heuristic tech detection
│   └── github_collector.py          # optional GitHub hints
├── analyzers/
│   └── surface_analyzer.py          # Heuristic surface analysis
├── ai/
│   └── report_generator.py          # Structured report (no AI API)
├── reports/
│   ├── pdf_writer.py                # PDF report (primary artifact)
│   ├── markdown_writer.py           # Markdown report
│   └── json_writer.py               # JSON output
├── models/schema.py                 # Data models (stdlib only)
└── tests/                           # Test suite
```

---

## Tests

```bash
# Run all tests
python3 -m pytest tests/ -v

# Individual test modules
python3 -m tests.test_target_manager -v
python3 -m tests.test_surface_analyzer -v
python3 -m tests.test_runtime_and_modes -v
python3 -m tests.test_ai_layer -v
python3 -m tests.test_pdf_report -v
```

---

## Notes

- ALR does **not** require any external AI API
- The PDF report is the primary deliverable
- Users may optionally upload the PDF to ChatGPT for interpretation
- dnsx, naabu, and wappalyzer are NOT part of the default recommended workflow
- GitHub public hints are optional (`--enable-github-check`)
- All runs are low-impact by default; no aggressive scanning is performed
