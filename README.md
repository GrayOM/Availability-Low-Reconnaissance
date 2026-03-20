# ALR — Availability Low Reconnaissance

---

## 한국어

> **패시브 우선, 저소음 OSINT 정찰 프레임워크**
> 공개 정보만을 수집하여 외부 공격 표면을 분석하고, 전문적인 PDF 리포트를 생성합니다.
> **외부 AI API 불필요.**

---

### 개요

ALR은 도메인 또는 IP 주소를 대상으로 **공개 데이터 소스만** 활용하는 패시브 우선 정찰 도구입니다.
수집된 데이터로부터 구조화된 **PDF 리포트**를 생성하며, 이를 직접 검토하거나
ChatGPT 등의 AI 도구에 업로드해 별도로 해석할 수 있습니다.

- 외부 AI API 키 불필요
- OpenAI / Anthropic 등 외부 API 비용 없음
- 리포트는 수집된 데이터만으로 완전히 생성됨

---

### ⚠️ 법적 고지

- **반드시 명시적인 서면 승인을 받은 대상에 대해서만 실행하십시오.**
- 이 도구는 취약점 익스플로잇 도구가 아닙니다.
- 모든 분석 결과는 휴리스틱 패턴 기반 지표이며, 확정된 취약점을 의미하지 않습니다.

---

### 동작 방식

```
타겟 입력
    │
    ▼
패시브 서브도메인 수집 (subfinder)
    │
    ▼
Certificate Transparency 보강 (crt.sh — 패시브)
    │
    ▼
RDAP / WHOIS / ASN 정보 수집 (패시브)
    │
    ▼
HTTP 자산 확인 (httpx — 경량 액티브)
    │
    ▼
휴리스틱 기술 스택 감지 (HTTP 메타데이터 기반)
    │
    ▼
공격 표면 분석 (패턴 기반, 보수적)
    │
    ▼
┌──────────────────────────────────┐
│  JSON  │  Markdown  │  PDF       │ ← 주요 최종 산출물
└──────────────────────────────────┘
```

---

### 출력 파일

```
output/
└── nafal.store.pdf          ← 사용자 전달용 PDF (타겟명 기반, 주요 산출물)

data/outputs/<run_id>/
├── output.json              ← 정규화된 전체 데이터 (디버그/추적용)
├── report.md                ← Markdown 요약
└── report.pdf               ← 내부 사본
```

---

### PDF 리포트 구성

| # | 섹션 |
|---|------|
| 1 | 표지 / 메타 정보 (타겟, Run ID, 모드, 시각) |
| 2 | 요약 (Executive Summary) |
| 3 | 데이터 수집 범위 및 신뢰도 |
| 4 | 정찰 요약 (수집 수치) |
| 5 | 공격 표면 분석 결과 |
| 6 | 우선 검토 자산 |
| 7 | 인프라 / 소유권 정보 (RDAP/ASN) |
| 8 | HTTP 노출 요약 |
| 9 | 공개 노출 힌트 (GitHub, 선택 사항) |
| 10 | 한계 및 주의 사항 |
| 11 | 부록 (출력 파일 참조) |

> PDF는 ChatGPT 또는 다른 AI 도구에 직접 업로드하여 추가 해석을 받을 수 있습니다.
> ALR 자체는 AI API를 호출하지 않습니다.

---

### 요구 사항

**Python**
- Python 3.10+
- `python-dotenv` — .env 로딩
- `reportlab` — PDF 생성
- `PyGithub` — 선택 사항 (`--enable-github-check` 사용 시)

**외부 CLI 도구 (Go 1.19+ 필요)**

| 도구 | 용도 | 구분 |
|------|------|------|
| subfinder | 패시브 서브도메인 수집 | ✅ 필수 |
| httpx | 경량 HTTP 확인 | ✅ 필수 |

> **기본 경로에 포함되지 않는 도구:** dnsx, naabu, wappalyzer
> 코드 내 비활성 모듈로 존재할 수 있으나 기본 실행 경로에서 사용되지 않습니다.

**지원 환경**
- Linux / WSL (권장 및 검증 완료)
- macOS (미검증)
- Windows 네이티브: 미지원

---

### 설치

```bash
# 저장소 클론
git clone https://github.com/GrayOM/Availability-Low-Reconnaissance.git
cd Availability-Low-Reconnaissance/alr_project/alr

# Python 패키지 설치
pip install python-dotenv reportlab

# 정찰 도구 설치 (Go 필요)
bash ./scripts/bootstrap_tools.sh

# 도구 확인
python3 -m cli.main --doctor
```

---

### 사용법

```bash
# 기본 실행 (권장)
python3 -m cli.main --domain example.com

# IP 대상
python3 -m cli.main --ip 203.0.113.10

# GitHub 공개 노출 힌트 포함
python3 -m cli.main --domain example.com --enable-github-check

# PDF 생성 생략
python3 -m cli.main --domain example.com --no-pdf

# 목 데이터로 데모 실행 (도구 없이)
python3 -m cli.main --domain example.com --allow-mock

# 진단
python3 -m cli.main --doctor
```

**CLI 플래그 전체 목록**

| 플래그 | 설명 |
|--------|------|
| `--domain` / `--ip` | 대상 (필수) |
| `--output-dir` | 출력 디렉토리 (기본값: `data/outputs`) |
| `--timeout` | 타임아웃 초 (기본값: 60) |
| `--enable-github-check` | GitHub 공개 노출 힌트 활성화 |
| `--no-pdf` | PDF 생성 생략 |
| `--allow-mock` | 목 데이터 허용 (데모/개발용) |
| `--strict-tools` | 필수 도구 없을 시 강제 종료 |
| `--doctor` | 도구 진단 후 종료 |
| `--verbose` | 상세 로그 출력 |

---

### 리포트 원칙

ALR은 보수적 언어를 일관되게 사용합니다:

| 사용 | 사용 금지 |
|------|----------|
| "가능성 있음", "검토 권장" | "확인된 취약점" |
| "노출 후보", "패턴 감지됨" | "악용 가능", "침해됨" |
| "수동 검증 필요" | "취약점으로 증명됨" |

모든 결과는 패턴 기반 지표이며, 취약점의 증명이 아닙니다.

---

### 테스트

```bash
python3 -m pytest tests/ -v

python3 -m tests.test_target_manager -v
python3 -m tests.test_surface_analyzer -v
python3 -m tests.test_runtime_and_modes -v
python3 -m tests.test_ai_layer -v
python3 -m tests.test_pdf_report -v
```

---

### 주요 특징 및 제한 사항

- 외부 AI API 불필요 — 리포트는 수집 데이터만으로 생성
- PDF가 주요 산출물이며 ChatGPT 업로드에 최적화됨
- dnsx, naabu, wappalyzer는 기본 실행 경로에 포함되지 않음
- GitHub 노출 힌트는 선택 사항 (`--enable-github-check`)
- 기본 실행은 공격적 스캔 없이 저영향 수집만 수행
- 패시브 수집 특성상 내부 시스템, 인증 필요 엔드포인트는 관찰 불가
- 수집 데이터는 공개 소스 기준이며 실제 현황과 다소 차이가 있을 수 있음

---

---

## English

> **Passive-first, low-noise OSINT reconnaissance framework.**
> Collects publicly available intelligence, analyzes the external attack surface,
> and generates a professional PDF report — **no AI API required.**

---

### Overview

ALR performs passive-first reconnaissance against a target domain or IP address
using only public data sources. It produces a structured **PDF report** as its
primary deliverable — suitable for direct review or optional upload to ChatGPT
for further manual interpretation.

- No external AI API key required
- No OpenAI / Anthropic billing
- Report is generated entirely from collected data

---

### ⚠️ Legal Notice

- **Only run against targets you have explicit written authorization to assess.**
- This tool is NOT an exploit framework or vulnerability scanner.
- All findings are heuristic pattern indicators — no confirmed vulnerabilities are asserted.

---

### How It Works

```
Target Input
    │
    ▼
Passive subdomain discovery (subfinder)
    │
    ▼
Certificate Transparency enrichment (crt.sh — passive)
    │
    ▼
RDAP / WHOIS / ASN enrichment (passive)
    │
    ▼
HTTP asset verification (httpx — lightweight active)
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

### Output Files

```
output/
└── nafal.store.pdf          ← user-facing PDF (named by target — primary artifact)

data/outputs/<run_id>/
├── output.json              ← full normalized data (debug/trace)
├── report.md                ← Markdown summary
└── report.pdf               ← internal copy
```

---

### PDF Report Sections

| # | Section |
|---|---------|
| 1 | Cover / Title Block (target, run ID, mode, timestamp) |
| 2 | Executive Summary |
| 3 | Data Collection Scope & Reliability |
| 4 | Reconnaissance Summary (counts/totals) |
| 5 | Surface Analysis Findings |
| 6 | Priority Review Targets |
| 7 | Infrastructure & Ownership Context (RDAP/ASN) |
| 8 | HTTP Exposure Summary |
| 9 | Public Exposure Hints (GitHub, if enabled) |
| 10 | Limitations & Notes |
| 11 | Appendix — Output References |

> The generated PDF is designed to be uploaded directly to ChatGPT or another
> AI assistant for manual interpretation. ALR itself makes no AI API calls.

---

### Requirements

**Python**
- Python 3.10+
- `python-dotenv` — .env loading
- `reportlab` — PDF generation
- `PyGithub` — optional, for `--enable-github-check`

**External CLI Tools (requires Go 1.19+)**

| Tool | Purpose | Status |
|------|---------|--------|
| subfinder | Passive subdomain discovery | ✅ Required |
| httpx | Lightweight HTTP verification | ✅ Required |

> **Not in the default path:** dnsx, naabu, wappalyzer.
> These may exist as inactive future modules but are not used by default.

**Supported Environments**
- Linux / WSL — recommended and tested
- macOS — untested
- Windows native — not supported

---

### Installation

```bash
git clone https://github.com/GrayOM/Availability-Low-Reconnaissance.git
cd Availability-Low-Reconnaissance/alr_project/alr

# Python dependencies
pip install python-dotenv reportlab

# Reconnaissance tools (requires Go)
bash ./scripts/bootstrap_tools.sh

# Verify tools
python3 -m cli.main --doctor
```

Manual tool installation:
```bash
export GOBIN=$(pwd)/.tools/bin
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

---

### Usage

```bash
# Basic run (recommended)
python3 -m cli.main --domain example.com

# IP target
python3 -m cli.main --ip 203.0.113.10

# Include GitHub public exposure hints
python3 -m cli.main --domain example.com --enable-github-check

# Skip PDF export
python3 -m cli.main --domain example.com --no-pdf

# Demo with mock data (no tools required)
python3 -m cli.main --domain example.com --allow-mock

# Diagnostics
python3 -m cli.main --doctor
```

**All CLI Flags**

| Flag | Description |
|------|-------------|
| `--domain` / `--ip` | Target (required) |
| `--output-dir` | Output directory (default: `data/outputs`) |
| `--timeout` | Timeout in seconds (default: 60) |
| `--enable-github-check` | Enable GitHub public exposure hints |
| `--no-pdf` | Skip PDF export |
| `--allow-mock` | Allow mock/fallback data (demo/dev only) |
| `--strict-tools` | Hard fail if required tools are missing |
| `--doctor` | Run diagnostics and exit |
| `--verbose` | Verbose logging |

---

### Configuration (`.env`)

```bash
cp .env.example .env
```

```env
SUBFINDER_BIN=subfinder
HTTPX_BIN=httpx
ALR_OUTPUT_DIR=data/outputs
ALR_TIMEOUT=60
# GITHUB_TOKEN=ghp_xxx   (optional, for --enable-github-check)
```

---

### Report Philosophy

ALR enforces conservative language throughout all outputs:

| Use | Avoid |
|-----|-------|
| "possible", "review recommended" | "confirmed vulnerability" |
| "exposure candidate" | "definitely exploitable" |
| "pattern suggests" | "breach", "compromised" |
| "manual validation required" | "proven to be vulnerable" |

All findings are clue-based pattern indicators, not proof of vulnerability.

---

### Architecture

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

### Tests

```bash
python3 -m pytest tests/ -v

python3 -m tests.test_target_manager -v
python3 -m tests.test_surface_analyzer -v
python3 -m tests.test_runtime_and_modes -v
python3 -m tests.test_ai_layer -v
python3 -m tests.test_pdf_report -v
```

---

### Notes

- ALR does not require any external AI API
- PDF is the primary deliverable, optimized for ChatGPT upload
- dnsx, naabu, and wappalyzer are not in the default path
- GitHub hints are optional (`--enable-github-check`)
- All runs are low-impact; no aggressive scanning is performed
- Passive collection cannot observe internal systems or authenticated endpoints
- Data is sourced from public registries and may not reflect real-time changes
