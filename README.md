# PhantomAI

PhantomAI is a CLI reconnaissance, enumeration, fuzzing, and reporting tool for authorized web security testing.

It can run in three AI modes:
- **Anthropic Mode**: Premium triage and exploit planning using Claude 3.5 Sonnet.
- **Gemini Mode**: Free, high-speed triage using Gemini 2.0 Flash (default fallback).
- **Heuristic Mode**: Local fallback when no API keys are available, ensuring functionality in air-gapped or credit-limited environments.

## Setup

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Linux or macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Optional environment variables:

```powershell
$env:ANTHROPIC_API_KEY = "sk-ant-..."
$env:PHANTOMAI_MODEL = "claude-sonnet-4-20250514"
```

## Usage

### Full scan

```powershell
python cli.py scan https://target.example --mode full
```

### Recon only

```powershell
python cli.py scan https://target.example --mode recon
```

### AI triage from stdin or file

```powershell
Get-Content scan_output.txt | python cli.py ai https://target.example
python cli.py ai https://target.example --file nmap_output.txt
```

### Through a proxy

```powershell
python cli.py scan https://target.example --mode full --proxy http://127.0.0.1:8080
```

### Generate an HTML report from the latest saved session

```powershell
python cli.py report https://target.example
```

### List sessions

```powershell
python cli.py sessions
```

## Config

Settings live in `config.yaml`.

Key sections:
- `ai`: model and token settings
- `scan`: timeouts, concurrency, host and endpoint limits
- `proxy`: outbound proxy settings
- `output`: report directory

You can also point to a different config file:

```powershell
python cli.py scan https://target.example --config .\config.yaml
```

## What the scanner does

- `modules/recon.py`: passive subdomain discovery from public sources
- `modules/enum.py`: common path probing and sensitive endpoint detection
- `modules/fuzzer.py`: lightweight XSS, SQLi, SSRF, and open redirect probes
- `modules/owasp_checks.py`: automated checks for OWASP Top 10 (2021 + 2025)
- `modules/exploit.py`: targeted confirmation using AI or fallback payloads
- `output/logger.py`: SQLite session logging in `%USERPROFILE%\.phantomai\sessions.db`
- `output/report.py`: HTML report generation

## Notes

- Reports are written to the configured report directory, which defaults to `reports`.
- If no Anthropic key is present, PhantomAI automatically falls back to heuristic mode.
- Use this tool only for systems you are explicitly authorized to test.
