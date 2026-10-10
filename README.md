# Infrastructure Security Auditor

Automated audit toolkit for multi-tenant Linux hosting environments that inspects filesystem permissions and verifies frontend stability across hosted sites.

## Overview

Misconfigured file permissions on shared web servers introduce severe privilege escalation and data leak vulnerabilities. This tool connects to CloudPanel or Ubuntu servers over SSH, verifies filesystem permissions against security baselines, and runs a headless Playwright crawl to catch frontend JavaScript regressions across all hosted domains.

## Key Features

- Non-destructive, read-only SSH auditing executing `find` and `stat` commands.
- Preconfigured security policies for Laravel applications (.env, storage, bootstrap/cache).
- Automatic discovery of active domains from filesystem hierarchies.
- Headless browser probing capturing console errors and unhandled exceptions.
- Structured export to CSV and summarized JSON reports.

## Architecture

- Backend Audit (`cloudpanel_auditor.py`): Connects via Paramiko, audits ownership and octal permissions, outputs `cloudpanel_audit_report.csv`.
- Framework Analyzer (`laravel_health_checker.py`): Filters the audit report for critical Laravel vulnerabilities.
- Domain Extractor (`site_url_extractor.py`): Generates a domain registry from the host tree.
- UI Health Probe (`ui_health_scanner.py`): Uses Playwright to visit each domain and record runtime browser errors.
- Report Simplifier (`ui_report_simplifier.py`): Compiles raw browser logs into a concise issue summary.

## Prerequisites

- Python 3.10 or higher.
- Playwright Chromium dependencies installed.
- SSH access with sudo privileges on the target server.

## Installation

```bash
git clone https://github.com/your-username/infra-security-auditor.git
cd infra-security-auditor
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
playwright install chromium
```

## Usage

1. Run the remote permission audit:

```bash
python cloudpanel_auditor.py -H 192.168.1.100 -u root
```

2. Filter for framework-specific vulnerabilities:

```bash
python laravel_health_checker.py cloudpanel_audit_report.csv
```

3. Extract hosted URLs and run frontend health checks:

```bash
python site_url_extractor.py -H 192.168.1.100 -u root
python ui_health_scanner.py
python ui_report_simplifier.py
```

## Security Model

This tool executes read-only operations. It does not run `chmod`, `chown`, or write commands on the audited remote server.

## License

MIT
