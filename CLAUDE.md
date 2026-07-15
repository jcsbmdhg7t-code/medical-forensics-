# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**nd-connection-platform** is a **forensic analysis toolkit for Dutch healthcare security**. It analyzes network captures (Proxyman, Charles Proxy, HAR) from Epic MyChart / MijnSpaarneGasthuis patient portals, validates MedMij/PGO data flows, and extracts forensic evidence from healthcare documents.

### Domain context
- **MedMij / PGO**: Dutch personal health record system; portals exchange patient data via authenticated redirect flows (`quliRedirect` cookie, `mfn` provider tokens)
- **Epic MyChart / MijnSpaarneGasthuis**: Epic EPD portal used by Spaarne Gasthuis hospital
- **Forensic scope**: session security, cookie flags, security headers, PII exposure, content-substitution, DOM manipulation, tracker injection, audit-log blocking, CSS-based data hiding

### Key characteristics
- No external framework dependencies — all tools are standalone Python 3.x or Vanilla JS/HTML
- Evidence integrity via SHA-256 hashing throughout
- Color-coded severity output: CRITICAL (red) → HIGH (yellow) → MEDIUM (blue) → LOW (cyan) → INFO (gray)
- Python tools run directly: `python3 <script>.py <args>`

---

## Repository Structure

```
nd-connection-platform/
├── forensic/                      # Importable Python package
│   ├── __init__.py                # Exports: analyse, forensic_check, require_ssl, ForensicReport, Finding
│   ├── decorators.py              # Single-transaction checks (Charles Proxy .dat format)
│   ├── multi.py                   # Multi-transaction analyser (.proxymanlogv2 / HAR archives)
│   ├── cli.py                     # CLI runner for single .dat captures (entry point)
│   └── report.py                  # Report formatting utilities
├── forensic_extractor.py          # Document extraction tool (HAR/ZIP/PDF/DOCX/XML/FHIR/binary)
├── storm_sniffer_analyzer.py      # Proxyman/HAR analyzer: Epic-specific forensic patterns
├── portal_forensic_inject.js      # DOM monitoring injection script for Epic portals
├── proxyman-filter.html           # Standalone interactive filter UI for captured transactions
├── FORENSISCH_RAPPORT_MEDISCHE_CODES.md  # Medical codes forensic report (Dutch)
├── TEST_COVERAGE_ANALYSIS.md      # Testing strategy baseline
└── CLAUDE.md                      # This file
```

---

## Running the Tools

### `forensic` package — single or multi-transaction analysis
```bash
# Single Charles Proxy .dat capture
python3 -m forensic.cli <capture.dat>

# Multi-transaction Proxyman archive or HAR
python3 -m forensic.cli <capture.proxymanlogv2>
python3 -m forensic.cli <capture.har>
```

### `forensic_extractor.py` — deep document extraction
```bash
# Extract all data from a directory of network captures and documents
python3 forensic_extractor.py <input_dir> <output_dir>

# iCloud mode (adjusts path handling)
python3 forensic_extractor.py <input_dir> <output_dir> --icloud
```
Outputs: Excel workbook (multi-sheet), extraction directory, SHA-256 evidence log.

Optional dependencies (graceful fallback if absent):
```bash
pip install openpyxl PyMuPDF python-docx chardet
```

### `storm_sniffer_analyzer.py` — Epic portal forensic patterns
```bash
python3 storm_sniffer_analyzer.py <capture_file> [--output <dir>]
```
Supports `.proxymanlogv2`, `.har`, generic `.json`. Outputs JSON + plaintext forensic log.

### `proxyman-filter.html` — interactive filter dashboard
Open directly in a browser — no server required. Upload a HAR or JSON capture and filter by domain, tag, method, status code.

### `portal_forensic_inject.js` — DOM monitoring
Paste into browser DevTools Console, or install as a Tampermonkey/Greasemonkey userscript, or inject via Proxyman Script Inject. Monitors DOM for hiding patterns, feature flags, and tracker injection in real time.

---

## `forensic` Package API

### `forensic.decorators`
Core module for single-transaction analysis.

**Data models:**
```python
@dataclass
class Finding:
    severity: str   # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    category: str
    detail: str

@dataclass
class ForensicReport:
    transaction_id: str
    host: str
    path: str
    server_ip: str
    findings: list[Finding]
    tokens: dict[str, str]

    def add(self, severity, category, detail) -> None: ...
    def summary(self) -> str: ...
```

**Main entry point:**
```python
from forensic import analyse
report: ForensicReport = analyse(data_dict)  # data_dict = parsed Charles .dat JSON
```

**Decorator usage:**
```python
from forensic import forensic_check, require_ssl, ForensicReport

@forensic_check          # records timing; adds INFO finding if check takes >0.1s
@require_ssl             # adds CRITICAL finding and returns early if not SSL
def check_something(report: ForensicReport, data: dict) -> None:
    ...
```

**Built-in checks** (run in order via `CHECKS` list):
1. `check_session_tokens` — JSESSIONID entropy, COOKIE_SUPPORT flag
2. `check_cookie_flags` — Secure/HttpOnly/SameSite on Set-Cookie headers
3. `check_medmij_redirect` — `quliRedirect` cookie parsing, MedMij flow detection
4. `check_security_headers` — CSP, X-Frame-Options, X-Content-Type-Options, HSTS
5. `check_response_body_integrity` — body size sanity, base64 decode, content substitution
6. `check_timing` — TTFB analysis, MitM latency injection heuristic (>2s TTFB → MEDIUM)

### `forensic.multi`
Multi-transaction analysis for `.proxymanlogv2` archives.

```python
from forensic.multi import analyse_archive, ArchiveReport, Transaction

report: ArchiveReport = analyse_archive("capture.proxymanlogv2")
# report.findings     — list[Finding] with tx_id field
# report.pii          — extracted user profile dict (name, email, mobile, dob, roles…)
# report.auth_tokens  — Liferay CSRF tokens keyed by token value → list of portlet ids
# report.medmij_transactions — list of raw MedMij transaction dicts
# report.medmij_providers    — list of raw MedMij provider dicts
```

**`Finding` in `multi` has an extra field:**
```python
@dataclass
class Finding:
    severity: str
    tx_id: str      # transaction id from archive
    category: str
    detail: str
```

---

## Code Conventions

### Language & compatibility
- Python 3.10+ (`int | str` union syntax, `list[X]` generics without `from __future__`)
- No third-party dependencies in the `forensic/` package — stdlib only
- Use `@dataclass` for data-holding types; avoid plain dicts for structured data

### Naming
- Functions prefixed with `check_` are forensic check functions — they must accept `(report, data)` and return `None`
- Private helpers are prefixed with `_` (e.g., `_get_header`, `_decode`, `_cookies`)
- Module-level constants are `UPPER_SNAKE_CASE`; dataclass fields use `snake_case`

### Adding a new forensic check to `forensic/decorators.py`
1. Define a function `check_<name>(report: ForensicReport, data: dict) -> None`
2. Decorate with `@forensic_check` (and `@require_ssl` if the check only applies to SSL)
3. Append the function to the `CHECKS` list at the bottom of the module — order matters

### Severity levels
| Level | When to use |
|-------|-------------|
| CRITICAL | Security control completely absent (non-SSL, no auth) |
| HIGH | Security header/flag missing, PII in plaintext, CSP allows unsafe-inline/eval |
| MEDIUM | Weak entropy, missing SameSite, suspicious body size, CSRF token reuse |
| LOW | Missing informational flags (COOKIE_SUPPORT), 404 responses |
| INFO | Observations, timing data, extracted metadata |

### Error handling
- Forensic tools must not crash on malformed input — use `try/except` around format parsing
- Missing optional dependencies are handled with `HAS_*` boolean flags and graceful fallback
- Never expose raw exceptions in forensic output; log them as LOW/INFO findings

### Evidence integrity
- All output that may be used as legal/forensic evidence must include SHA-256 hashes
- Do not modify input files — treat all captures as read-only

---

## Testing Strategy

No test files exist yet. When tests are added, follow this priority order:

### 1. Unit tests (highest priority)
Target: `forensic/decorators.py` and `forensic/multi.py` — the core analysis logic.
```
tests/unit/
├── test_decorators.py   # check_* functions with fixture .dat dicts
├── test_multi.py        # analyse_archive with synthetic ZIP archives
└── test_report.py       # ForensicReport / ArchiveReport methods
```
Use `pytest`. No external fixtures required — build minimal `dict` inputs inline.

### 2. Integration tests
```
tests/integration/
├── test_cli.py          # Invoke forensic.cli.main() with real sample .dat files
└── test_extractor.py    # Run forensic_extractor.py against synthetic ZIP/HAR inputs
```

### 3. Edge cases to cover
- Malformed JSON in captures (should not raise)
- Empty archive (0 transactions)
- Non-SSL transaction passed to `@require_ssl` check
- JSESSIONID exactly 32 hex chars vs. longer token
- Missing `bodyData` in response

### Running tests (once configured)
```bash
pip install pytest pytest-cov
pytest --cov=forensic tests/
```

---

## Code Review Checklist

1. **Forensic correctness**: Do new findings use the correct severity level per the table above?
2. **No crash on bad input**: Is all format parsing wrapped in try/except?
3. **Evidence integrity**: Are SHA-256 hashes logged for any new extraction output?
4. **No PII in logs**: Do findings reference PII only as necessary for the forensic record?
5. **Dependency hygiene**: Does new code in `forensic/` stay stdlib-only?
6. **Decorator order**: Is `@forensic_check` outermost, `@require_ssl` innermost?
7. **CHECKS list**: Is a new check function appended to `CHECKS` in `decorators.py`?

---

## Useful References

- **TEST_COVERAGE_ANALYSIS.md** — Baseline testing strategy and recommended testing layers
- **FORENSISCH_RAPPORT_MEDISCHE_CODES.md** — Medical codes analysis (Dutch); ICD-10, SNOMED CT, G-standaard, LOINC, DHD Thesaurus context
- MedMij documentation: `mfn` = MedMij identifier for PGO provider; `quliRedirect` = Quli redirect cookie carrying provider flow
- Epic MyChart feature flags referenced in `storm_sniffer_analyzer.py` and `portal_forensic_inject.js`: `DISABLEMYCONDITIONS`, `DISABLEPLANOFCARE`, `USERAUDITTRAIL`, `AUTOGENERATESIGNATURE`, `SUBSTANCEHXQNR`

---

**Last Updated:** 2026-06-23
