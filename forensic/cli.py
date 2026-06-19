#!/usr/bin/env python3
"""Run forensic analysis on a Charles Proxy .dat capture."""
import json
import sys
from pathlib import Path
from .decorators import analyse, Finding

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
COLORS = {
    "CRITICAL": "\033[91m", "HIGH": "\033[93m",
    "MEDIUM": "\033[94m",   "LOW": "\033[96m",
    "INFO": "\033[90m",     "RESET": "\033[0m",
}


def _color(severity: str, text: str) -> str:
    return f"{COLORS.get(severity, '')}{text}{COLORS['RESET']}"


def main(path: str) -> None:
    data = json.loads(Path(path).read_text())
    report = analyse(data)

    print(f"\n{'═'*60}")
    print(f"  FORENSIC REPORT  #{report.transaction_id}")
    print(f"{'═'*60}")
    print(f"  Host      : {report.host}")
    print(f"  Path      : {report.path}")
    print(f"  Server IP : {report.server_ip}")
    print(f"  SSL       : {data.get('isSSL')}")
    print(f"  Timezone  : {data.get('timezone')}")
    print(f"{'─'*60}")

    if report.tokens:
        print("  TOKENS FOUND:")
        for name, val in report.tokens.items():
            print(f"    {name} = {val}")
    print(f"{'─'*60}")

    findings = sorted(report.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    for f in findings:
        label = _color(f.severity, f"[{f.severity:<8}]")
        print(f"  {label} [{f.category}] {f.detail}")

    print(f"{'─'*60}")
    print(f"  SUMMARY: {report.summary()}")
    print(f"{'═'*60}\n")


if __name__ == "__main__":
    main(sys.argv[1])
