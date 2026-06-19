#!/usr/bin/env python3
"""CLI: forensic report for single .dat or .proxymanlogv2 archive."""
import sys
from .multi import analyse_archive
from datetime import datetime

SEV = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
CLR = {
    "CRITICAL": "\033[91m", "HIGH": "\033[93m",
    "MEDIUM": "\033[94m",   "LOW": "\033[96m",
    "INFO": "\033[90m",     "RESET": "\033[0m",
}


def c(sev: str, text: str) -> str:
    return f"{CLR.get(sev,'')}{text}{CLR['RESET']}"


def main(path: str) -> None:
    report = analyse_archive(path)

    W = 70
    print(f"\n{'═'*W}")
    print(f"  FORENSIC REPORT  —  {report.source}")
    print(f"  {report.transactions} transactions  |  {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'═'*W}")

    if report.pii:
        p = report.pii
        print(f"\n  {'PII EXTRACTED':─<{W-2}}")
        print(f"  Name       : {p.get('name')}")
        print(f"  Email      : {p.get('email')}  (verified={p.get('email_verified')})")
        print(f"  Mobile     : {p.get('mobile')}")
        print(f"  Birth date : {p.get('birth_date')}")
        print(f"  User ID    : {p.get('user_id')}  group={p.get('group')}")
        print(f"  Auth level : {p.get('auth_level')}  2FA={p.get('2fa_methods')}  must_set_2fa={p.get('must_set_2fa')}")
        print(f"  Roles      : {', '.join(p.get('roles', []))}")

    if report.medmij_providers:
        print(f"\n  {'MEDMIJ PROVIDERS':─<{W-2}}")
        for p in report.medmij_providers:
            from datetime import datetime as dt
            last = dt.fromtimestamp(p['dateOfLastTransaction']/1000).date()
            print(f"  {p['name']:<40} mfn={p['mfn']}")
            print(f"    last={last}  status={p['status']}")

    if report.medmij_transactions:
        print(f"\n  {'MEDMIJ TRANSACTIONS ({})'.format(len(report.medmij_transactions)):─<{W-2}}")
        for tx in report.medmij_transactions:
            from datetime import datetime as dt
            ts = dt.fromtimestamp(tx['transactionDate']/1000).date()
            status_tag = "" if tx['status'] == "SUCCESS" else f"  !! {tx['status']}"
            print(f"  [{tx['id']}] {ts}  {tx['providerName']:<45} {tx['status']}{status_tag}")

    if report.auth_tokens:
        print(f"\n  {'PORTLET CSRF TOKENS':─<{W-2}}")
        for token, uses in report.auth_tokens.items():
            reuse = f"  (reused ×{len(uses)})" if len(uses) > 1 else ""
            print(f"  {token!r:<14}{reuse}")

    print(f"\n  {'FINDINGS':─<{W-2}}")
    findings = sorted(report.findings, key=lambda f: SEV.get(f.severity, 99))
    for f in findings:
        label = c(f.severity, f"[{f.severity:<8}]")
        print(f"  {label} tx={f.tx_id:<6} [{f.category}] {f.detail}")

    print(f"\n  {'SUMMARY':─<{W-2}}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        n = report.summary().get(sev, 0)
        if n:
            print(f"  {c(sev, sev):<20} {n}")
    print(f"{'═'*W}\n")


if __name__ == "__main__":
    main(sys.argv[1])
