"""
Decorator-based forensic analysis for HTTP proxy captures (Charles Proxy format).
Focuses on session token security in MedMij/PGO connections.
"""
import base64
import functools
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class Finding:
    severity: str  # CRITICAL / HIGH / MEDIUM / INFO
    category: str
    detail: str


@dataclass
class ForensicReport:
    transaction_id: str
    host: str
    path: str
    server_ip: str
    findings: list[Finding] = field(default_factory=list)
    tokens: dict[str, str] = field(default_factory=dict)

    def add(self, severity: str, category: str, detail: str) -> None:
        self.findings.append(Finding(severity, category, detail))

    def summary(self) -> str:
        counts = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return " | ".join(f"{k}: {v}" for k, v in sorted(counts.items()))


# ── Decorators ──────────────────────────────────────────────────────────────

def forensic_check(fn: Callable) -> Callable:
    """Marks a function as a forensic check; records timing."""
    @functools.wraps(fn)
    def wrapper(report: ForensicReport, data: dict) -> None:
        t = time.monotonic()
        fn(report, data)
        elapsed = time.monotonic() - t
        if elapsed > 0.1:
            report.add("INFO", "perf", f"{fn.__name__} took {elapsed:.3f}s")
    return wrapper


def require_ssl(fn: Callable) -> Callable:
    """Skip check when transport is not SSL (findings would be misleading)."""
    @functools.wraps(fn)
    def wrapper(report: ForensicReport, data: dict) -> None:
        if not data.get("isSSL"):
            report.add("CRITICAL", "transport", "Non-SSL connection detected")
            return
        fn(report, data)
    return wrapper


# ── Checks ──────────────────────────────────────────────────────────────────

@forensic_check
@require_ssl
def check_session_tokens(report: ForensicReport, data: dict) -> None:
    cookies = _get_header(data["request"], "cookie") or ""
    for pair in cookies.split("; "):
        if "=" not in pair:
            continue
        name, _, value = pair.partition("=")
        name = name.strip()
        report.tokens[name] = value[:64] + ("…" if len(value) > 64 else "")

    jsessionid = report.tokens.get("JSESSIONID", "")
    if jsessionid:
        report.add("INFO", "token", f"JSESSIONID present ({len(jsessionid)} chars)")
        # Weak entropy heuristic: all-hex 32-char tokens are often sequential
        if len(jsessionid) == 32 and all(c in "0123456789ABCDEFabcdef" for c in jsessionid):
            report.add("MEDIUM", "token", "JSESSIONID is 32-char hex — verify randomness/entropy")

    if not report.tokens.get("COOKIE_SUPPORT"):
        report.add("LOW", "token", "COOKIE_SUPPORT flag absent")


@forensic_check
def check_cookie_flags(report: ForensicReport, data: dict) -> None:
    """Infer missing Secure/HttpOnly flags from Set-Cookie response headers."""
    for entry in data["response"]["header"]["entries"]:
        if entry["key"]["nameInLowercase"] == "set-cookie":
            val = entry["value"]
            if "Secure" not in val:
                report.add("HIGH", "cookie-flags", f"Set-Cookie missing Secure: {val[:80]}")
            if "HttpOnly" not in val:
                report.add("HIGH", "cookie-flags", f"Set-Cookie missing HttpOnly: {val[:80]}")
            if "SameSite" not in val:
                report.add("MEDIUM", "cookie-flags", f"Set-Cookie missing SameSite: {val[:80]}")


@forensic_check
def check_medmij_redirect(report: ForensicReport, data: dict) -> None:
    cookies = _get_header(data["request"], "cookie") or ""
    redirect_raw = ""
    for pair in cookies.split("; "):
        if pair.startswith("quliRedirect="):
            redirect_raw = pair[len("quliRedirect="):]
            break
    if not redirect_raw:
        return
    try:
        redirect = json.loads(redirect_raw)
        mfn = redirect.get("params", {}).get("mfn", "")
        report.add("INFO", "medmij", f"MedMij redirect → {mfn} (flow: {redirect.get('name')})")
    except json.JSONDecodeError:
        report.add("HIGH", "medmij", "quliRedirect cookie is not valid JSON — possible tampering")


@forensic_check
def check_security_headers(report: ForensicReport, data: dict) -> None:
    headers = {e["key"]["nameInLowercase"]: e["value"]
               for e in data["response"]["header"]["entries"]}

    required = {
        "content-security-policy": "CSP missing",
        "x-frame-options": "X-Frame-Options missing",
        "x-content-type-options": "X-Content-Type-Options missing",
        "strict-transport-security": "HSTS missing",
    }
    for header, msg in required.items():
        if header not in headers:
            report.add("HIGH", "security-headers", msg)
        else:
            report.add("INFO", "security-headers", f"{header}: {headers[header][:60]}")

    csp = headers.get("content-security-policy", "")
    if "unsafe-inline" in csp:
        report.add("HIGH", "csp", "CSP allows unsafe-inline scripts")
    if "unsafe-eval" in csp:
        report.add("HIGH", "csp", "CSP allows unsafe-eval")


@forensic_check
def check_response_body_integrity(report: ForensicReport, data: dict) -> None:
    """Validate that the served JS has not been tampered with (length sanity)."""
    body_b64 = data["response"].get("bodyData", "")
    if not body_b64:
        report.add("MEDIUM", "integrity", "Response body is empty — possible interception")
        return

    # bodyData may contain surrogate/non-ASCII chars from proxy encoding
    raw = body_b64.encode("latin-1", errors="replace")
    try:
        body = base64.b64decode(raw + b"==")
        report.add("INFO", "integrity", f"Response body decoded: {len(body):,} bytes")
        if len(body) < 1000:
            report.add("HIGH", "integrity", "Suspiciously small JS response — possible content substitution")
    except Exception as exc:
        report.add("LOW", "integrity", f"Could not fully decode body ({exc})")


@forensic_check
def check_timing(report: ForensicReport, data: dict) -> None:
    t = data.get("timing", {})
    if not t:
        return
    ttfb = t["responseStartedAt"] - t["requestEndedAt"]
    total = t["responseEndedAt"] - t["requestStartedAt"]
    report.add("INFO", "timing", f"TTFB {ttfb*1000:.0f}ms  total {total*1000:.0f}ms")
    if ttfb > 2.0:
        report.add("MEDIUM", "timing", f"High TTFB ({ttfb:.2f}s) — possible MitM latency injection")


# ── Runner ───────────────────────────────────────────────────────────────────

CHECKS: list[Callable] = [
    check_session_tokens,
    check_cookie_flags,
    check_medmij_redirect,
    check_security_headers,
    check_response_body_integrity,
    check_timing,
]


def analyse(data: dict) -> ForensicReport:
    summary = data.get("summary", {})
    report = ForensicReport(
        transaction_id=data.get("name", "?"),
        host=_get_header(data["request"], "host") or data["request"].get("host", "?"),
        path=data["request"].get("uri", ""),
        server_ip=summary.get("serverIpAddress", "?"),
    )
    for check in CHECKS:
        check(report, data)
    return report


def _get_header(req_or_resp: dict, name: str) -> str | None:
    for entry in req_or_resp.get("header", {}).get("entries", []):
        if entry["key"]["nameInLowercase"] == name.lower():
            return entry["value"]
    return None
