"""
Multi-transaction forensic analyser for Proxyman .proxymanlogv2 archives.
"""
import base64
import gzip
import json
import os
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Transaction:
    id: str
    method: str
    path: str
    status: int | str
    server_ip: str
    ssl: bool
    req_headers: dict[str, str]
    resp_headers: dict[str, str]
    req_body: bytes
    resp_body: bytes
    timing: dict[str, float]
    cookies: dict[str, str]
    set_cookies: list[str]


def _headers(section: dict) -> dict[str, str]:
    return {
        e["key"]["nameInLowercase"]: e["value"]
        for e in section.get("header", {}).get("entries", [])
    }


def _decode(b64: str, encoding: str = "") -> bytes:
    if not b64:
        return b""
    try:
        raw = b64.encode("latin-1", errors="replace")
        pad = len(raw) % 4
        if pad:
            raw += b"=" * (4 - pad)
        body = base64.b64decode(raw)
        if "gzip" in encoding:
            try:
                body = gzip.decompress(body)
            except Exception:
                pass
        return body
    except Exception:
        return b""


def _cookies(header_val: str) -> dict[str, str]:
    result = {}
    for pair in header_val.split("; "):
        if "=" in pair:
            n, _, v = pair.partition("=")
            result[n.strip()] = v
    return result


def _parse(raw: str) -> Transaction:
    d = json.loads(raw)
    req = d.get("request", {})
    resp = d.get("response", {})
    method = req.get("method", {})
    rh = _headers(req)
    enc = _headers(resp).get("content-encoding", "")
    status_obj = resp.get("status", {})
    return Transaction(
        id=str(d.get("name", "?")),
        method=method.get("name", "?") if isinstance(method, dict) else str(method),
        path=req.get("uri", req.get("fullPath", "")),
        status=status_obj.get("code", "?") if isinstance(status_obj, dict) else "?",
        server_ip=d.get("summary", {}).get("serverIpAddress", ""),
        ssl=bool(d.get("isSSL")),
        req_headers=rh,
        resp_headers=_headers(resp),
        req_body=_decode(req.get("bodyData", "")),
        resp_body=_decode(resp.get("bodyData", ""), enc),
        timing=d.get("timing", {}),
        cookies=_cookies(rh.get("cookie", "")),
        set_cookies=[
            e["value"]
            for e in resp.get("header", {}).get("entries", [])
            if e["key"]["nameInLowercase"] == "set-cookie"
        ],
    )


def load_archive(path: str) -> list[Transaction]:
    """Load all transactions from a .proxymanlogv2 zip or a single .dat file."""
    txs = []
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                try:
                    txs.append(_parse(zf.read(name).decode("utf-8", errors="replace")))
                except Exception:
                    pass
    else:
        with open(path) as f:
            txs.append(_parse(f.read()))
    txs.sort(key=lambda t: int(t.id) if t.id.isdigit() else 0)
    return txs


# ── Forensic checks ──────────────────────────────────────────────────────────

@dataclass
class Finding:
    severity: str
    tx_id: str
    category: str
    detail: str


@dataclass
class ArchiveReport:
    source: str
    transactions: int
    findings: list[Finding] = field(default_factory=list)
    pii: dict[str, Any] = field(default_factory=dict)
    auth_tokens: dict[str, list[str]] = field(default_factory=dict)
    medmij_transactions: list[dict] = field(default_factory=list)
    medmij_providers: list[dict] = field(default_factory=list)

    def add(self, severity: str, tx_id: str, category: str, detail: str) -> None:
        self.findings.append(Finding(severity, tx_id, category, detail))

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


_REQUIRED_HEADERS = {
    "strict-transport-security": "HSTS missing — downgrade attacks possible",
    "x-xss-protection": "X-XSS-Protection missing",
}
_PRESENT_HEADERS = {
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
}
_HSTS_WARNED = False


def analyse_archive(path: str) -> ArchiveReport:
    txs = load_archive(path)
    report = ArchiveReport(source=os.path.basename(path), transactions=len(txs))

    hsts_warned = False
    jsessionids_seen: set[str] = set()

    for tx in txs:
        body_str = tx.resp_body.decode("utf-8", errors="replace")
        req_body_str = tx.req_body.decode("utf-8", errors="replace")

        # ── Redirect chain ──────────────────────────────────────────────
        if tx.status in (301, 302, "301", "302"):
            loc = tx.resp_headers.get("location", "")
            report.add("INFO", tx.id, "redirect", f"{tx.method} {tx.path} → {loc}")

        # ── HSTS (once) ─────────────────────────────────────────────────
        if not hsts_warned and "strict-transport-security" not in tx.resp_headers:
            report.add("HIGH", tx.id, "hsts", "HSTS header absent (consistent across all responses)")
            hsts_warned = True

        # ── Set-Cookie flags ─────────────────────────────────────────────
        for sc in tx.set_cookies:
            flags = []
            if "Secure" not in sc:
                flags.append("Secure")
            if "HttpOnly" not in sc and "httponly" not in sc.lower():
                flags.append("HttpOnly")
            if "SameSite" not in sc:
                flags.append("SameSite")
            if flags:
                report.add("HIGH", tx.id, "cookie-flags",
                           f"Set-Cookie missing {', '.join(flags)}: {sc[:60]}")

        # ── JSESSIONID entropy (deduplicated per unique value) ───────────
        jsid = tx.cookies.get("JSESSIONID", "")
        if jsid and jsid not in jsessionids_seen and len(jsid) == 32 and all(c in "0123456789ABCDEFabcdef" for c in jsid):
            jsessionids_seen.add(jsid)
            report.add("MEDIUM", tx.id, "token",
                       f"JSESSIONID 32-char hex — verify server-side entropy: {jsid}")

        # ── Auth token responses (Liferay CSRF) ──────────────────────────
        if (tx.method == "POST" and 4 <= len(body_str.strip()) <= 20
                and body_str.strip().isascii() and "{" not in body_str):
            token = body_str.strip()
            portlet = ""
            if "portletId=" in req_body_str:
                portlet = req_body_str.split("portletId=")[-1][:40]
            report.auth_tokens.setdefault(token, []).append(portlet or tx.id)
            report.add("INFO", tx.id, "auth-token",
                       f"Portlet CSRF token issued: {token!r} for {portlet[:40]}")

        # ── PII in JSON responses ─────────────────────────────────────────
        if "application/json" in tx.resp_headers.get("content-type", "") or body_str.startswith("{"):
            try:
                parsed = json.loads(body_str)
                user = parsed.get("user") if isinstance(parsed, dict) else None
                if user and "emailAddress" in user:
                    report.pii = {
                        "name": user.get("profileName"),
                        "email": user.get("emailAddress"),
                        "mobile": user.get("mobile"),
                        "birth_date": user.get("scopeUserBirthDate"),
                        "user_id": user.get("userId"),
                        "group": user.get("groupUrl"),
                        "auth_level": user.get("authLevel"),
                        "email_verified": user.get("emailAddressVerified"),
                        "2fa_methods": user.get("userHasTwoFactorMethods"),
                        "must_set_2fa": user.get("mustSetTwoFactor"),
                        "roles": list((user.get("permissions") or {})
                                      .get("scopeGroupRoles", {}).keys()),
                    }
                    report.add("HIGH", tx.id, "pii",
                               f"User profile with PII in plaintext response: name={user.get('profileName')}, "
                               f"email={user.get('emailAddress')}, mobile={user.get('mobile')}, "
                               f"dob={user.get('scopeUserBirthDate')}")
                    if not user.get("emailAddressVerified"):
                        report.add("MEDIUM", tx.id, "account",
                                   "Email address NOT verified — notifications may go to wrong address")

                # MedMij transactions
                txlist = parsed.get("transactions") if isinstance(parsed, dict) else None
                if txlist and isinstance(txlist, list) and txlist and "transactionId" in txlist[0]:
                    report.medmij_transactions = txlist
                    partial = [t for t in txlist if t.get("status") != "SUCCESS"]
                    report.add("INFO", tx.id, "medmij",
                               f"{len(txlist)} MedMij transactions found; "
                               f"{len(partial)} with non-SUCCESS status")

                # MedMij providers
                prov = parsed.get("providers") if isinstance(parsed, dict) else None
                if prov and isinstance(prov, list) and prov and "mfn" in prov[0]:
                    report.medmij_providers = prov
                    for p in prov:
                        report.add("INFO", tx.id, "medmij-provider",
                                   f"{p['name']}  mfn={p['mfn']}  status={p['status']}")

            except (json.JSONDecodeError, KeyError):
                pass

        # ── Error responses ──────────────────────────────────────────────
        if tx.status in (404, "404") and tx.path not in ("/apple-touch-icon-precomposed.png",):
            report.add("LOW", tx.id, "error", f"404 on {tx.path}")
        if "Http Status 0" in body_str:
            report.add("MEDIUM", tx.id, "error",
                       f"Server returned Http Status 0 (null) on {tx.path} — possible expired session token")

        # ── Auth token reuse ─────────────────────────────────────────────

    for token, uses in report.auth_tokens.items():
        if len(uses) > 1:
            report.add("MEDIUM", "multi", "auth-token-reuse",
                       f"CSRF token {token!r} reused across {len(uses)} portlets: {uses}")

    return report
