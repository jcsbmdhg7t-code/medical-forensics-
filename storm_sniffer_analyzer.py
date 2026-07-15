#!/usr/bin/env python3
"""
Forensisch analyzer voor Storm Sniffer / Proxyman captures.
Parse HAR, .proxymanlogv2, JSON formats en detect kritieke patronen.
"""

import os
import sys
import json
import gzip
import zlib
import base64
import hashlib
import re
import datetime
import pathlib
import argparse

CRITICAL_PATTERNS = {
    'DIAGNOSE_CODE': [
        (re.compile(r'F19\.1|neusdruppelmisbruik', re.I), 'NB-01 F19.1'),
        (re.compile(r'361055000'), 'NB-03 SNOMED 361055000'),
        (re.compile(r'228273003'), 'NB-23 SNOMED 228273003'),
    ],
    'CDA_ANOMALY': [
        (re.compile(r'extension="999999"', re.I), 'NB-18 anonymous author'),
        (re.compile(r'extension="373282512"', re.I), 'NB-05 al-Mousawi'),
    ],
    'AUDIT_TRAIL': [
        (re.compile(r'GetClinicianAccessLog|GetThirdPartyAccessLog', re.I), 'NB-163 audit blocked'),
    ],
    'TELEMETRY': [
        (re.compile(r'hotjar|sentry\.io|datadog', re.I), 'NB-79/69 telemetry'),
    ],
}

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha256_str(s: str) -> str:
    return sha256(s.encode("utf-8", errors="replace"))

def decode_body(body_raw, encoding=""):
    if not body_raw:
        return ""
    try:
        data = base64.b64decode(body_raw + "==") if isinstance(body_raw, str) else body_raw
        if encoding in ("gzip", "gz") or data[:2] == b'\x1f\x8b':
            data = gzip.decompress(data)
        elif encoding in ("deflate", "zlib"):
            try:
                data = zlib.decompress(data)
            except Exception:
                data = zlib.decompress(data, -15)
        return data.decode("utf-8", errors="replace")
    except Exception:
        return body_raw if isinstance(body_raw, str) else body_raw.decode("utf-8", errors="replace")

def parse_har(path: str) -> list:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        har = json.load(f)
    transacties = []
    for entry in har.get("log", {}).get("entries", []):
        req = entry.get("request", {})
        resp = entry.get("response", {})
        content = resp.get("content", {})
        tekst = content.get("text", "")
        if content.get("encoding") == "base64" and tekst:
            tekst = decode_body(tekst, content.get("mimeType", ""))
        req_body = req.get("postData", {}).get("text", "")
        headers = " ".join(f"{h['name']}: {h['value']}" for h in resp.get("headers", []) + req.get("headers", []))
        gecombineerd = tekst + "\n" + req_body + "\n" + headers
        transacties.append((req.get("url", ""), req.get("method", ""), resp.get("status", 0), entry.get("startedDateTime", ""), gecombineerd))
    return transacties

def parse_json(path: str) -> list:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)
    records = data if isinstance(data, list) else data.get("entries", data.get("requests", [data]))
    return [(str(r.get("url", r.get("uri", ""))), str(r.get("method", "")), int(r.get("status", r.get("statusCode", 0))), str(r.get("timestamp", r.get("time", ""))), json.dumps(r)) for r in records]

def scan_text(text: str, url: str, method: str, status: int, timestamp: str) -> list:
    bevindingen = []
    for category, patterns in CRITICAL_PATTERNS.items():
        for regex, label in patterns:
            if regex.search(text):
                bevindingen.append({
                    'category': category,
                    'label': label,
                    'url': url[:200],
                    'method': method,
                    'status': status,
                    'timestamp': timestamp,
                    'hash': sha256_str(label + url + timestamp),
                })
    return bevindingen

def analyse(pad: str, output_map: str):
    start = datetime.datetime.now(datetime.timezone.utc)
    ext = pathlib.Path(pad).suffix.lower()
    
    if ext == ".har":
        transacties = parse_har(pad)
    elif ext == ".json":
        transacties = parse_json(pad)
    else:
        transacties = []

    print(f"[+] {len(transacties)} transacties geladen")

    alle_bevindingen = []
    for url, methode, status, tijdstempel, tekst in transacties:
        alle_bevindingen.extend(scan_text(tekst, url, methode, status, tijdstempel))

    gezien = set()
    uniek = []
    for b in alle_bevindingen:
        h = b['hash']
        if h not in gezien:
            gezien.add(h)
            uniek.append(b)

    print(f"[+] {len(alle_bevindingen)} bevindingen ({len(uniek)} uniek)")

    os.makedirs(output_map, exist_ok=True)
    ts = start.strftime("%Y%m%d_%H%M%S")

    output_file = os.path.join(output_map, f"forensisch_rapport_{ts}.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump({"bevindingen": uniek, "meta": {"input": pad, "timestamp": start.isoformat()}}, f, ensure_ascii=False, indent=2)

    print(f"[+] Rapport opgeslagen: {output_file}")
    return uniek

def main():
    parser = argparse.ArgumentParser(description="Forensisch analyzer voor Storm Sniffer / Proxyman captures")
    parser.add_argument("invoer", help="Capture-bestand (.proxymanlogv2, .har, .json)")
    parser.add_argument("--output", "-o", default="forensisch_output", help="Output map")
    args = parser.parse_args()

    if not os.path.exists(args.invoer):
        print(f"[!] Bestand niet gevonden: {args.invoer}", file=sys.stderr)
        sys.exit(1)

    try:
        bevindingen = analyse(args.invoer, args.output)
        sys.exit(0 if not any(b['label'].startswith('KRITIEK') for b in bevindingen) else 2)
    except Exception as e:
        print(f"[!] Fout: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
