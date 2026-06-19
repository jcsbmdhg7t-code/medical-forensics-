#!/usr/bin/env python3
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

CSS_VERBERGING = [
    (re.compile(r'\.hiddenProvider\s*\{[^}]*display\s*:\s*none', re.I), "CSS .hiddenProvider display:none — patiëntgegevens verborgen (NB-12)"),
    (re.compile(r'CEDataExternal\s*\{[^}]*display\s*:\s*none', re.I), "CSS CEDataExternal display:none — externe data verborgen (NB-12)"),
    (re.compile(r'\.SRonly|SRonly\s*\{[^}]*left\s*:\s*-\d{4,}px', re.I), "CSS SRonly — schermlezer-verberging (NB-53/56)"),
    (re.compile(r'display\s*:\s*none\s*!important', re.I), "CSS display:none !important — forceerde verberging"),
    (re.compile(r'visibility\s*:\s*hidden', re.I), "CSS visibility:hidden"),
    (re.compile(r'font-size\s*:\s*0(px)?[;\s]', re.I), "CSS font-size:0 — tekst onzichtbaar gemaakt"),
    (re.compile(r'left\s*:\s*-1000\d+px', re.I), "CSS off-screen positie (left:-10000px) — SRonly patroon (NB-53)"),
    (re.compile(r'printBlackText', re.I), "CSS printBlackText — alarmkleuren geneutraliseerd bij afdrukken (NB-84)"),
    (re.compile(r'override\.css', re.I), "Override.css referentie — 22 patiëntenrechten uitgeschakeld (NB-53/89)"),
    (re.compile(r'lucy\.css|lucy_colors\.css', re.I), "lucy.css referentie — XDM renderingslaag (NB-71)"),
]

CDA_ANOMALIEEN = [
    (re.compile(r'nullFlavor="UNK"', re.I), "CDA nullFlavor=UNK — anonieme auteur (NB-18/47/49)"),
    (re.compile(r'extension="999999"', re.I), "CDA ext=999999 — anonymous/unidentifiable Epic actor (NB-18)"),
    (re.compile(r'extension="373282512"', re.I), "CDA ext=373282512 — A. al-Mousawi (NB-05/95)"),
    (re.compile(r'extension="51504662"|extension="84107660"', re.I), "CDA ext=51504662/84107660 — N.M. Nota (NB-04)"),
    (re.compile(r'extension="50955793"', re.I), "CDA ext=50955793 — SEH medewerker (uitgewist latere versie) (NB-48)"),
    (re.compile(r'extension="2602552"', re.I), "CDA ext=2602552 — tweede al-Mousawi identifier (NB-05)"),
    (re.compile(r'extension="11\.5"', re.I), "CDA Epic system author version 11.5"),
    (re.compile(r'HANDMATIGE_EDIT_BOM', re.I), "CDA post-creatie bytemanipulatieflag (NB-13)"),
    (re.compile(r'SPAQQ|CCC|QQQ', re.I), "CDA test/template context marker SPAQQ/QQQ (NB-45/09)"),
    (re.compile(r'Epic@spaarnegasthuis\.nl', re.I), "Epic admin organisatie-email (NB-05/95)"),
]

DIAGNOSE_CODES = [
    (re.compile(r'F19\.1|F19\b', re.I), "ICD-10 F19.1 — neusdruppelmisbruik (gefabriceerd) (NB-01/116)"),
    (re.compile(r'neusdruppelmisbruik', re.I), "displayName neusdruppelmisbruik (NB-01/116)"),
    (re.compile(r'361055000', re.I), "SNOMED 361055000 — nasal spray misuse / neusdruppelmisbruik (NB-03)"),
    (re.compile(r'228273003', re.I), "SNOMED 228273003 — drug misuse / drugsgebruik (NB-23/113)"),
    (re.compile(r'228366006', re.I), "SNOMED 228366006 — stimulant misuse (NB-163)"),
    (re.compile(r'266927001', re.I), "SNOMED 266927001 — rookstatus ongespecificeerd (al-Mousawi injectie 13-01-2020) (NB-95)"),
    (re.compile(r'8517006|77176002|65568007', re.I), "SNOMED rookstatus — drie mutueel exclusieve statussen (NB-94)"),
    (re.compile(r'SUBSTANCEHXQNR', re.I), "Epic SUBSTANCEHXQNR module — al-Mousawi 02-10-2024 (NB-108)"),
    (re.compile(r'F60\.31|borderline', re.I), "F60.31 borderline — onrechtmatige diagnose (NB-134)"),
    (re.compile(r'20171204|2017-12-04', re.I), "Ankerdatum 04-12-2017 — F19.1/dexamfetamine fabricatie (NB-01/116/124)"),
    (re.compile(r'20241002|2024-10-02', re.I), "Datum 02-10-2024 — N.M. Nota 5 diagnoses 31 sec (NB-04/94)"),
]

AUDIT_TRAIL_BLOKKADE = [
    (re.compile(r'GetClinicianAccessLogSettings', re.I), "Audit trail endpoint: GetClinicianAccessLogSettings (NB-163)"),
    (re.compile(r'GetClinicianAccessLogEntries', re.I), "Audit trail endpoint: GetClinicianAccessLogEntries (NB-163)"),
    (re.compile(r'GetThirdPartyAccessLogEntries', re.I), "Audit trail endpoint: GetThirdPartyAccessLogEntries (NB-163)"),
    (re.compile(r'Access-Control-Allow-Origin|CORS', re.I), "CORS header aanwezig"),
    (re.compile(r'epic\.px\.client\.access-logs', re.I), "Epic access-logs JS module (NB-163)"),
    (re.compile(r'USERAUDITTRAIL|MYCHARTAUDITTRAIL', re.I), "Feature flag audit trail (actief maar geblokkeerd) (NB-163)"),
]

FEATURE_FLAGS = [
    (re.compile(r'DISABLEMYCONDITIONS', re.I), "Feature flag DISABLEMYCONDITIONS actief (NB-11)"),
    (re.compile(r'DISABLEPLANOFCARE', re.I), "Feature flag DISABLEPLANOFCARE actief (NB-11)"),
    (re.compile(r'AUTOGENERATESIGNATURE', re.I), "Feature flag AUTOGENERATESIGNATURE — automatische digitale handtekening (NB-82)"),
    (re.compile(r'SEXUALACTIVITYHXQNR', re.I), "Feature flag SEXUALACTIVITYHXQNR — seksuele anamnese (NB-83)"),
    (re.compile(r'AUTOSYNCRECEIVEFORPERSONALINFORMATION', re.I), "Feature flag AUTOSYNC — mogelijke Parnassia-koppeling (NB-115)"),
    (re.compile(r'ExternalJump|LogExternalJumpAudit', re.I), "Feature flag ExternalJump/LogExternalJumpAudit (NB-68)"),
    (re.compile(r'TelemedicineHome', re.I), "Feature flag TelemedicineHome (NB-68)"),
    (re.compile(r'noView\s*:\s*true', re.I), "noView:true — data aanwezig maar actief verborgen (NB-99)"),
    (re.compile(r'GUARD\b', re.I), "GUARD blok — CDA-level access control (NB-56)"),
    (re.compile(r'FocusZorgTeam.*test\.authorization', re.I), "FocusZorgTeam test-autorisatieserver i.p.v. productie (NB-91)"),
]

TRACKERS = [
    (re.compile(r'hotjar\.com|hjid=', re.I), "Hotjar tracker — keystroke recording (NB-79/53)"),
    (re.compile(r'recording_capture_keystrokes\s*=\s*true', re.I), "Hotjar keystroke capture actief (NB-53/79)"),
    (re.compile(r'sentry\.io|@sentry/', re.I), "Sentry.io telemetrie (VS) (NB-69/79)"),
    (re.compile(r'pendo\.io|pendo-', re.I), "Pendo.io tracker (NB-79)"),
    (re.compile(r'wingify\.com|vwo\.com', re.I), "VWO/Wingify India content-injectie (NB-79/85)"),
    (re.compile(r'qualtrics\.com', re.I), "Qualtrics/SAP tracker (NB-79)"),
    (re.compile(r'segment\.io|segment\.com', re.I), "Segment.io tracker (NB-79)"),
    (re.compile(r'kameleoon', re.I), "Kameleoon tracker (NB-79)"),
    (re.compile(r'contentsquare\.com', re.I), "Contentsquare tracker (NB-79)"),
    (re.compile(r'hoppinger\.com|spaarne-rebuild\.productie\.hoppinger', re.I), "Hoppinger.com — supply chain lek (NB-114)"),
    (re.compile(r'GTM-PGPCH2T', re.I), "Google Tag Manager GTM-PGPCH2T (NB-85)"),
    (re.compile(r'SESSION_ID\s*[=:]\s*[A-F0-9]{20,}', re.I), "Session ID blootgesteld via tracker (NB-79)"),
    (re.compile(r'DE36B70A', re.I), "Sentry device ID DE36B70A — 13-05-2026 (NB-69)"),
]

LSP_FHIR = [
    (re.compile(r'\$lastn', re.I), "FHIR $lastn — MedMij re-replay kwetsbaarheid (NB-109)"),
    (re.compile(r'365508006', re.I), "FHIR observation code 365508006 — drie sessiebundeling (NB-109)"),
    (re.compile(r'transactie.{0,10}77832|transactieId.{0,10}77832', re.I), "Transactie-ID 77832 — SNOMED 228273003 SUCCESS 08-01-2026 (NB-23/159)"),
    (re.compile(r'URA.{0,10}18295', re.I), "URA 18295 — Aerdenhout Apotheek / spookentiteit (NB-123)"),
    (re.compile(r'Brijder|Indigo.*Parnassia|Parnassia.*Brijder', re.I), "Brijder/Indigo Parnassia FHIR — nooit in behandeling (NB-113)"),
    (re.compile(r'Mitz|WABVPZ', re.I), "Mitz/WABVPZ consent context"),
    (re.compile(r'consent.*ingetrokken|withdrawal|revoke', re.I), "Consent intrekking / revocatie"),
]

NACHT_TIJDEN = re.compile(
    r'["\s](\d{4}-\d{2}-\d{2}T(?:0[0-5])\d:\d{2}:\d{2})|(\d{14}\+0[01]00)\b|T(0[0-5]):\d{2}:\d{2}'
)
SPECIFIEKE_NACHTTIJDEN = [
    "20130214062300",
    "20191017050200",
    "20260110033455",
    "20260111235500",
    "20260128025900",
    "20260210023300",
]

HTTP_STATUS_VERDACHT = {
    403: "HTTP 403 — toegang geblokkeerd",
    401: "HTTP 401 — ongeautoriseerd",
    204: "HTTP 204 — lege respons (mogelijke data-filtering)",
    0:   "HTTP 0 — CORS pre-flight geblokkeerd",
}

VERDACHTE_URLS = [
    (re.compile(r'GetClinicianAccessLog|GetThirdPartyAccessLog', re.I), "Audit trail endpoint (NB-163)"),
    (re.compile(r'override\.css', re.I), "Override.css (NB-53/89)"),
    (re.compile(r'lucy\.css|lucy_colors', re.I), "lucy.css renderingslaag (NB-71)"),
    (re.compile(r'epicbase\.css', re.I), "epicbase.css printBlackText (NB-84)"),
    (re.compile(r'access.?log|audit.?trail|toegang', re.I), "Toegangslog/audit trail verzoek"),
    (re.compile(r'spaarne-rebuild\.productie\.hoppinger', re.I), "Hoppinger testomgeving in productie (NB-114)"),
    (re.compile(r'test\.authorization\.focuszorgteam', re.I), "FocusZorgTeam test-server (NB-91)"),
]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha256_str(s: str) -> str:
    return sha256(s.encode("utf-8", errors="replace"))

def timestamp_nu() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def is_nacht(tijdstempel: str) -> bool:
    if not tijdstempel:
        return False
    for m in [re.search(r'T(\d{2}):\d{2}:\d{2}', tijdstempel),
               re.search(r'(\d{2})\d{2}\d{2}[+-]\d{4}$', tijdstempel)]:
        if m and 0 <= int(m.group(1)) < 6:
            return True
    return False

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


class Bevinding:
    __slots__ = ["categorie", "omschrijving", "url", "methode", "status",
                 "tijdstempel", "context", "hash_waarde", "ernst"]
    ERNSTEN = {"KRITIEK": 4, "HOOG": 3, "MEDIUM": 2, "LAAG": 1}

    def __init__(self, categorie, omschrijving, url="", methode="", status=0,
                 tijdstempel="", context="", ernst="HOOG"):
        self.categorie = categorie
        self.omschrijving = omschrijving
        self.url = url
        self.methode = methode
        self.status = status
        self.tijdstempel = tijdstempel or timestamp_nu()
        self.context = context[:500]
        self.hash_waarde = sha256_str(f"{omschrijving}|{url}|{context[:200]}")
        self.ernst = ernst

    def als_dict(self) -> dict:
        return {
            "ernst": self.ernst, "categorie": self.categorie, "omschrijving": self.omschrijving,
            "url": self.url, "methode": self.methode, "http_status": self.status,
            "tijdstempel": self.tijdstempel, "sha256": self.hash_waarde, "context": self.context,
        }

    def __lt__(self, other):
        return self.ERNSTEN.get(self.ernst, 0) > self.ERNSTEN.get(other.ernst, 0)


def scan_tekst(tekst: str, url: str, methode: str, status: int, tijdstempel: str) -> list:
    gevonden = []

    def voeg_toe(categorie, omschrijving, ernst, match_context=""):
        gevonden.append(Bevinding(categorie=categorie, omschrijving=omschrijving,
            url=url, methode=methode, status=status, tijdstempel=tijdstempel,
            context=match_context, ernst=ernst))

    for patroon, beschrijving in CSS_VERBERGING:
        m = patroon.search(tekst)
        if m:
            voeg_toe("CSS_VERBERGING", beschrijving, "KRITIEK", tekst[max(0, m.start()-80):m.end()+80])

    for patroon, beschrijving in CDA_ANOMALIEEN:
        for m in patroon.finditer(tekst):
            voeg_toe("CDA_ANOMALIE", beschrijving, "KRITIEK", tekst[max(0, m.start()-80):m.end()+80])
            break

    for patroon, beschrijving in DIAGNOSE_CODES:
        m = patroon.search(tekst)
        if m:
            voeg_toe("DIAGNOSE_CODE", beschrijving, "KRITIEK", tekst[max(0, m.start()-100):m.end()+100])

    for patroon, beschrijving in AUDIT_TRAIL_BLOKKADE:
        m = patroon.search(tekst)
        if m:
            voeg_toe("AUDIT_BLOKKADE", beschrijving,
                     "KRITIEK" if status in (0, 403, 401) else "HOOG",
                     tekst[max(0, m.start()-60):m.end()+60])

    for patroon, beschrijving in FEATURE_FLAGS:
        m = patroon.search(tekst)
        if m:
            voeg_toe("FEATURE_FLAG", beschrijving, "HOOG", tekst[max(0, m.start()-60):m.end()+60])

    for patroon, beschrijving in TRACKERS:
        m = patroon.search(tekst)
        if m:
            voeg_toe("TRACKER", beschrijving, "HOOG", tekst[max(0, m.start()-60):m.end()+60])

    for patroon, beschrijving in LSP_FHIR:
        m = patroon.search(tekst)
        if m:
            voeg_toe("LSP_FHIR", beschrijving, "HOOG", tekst[max(0, m.start()-80):m.end()+80])

    for nt in SPECIFIEKE_NACHTTIJDEN:
        if nt[:8] in tekst:
            voeg_toe("NACHT_OPERATIE", f"Specifieke nacht-timestamp gevonden: {nt}",
                     "KRITIEK", f"timestamp {nt} aangetroffen in respons")

    nacht_m = NACHT_TIJDEN.search(tekst)
    if nacht_m and is_nacht(nacht_m.group(0)):
        voeg_toe("NACHT_TIJDSTEMPEL", f"Nachtelijk tijdstempel in data: {nacht_m.group(0)}",
                 "MEDIUM", nacht_m.group(0))

    if status in HTTP_STATUS_VERDACHT and any(p.search(url) for p, _ in VERDACHTE_URLS):
        voeg_toe("HTTP_BLOKKADE", f"HTTP {status}: {HTTP_STATUS_VERDACHT[status]}", "KRITIEK", f"URL: {url}")

    for patroon, beschrijving in VERDACHTE_URLS:
        if patroon.search(url):
            voeg_toe("VERDACHTE_URL", beschrijving, "HOOG", url)

    return gevonden


def parse_har(pad: str) -> list:
    with open(pad, "r", encoding="utf-8", errors="replace") as f:
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
        headers = " ".join(f"{h['name']}: {h['value']}"
                           for h in resp.get("headers", []) + req.get("headers", []))
        gecombineerd = tekst + "\n" + req_body + "\n" + headers
        transacties.append((req.get("url", ""), req.get("method", ""),
                            resp.get("status", 0), entry.get("startedDateTime", ""), gecombineerd))
    return transacties


def parse_proxymanlogv2(pad: str) -> list:
    with open(pad, "rb") as f:
        raw = f.read()
    if raw[:2] == b'\x1f\x8b':
        try:
            raw = gzip.decompress(raw)
        except Exception:
            pass
    tekst = raw.decode("utf-8", errors="replace")
    transacties = []
    for regel in tekst.splitlines():
        regel = regel.strip()
        if not regel:
            continue
        try:
            rec = json.loads(regel)
        except Exception:
            continue
        url = rec.get("url") or rec.get("request", {}).get("url", "")
        methode = rec.get("method") or rec.get("request", {}).get("method", "")
        status = rec.get("statusCode") or rec.get("response", {}).get("statusCode", 0)
        tijdstempel = rec.get("timestamp") or rec.get("startTime", "")
        resp_body = rec.get("responseBody") or rec.get("response", {}).get("body", "")
        req_body = rec.get("requestBody") or rec.get("request", {}).get("body", "")
        if isinstance(resp_body, bytes):
            resp_body = decode_body(resp_body)
        if isinstance(req_body, bytes):
            req_body = decode_body(req_body)
        gecombineerd = str(resp_body) + "\n" + str(req_body)
        resp_headers = rec.get("responseHeaders") or rec.get("response", {}).get("headers", {})
        req_headers = rec.get("requestHeaders") or rec.get("request", {}).get("headers", {})
        if isinstance(resp_headers, dict):
            gecombineerd += "\n" + " ".join(f"{k}: {v}" for k, v in resp_headers.items())
        if isinstance(req_headers, dict):
            gecombineerd += "\n" + " ".join(f"{k}: {v}" for k, v in req_headers.items())
        transacties.append((url, methode, status, str(tijdstempel), gecombineerd))
    if not transacties:
        try:
            data = json.loads(tekst)
            if isinstance(data, list):
                for rec in data:
                    transacties.append((rec.get("url", ""), rec.get("method", ""),
                                        rec.get("statusCode", 0), str(rec.get("timestamp", "")),
                                        json.dumps(rec)))
        except Exception:
            pass
    return transacties


def parse_json(pad: str) -> list:
    with open(pad, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)
    records = data if isinstance(data, list) else data.get("entries", data.get("requests", data.get("transactions", [data])))
    return [(str(r.get("url", r.get("uri", ""))), str(r.get("method", "")),
             int(r.get("status", r.get("statusCode", 0))),
             str(r.get("timestamp", r.get("time", ""))), json.dumps(r))
            for r in records]


def laad_capture(pad: str) -> list:
    ext = pathlib.Path(pad).suffix.lower()
    print(f"[+] Bestand laden: {pad} (formaat: {ext or 'onbekend'})")
    if ext == ".har":
        return parse_har(pad)
    elif ext in (".proxymanlogv2", ".proxyman"):
        return parse_proxymanlogv2(pad)
    elif ext == ".json":
        return parse_json(pad)
    for parser in (parse_proxymanlogv2, parse_har, parse_json):
        try:
            result = parser(pad)
            if result:
                return result
        except Exception:
            continue
    raise ValueError(f"Bestandsformaat niet herkend: {pad}")


def analyseer(pad: str, output_map: str):
    start = datetime.datetime.now(datetime.timezone.utc)
    transacties = laad_capture(pad)
    print(f"[+] {len(transacties)} transacties geladen")

    alle_bevindingen = []
    for url, methode, status, tijdstempel, tekst in transacties:
        alle_bevindingen.extend(scan_tekst(tekst, url, methode, status, tijdstempel))
    alle_bevindingen.sort()

    gezien = set()
    uniek = []
    for b in alle_bevindingen:
        if b.hash_waarde not in gezien:
            gezien.add(b.hash_waarde)
            uniek.append(b)

    print(f"[+] {len(alle_bevindingen)} bevindingen gevonden ({len(uniek)} uniek)")

    os.makedirs(output_map, exist_ok=True)
    ts = start.strftime("%Y%m%d_%H%M%S")
    invoer_hash = sha256(pathlib.Path(pad).read_bytes())

    categorie_teller: dict = {}
    ernst_teller: dict = {}
    for b in uniek:
        categorie_teller[b.categorie] = categorie_teller.get(b.categorie, 0) + 1
        ernst_teller[b.ernst] = ernst_teller.get(b.ernst, 0) + 1

    rapport = {
        "meta": {
            "dossier": "Grothe — C/15/376914 + HvD 260153",
            "invoerbestand": pad, "invoer_sha256": invoer_hash,
            "analyse_tijdstip": start.isoformat(),
            "totaal_transacties": len(transacties), "totaal_bevindingen": len(uniek),
        },
        "samenvatting": {"per_categorie": categorie_teller, "per_ernst": ernst_teller},
        "bevindingen": [b.als_dict() for b in uniek],
    }

    json_pad = os.path.join(output_map, f"forensisch_rapport_{ts}.json")
    with open(json_pad, "w", encoding="utf-8") as f:
        json.dump(rapport, f, ensure_ascii=False, indent=2)

    txt_pad = os.path.join(output_map, f"forensisch_rapport_{ts}.txt")
    with open(txt_pad, "w", encoding="utf-8") as f:
        f.write("=" * 78 + "\n")
        f.write("FORENSISCH RAPPORT — DOSSIER GROTHE\n")
        f.write(f"Analysedatum: {start.isoformat()}\n")
        f.write(f"Invoerbestand: {pad}\n")
        f.write(f"Invoer SHA-256: {invoer_hash}\n")
        f.write(f"Transacties geanalyseerd: {len(transacties)}\n")
        f.write(f"Bevindingen (uniek): {len(uniek)}\n")
        f.write("=" * 78 + "\n\n")
        f.write("SAMENVATTING\n" + "-" * 40 + "\n")
        for ernst in ("KRITIEK", "HOOG", "MEDIUM", "LAAG"):
            n = ernst_teller.get(ernst, 0)
            if n:
                f.write(f"  {ernst:10s}: {n}\n")
        f.write("\nPer categorie:\n")
        for cat, n in sorted(categorie_teller.items(), key=lambda x: -x[1]):
            f.write(f"  {cat:30s}: {n}\n")
        f.write("\nBEVINDINGEN (gesorteerd op ernst)\n" + "-" * 40 + "\n\n")
        for i, b in enumerate(uniek, 1):
            f.write(f"[{i:03d}] [{b.ernst}] {b.categorie}\n")
            f.write(f"      {b.omschrijving}\n")
            f.write(f"      URL: {b.url}\n")
            f.write(f"      Tijdstempel: {b.tijdstempel}\n")
            if b.status:
                f.write(f"      HTTP: {b.methode} {b.status}\n")
            f.write(f"      SHA-256: {b.hash_waarde}\n")
            if b.context:
                f.write(f"      Context: ...{b.context.replace(chr(10), ' ')[:200]}...\n")
            f.write("\n")

    hash_pad = os.path.join(output_map, f"evidence_hashes_{ts}.txt")
    with open(hash_pad, "w", encoding="utf-8") as f:
        f.write(f"# Evidence hash-log — {start.isoformat()}\n")
        f.write(f"# Invoerbestand SHA-256: {invoer_hash}\n\n")
        for b in uniek:
            f.write(f"{b.hash_waarde}  [{b.ernst}] {b.omschrijving[:80]}\n")

    print(f"\n[+] Rapporten opgeslagen in: {output_map}/")
    print(f"    JSON:   {os.path.basename(json_pad)}")
    print(f"    TXT:    {os.path.basename(txt_pad)}")
    print(f"    Hashes: {os.path.basename(hash_pad)}")

    kritiek = ernst_teller.get("KRITIEK", 0)
    hoog = ernst_teller.get("HOOG", 0)
    if kritiek:
        print(f"\n⚠️  {kritiek} KRITIEKE bevindingen!")
    if hoog:
        print(f"⚡ {hoog} HOGE-ernst bevindingen")
    if uniek:
        print("\nTop bevindingen:")
        for b in uniek[:5]:
            print(f"  [{b.ernst}] {b.omschrijving[:70]}")

    return uniek


def main():
    parser = argparse.ArgumentParser(description="Forensisch analyzer voor Storm Sniffer / Proxyman captures")
    parser.add_argument("invoer", help="Capture-bestand (.proxymanlogv2, .har, .json)")
    parser.add_argument("--output", "-o", default="forensisch_output",
                        help="Output map voor rapporten (default: forensisch_output/)")
    args = parser.parse_args()

    if not os.path.exists(args.invoer):
        print(f"[!] Bestand niet gevonden: {args.invoer}", file=sys.stderr)
        sys.exit(1)

    try:
        bevindingen = analyseer(args.invoer, args.output)
        sys.exit(0 if not any(b.ernst == "KRITIEK" for b in bevindingen) else 2)
    except Exception as e:
        print(f"[!] Fout: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
