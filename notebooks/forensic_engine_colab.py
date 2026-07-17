# -*- coding: utf-8 -*-
"""
================================================================================
 FORENSISCHE ENGINE — GECONSOLIDEERD + UITGEBREID (Google Colab)
 Dossier Grothe — Rechtbank Noord-Holland C/15/376914
================================================================================
Dit bestand vervangt ALLE losse Colab-cellen (engines V7 t/m V17, de diverse
report-/dashboard-/timestomping-cellen en de dubbele integrity-vault-definities)
en breidt ze uit met de domeinspecifieke detectie uit de forensische skills.
Eén engine, één rapportgenerator, één Drive-helper, één timestomping-analyse.

Behouden basistechnieken (uit de oude cellen):
  entropie + entropie-eilanden, XOR-bruteforce, recursieve codec-ketens
  (base64/32/85, hex, gzip/zlib/deflate/bzip2/lzma), zero-width/bidi/homoglyphs/
  Unicode-tags-steganografie, ZIP-inversie + ZIP-residu, PDF-lagen (incrementele
  update, SMask, onzichtbare/witte/mini/buiten-vlak tekst, OCG, hidden annotaties),
  Office (w:vanish, tracked changes, rsid, verborgen sheets/rijen, wees-strings),
  PNG-chunks, staartdata, UUIDv1-MAC+tijd, BSN 11-proef, en de
  "gelijke lengte / andere hash"-signatuur (NB-224).

ONTDEKKINGSLAAG (anti-tunnelvisie) — vindt zelf, sluit niet uit:
  De engine leunt NIET op een vaste lijst van "wat verdacht is". Ze enumereert
  ALLES (elke OID-autoriteit, codeSystem, identifier, namespace, tijdzone,
  UUIDv1-MAC), voedt een corpus-brede index, en meldt AFWIJKINGEN VAN DE NORM:
    - onbekende OID-autoriteit / onbekend codeSystem (nieuwe bron valt op)
    - placeholder-identifiers (herhaald cijfer, bv. 000000/999999) generiek
    - singleton-actoren (numeriek ID dat corpus-breed één keer voorkomt)
    - zeldzame coderingen (frequentie 1), tijdzone-spreiding, meerdere MAC-nodes,
      setId-rotatie over documenten
    - niets stil weggeslikt: onbekende bestandstypen worden expliciet gemeld
  Zo komen ONBEKENDE bevindingen boven zonder ze vooraf te definiëren.

Bekende-signatuur-laag (aanvullende bevestiging, niet leidend):
  NL zorg-identifiers met OID-context, referentie-actoren en -codes, CDA-verdieping
  (setId/versionNumber-rotatie, tijdzone-anomalie, parentDocument), FHIR, IHE XDM,
  MedMij-portabiliteitsrapport, HAR/Proxyman + sabotagemarkers, Apple .ips/.crash/
  .diag, magic-byte-mismatch, Office-documentmetadata, recursieve archief-extractie
  + matroesjka-reparatie. Bevindingen dragen bewijswaarde (H/M/L) en juridische
  grondslag (AVG, WGBO 7:454, WABVPZ, NEN 7510, HL7 CDA R2, Sr).

GEBRUIK IN COLAB
----------------
Cel 1:  !pip install -q pymupdf pandas openpyxl fpdf2
Cel 2:  plak de inhoud van dit bestand (of: %run forensic_engine_colab.py)
Cel 3:  df = run()                      # mount Drive, kies map, scan, rapport
        # of los:  engine = ForensicEngineV18(); engine.scan_map("/content/invoer")
Cel 4 (optioneel):  dashboard()         # interactieve HTML-UI
Cel 5 (optioneel):  timestomping_analyse(engine)

Draait ook buiten Colab (Drive-mount en upload worden dan overgeslagen).
"""

import os
import re
import io
import json
import math
import gzip
import zlib
import lzma
import bz2
import base64
import struct
import hashlib
import pathlib
import unicodedata
import uuid as _uuid
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timedelta

# ── Optionele libs met nette fallback ────────────────────────────────────────
try:
    import pandas as pd
    _HAS_PD = True
except Exception:
    _HAS_PD = False

try:
    import fitz  # PyMuPDF
    _HAS_FITZ = True
except Exception:
    _HAS_FITZ = False

_IN_COLAB = os.path.exists("/content")
TS = datetime.now().strftime("%Y%m%d_%H%M%S")


# ════════════════════════════════════════════════════════════════════════════
#  1. DRIVE-HELPER  (vervangt alle losse mount-/mapkeuze-cellen)
# ════════════════════════════════════════════════════════════════════════════
def mount_drive():
    """Mount Google Drive (idempotent). Buiten Colab: no-op."""
    if not _IN_COLAB:
        return None
    try:
        from google.colab import drive
        if not os.path.exists("/content/drive/MyDrive"):
            drive.mount("/content/drive")
        return "/content/drive/MyDrive"
    except Exception as e:
        print(f"[!] Drive-mount overgeslagen: {e}")
        return None


def kies_map(basismap="/content/drive/MyDrive"):
    """Toon mappen en laat de gebruiker er één kiezen. [0] = root."""
    if not os.path.isdir(basismap):
        print(f"[!] {basismap} bestaat niet.")
        return None
    mappen = sorted(m for m in os.listdir(basismap)
                    if os.path.isdir(os.path.join(basismap, m)))
    print(f"[0] {basismap} (root)")
    for i, m in enumerate(mappen, 1):
        print(f"[{i}] {m}")
    keuze = input("\nSelecteer mapnummer: ").strip()
    if keuze in ("", "0"):
        return basismap
    try:
        return os.path.join(basismap, mappen[int(keuze) - 1])
    except Exception:
        print("[!] Ongeldige keuze; root gebruikt.")
        return basismap


def mount_en_kies_map():
    base = mount_drive() or "/content"
    return kies_map(base)


# ════════════════════════════════════════════════════════════════════════════
#  2. INTEGRITEITSKLUIS  (vervangt alle ForensicIntegrityVault*-varianten)
#     Persistente SHA-256-database → detecteert stille wijzigingen over tijd.
# ════════════════════════════════════════════════════════════════════════════
class IntegriteitsKluis:
    def __init__(self, kluis_pad):
        self.kluis_pad = kluis_pad
        os.makedirs(os.path.dirname(kluis_pad) or ".", exist_ok=True)
        self.db = self._laad()

    def _laad(self):
        if os.path.exists(self.kluis_pad):
            try:
                with open(self.kluis_pad, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _bewaar(self):
        with open(self.kluis_pad, "w", encoding="utf-8") as f:
            json.dump(self.db, f, indent=1, ensure_ascii=False)

    def audit(self, pad, sha, grootte):
        """Geeft ('NIEUW'|'ONGEWIJZIGD'|'GEWIJZIGD', vorige_entry_or_None)."""
        sleutel = os.path.abspath(pad)
        entry = {"sha256": sha, "grootte": grootte,
                 "mtime": os.path.getmtime(pad) if os.path.exists(pad) else 0,
                 "gezien": datetime.now().isoformat()}
        if sleutel in self.db:
            hist = self.db[sleutel]
            if hist[-1]["sha256"] != sha:
                vorige = hist[-1]
                hist.append(entry)
                self._bewaar()
                return "GEWIJZIGD", vorige
            return "ONGEWIJZIGD", hist[-1]
        self.db[sleutel] = [entry]
        self._bewaar()
        return "NIEUW", None


# ════════════════════════════════════════════════════════════════════════════
#  3. DE ENGINE  (vervangt V7..V17 + ForensicEngine/DeepScanner/ForensischeEngine)
# ════════════════════════════════════════════════════════════════════════════

# — Unicode-tabellen —
_ONZICHTBAAR = {0x200b: "ZERO WIDTH SPACE", 0x200c: "ZW NON-JOINER",
                0x200d: "ZW JOINER", 0x2060: "WORD JOINER", 0xfeff: "BOM",
                0x00ad: "SOFT HYPHEN", 0x180e: "MONGOLIAN VOWEL SEP",
                0x3164: "HANGUL FILLER"}
_BIDI = {0x200e: "LRM", 0x200f: "RLM", 0x202a: "LRE", 0x202b: "RLE",
         0x202c: "PDF", 0x202d: "LRO", 0x202e: "RLO", 0x2066: "LRI",
         0x2067: "RLI", 0x2069: "PDI"}
_HOMO = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
         "і": "i", "ј": "j", "ѕ": "s", "А": "A", "В": "B", "Е": "E", "К": "K",
         "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
         "Ѕ": "S", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I",
         "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y",
         "Χ": "X", "ο": "o", "α": "a"}
_SCRIPT_RANGES = [((0x41, 0x24f), "Latijn"), ((0x370, 0x3ff), "Grieks"),
                  ((0x400, 0x4ff), "Cyrillisch"), ((0x590, 0x5ff), "Hebreeuws"),
                  ((0x600, 0x6ff), "Arabisch"), ((0x4e00, 0x9fff), "Han"),
                  ((0xac00, 0xd7af), "Hangul")]

# — Standaard PNG-chunks (alles daarbuiten is verdacht) —
_PNG_STD = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"cHRM", b"gAMA",
            b"iCCP", b"sBIT", b"sRGB", b"bKGD", b"hIST", b"pHYs", b"sPLT",
            b"tIME", b"acTL", b"fcTL", b"fdAT", b"eXIf", b"cICP"}

# — Medische / obfuscatie-patronen (samengevoegd uit alle oude engines) —
_MED = {
    "BSN": r"\b[0-9]{8,9}\b",
    "ICD10": r"\b[A-Z][0-9][0-9](\.[0-9]{1,2})?\b",
    "HL7_SEGMENT": r"(?m)^(MSH|PID|OBR|OBX|ORC|DG1|AL1)\|",
    "ZORG_ID": r"\b(UZI|AGB|BIG)-[0-9]{5,10}\b",
}
_POWERSHELL = re.compile(
    r"(?i)(Invoke-Expression|IEX|EncodedCommand|WindowStyle\s+Hidden|"
    r"DownloadString|Net\.WebClient|powershell\.exe)")

# — NL zorg-identifier OID-roots (bron: skill identifier-systems) —
_OID_SYSTEM = {
    "2.16.840.1.113883.2.4.6.1": "VEKTIS AGB",
    "2.16.528.1.1007.5.1": "BIG",
    "2.16.528.1.1007.3.1": "UZI",
    "2.16.528.1.1007.3.3": "URA",
    "2.16.840.1.113883.6.96": "SNOMED CT",
    "2.16.840.1.113883.6.1": "LOINC",
    "2.16.840.1.113883.2.4.6.3": "BSN (NL persoon)",
    "1.2.840.114350.1.1": "Epic (versie)",
    "1.2.840.114350.1.13.201.2.7.2.836982": "Epic Practitioner-ID",
    "1.2.840.114350.1.13.201.2.7.1.1": "Epic setId-root",
}
# verdachte/ongeïdentificeerde actoren uit het dossier
_VERDACHTE_ACTOREN = {
    "999999": "anoniem — geen BIG/VEKTIS (WGBO 7:454)",
    "470154242": "ongeïdentificeerd — Care Team-wijziging",
    "373282512": "geen BIG/VEKTIS — invoer SNOMED 361055000",
}
# forensisch relevante SNOMED-codes (stigmatiserend / gevoelig)
_SNOMED_FORENSISCH = {
    "361055000": "drugsgebruik (stigmatiserende codering)",
    "41021000146105": "neusdruppelmisbruik",
    "73425007": "vermoeidheid",
}
# forensisch relevante LOINC-secties (verwijdering = suppressie-indicator)
_LOINC_FORENSISCH = {
    "10160-0": "Medicatie (verdwijning = suppressie, WGBO 7:454 lid 3)",
    "11450-4": "Probleemlijst",
    "29762-2": "Sociale anamnese",
    "48768-6": "Betalers",
    "8716-3": "Vitale functies",
}
# dossier-specifieke sabotage-/injectiemarkers (portaal/netwerk)
_SABOTAGE_MARKERS = [
    "ajaxrequestinterceptor", "__startfilteringerrors", "polyfillcustomevent",
    "epic.eci", "spaarne-prd", "hideprovidername", "override.css",
    "dom_verwijderd", "coc_onvolledig", "57.150.81.65", "za=psyq@medmij",
    "ng-validate.js",
]
# XML/HL7-namespaces
_NS_CDA = "urn:hl7-org:v3"
_NS_XDM = "urn:oasis:names:tc:ebxml-regrep:xsd:lcm:3.0"
_NS_MEDMIJ = "afsprakenstelsel.medmij.nl/portabiliteitsrapport"

# — ONTDEKKINGSLAAG: bekende OID-/codeSystem-PREFIXEN (alles daarbuiten = onbekende
#   autoriteit die wordt gemeld, NIET uitgesloten). Geen limitatieve signatuurlijst. —
_BEKENDE_OID_PREFIXEN = (
    "2.16.840.1.113883",   # HL7 internationaal
    "2.16.528",            # Nederland (BIG/UZI/URA/VEKTIS)
    "1.2.840.114350",      # Epic
    "1.3.6.1.4.1.19376",   # IHE
    "1.2.276",             # Duitsland
)
_BEKENDE_CODESYSTEMEN = {
    "2.16.840.1.113883.6.96": "SNOMED CT",
    "2.16.840.1.113883.6.1": "LOINC",
    "2.16.840.1.113883.6.3": "ICD-10",
    "2.16.840.1.113883.6.73": "ATC",
    "2.16.840.1.113883.6.88": "RxNorm",
    "2.16.840.1.113883.2.4.4.1.900.2": "G-Standaard",
}


def _script_van(c):
    o = ord(c)
    for (a, b), naam in _SCRIPT_RANGES:
        if a <= o <= b:
            return naam
    return ""


def _entropie(data):
    if not data:
        return 0.0
    teller = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in teller.values())


def _plausibel(d):
    if len(d) < 12:
        return False
    if any(d[:8].startswith(s) for s in (b"%PDF", b"PK\x03\x04", b"\x1f\x8b",
                                          b"\x89PNG", b"{", b"[", b"<?xml", b"BZh")):
        return True
    s = d[:512]
    return sum(1 for x in s if 32 <= x < 127 or x in (9, 10, 13)) / max(1, len(s)) > 0.85


def _valide_bsn(bsn):
    """11-proef. Geeft (bool, uitleg)."""
    b = str(bsn).strip()
    if not b.isdigit() or not (8 <= len(b) <= 9):
        return False, "ongeldig formaat"
    b = b.zfill(9)
    som = sum(int(b[i]) * (9 - i) for i in range(8)) - int(b[8])
    return (som % 11 == 0), ("valide" if som % 11 == 0 else "faalt 11-proef")


class ForensicEngineV18:
    """Geconsolideerde forensische engine. Verzamelt bevindingen met bewijswaarde
    (H/M/L) en juridische grondslag."""

    def __init__(self, kluis_pad=None):
        self.bevindingen = []          # list[dict]
        self.inventaris = []           # list[dict] (per bestand)
        self._gezien = set()           # dedup-sleutels
        self.kluis = IntegriteitsKluis(kluis_pad) if kluis_pad else None
        # corpus-brede accumulatoren voor de ONTDEKKINGSLAAG (anomalie i.p.v. signatuur)
        self.corpus = {
            "oid_roots": Counter(),          # elke gebruikte OID-autoriteit
            "code_systems": Counter(),       # elk codeSystem
            "codes": defaultdict(Counter),   # codeSystem -> Counter(code)
            "actoren": defaultdict(set),     # numeriek ID -> set(bestanden)
            "namespaces": Counter(),         # elke XML-namespace
            "tijdzones": Counter(),          # elke tijdzone-offset
            "macs": defaultdict(set),        # UUIDv1-node -> set(bestanden)
            "setids": defaultdict(set),      # setId -> set(versionNumber)
        }

    # — registratie (met dedup op techniek+pad+detail) —
    def vind(self, techniek, bron, detail, waarde="M", grond="", universeel=False):
        sleutel = (techniek, str(bron), detail)
        if sleutel in self._gezien:
            return
        self._gezien.add(sleutel)
        self.bevindingen.append({
            "techniek": techniek,
            "bestand": pathlib.Path(bron).name,
            "pad": str(bron),
            "detail": detail,
            "bewijswaarde": waarde,
            "juridisch": grond,
            "universeel": universeel,
            "tijd": datetime.now().strftime("%H:%M:%S"),
        })

    # — helpers —
    @staticmethod
    def _hashes(pad):
        a, b, n = hashlib.sha256(), hashlib.md5(), 0
        with open(pad, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                a.update(chunk); b.update(chunk); n += len(chunk)
        return a.hexdigest(), b.hexdigest(), n

    @staticmethod
    def _soort(pad, raw):
        for sig, t in ((b"%PDF", "pdf"), (b"PK\x03\x04", "zip"),
                       (b"\x1f\x8b", "gz"), (b"\x89PNG", "png"),
                       (b"\xff\xd8\xff", "jpg"), (b"<?xml", "xml"),
                       (b"BZh", "bz2"), (b"GIF8", "gif")):
            if raw.startswith(sig):
                if t == "zip":
                    try:
                        namen = zipfile.ZipFile(io.BytesIO(raw)).namelist()
                        for pre, x in (("word/", "docx"), ("xl/", "xlsx"),
                                       ("ppt/", "pptx")):
                            if any(q.startswith(pre) for q in namen):
                                return x
                    except Exception:
                        pass
                return t
        s = pathlib.Path(pad).suffix.lower().lstrip(".")
        return {"htm": "html", "jpeg": "jpg", "har": "json",
                "cda": "xml", "xsl": "xml"}.get(s, s or "bin")

    # ── recursieve codec-ketens (base64/32/85, hex, gzip/zlib/deflate/bz2/lzma) ──
    def _pel(self, raw, bron, keten="", diep=0):
        if diep > 5 or not raw or len(raw) > 50_000_000:
            return
        pogingen = [
            ("base64", lambda r: base64.b64decode(r, validate=True)
             if re.fullmatch(rb"[A-Za-z0-9+/]{24,}={0,2}", r) and len(r) % 4 == 0 else None),
            ("base32", lambda r: base64.b32decode(r)
             if re.fullmatch(rb"[A-Z2-7]{24,}=*", r) and len(r) % 8 == 0 else None),
            ("base85", lambda r: base64.b85decode(r)),
            ("hex", lambda r: bytes.fromhex(r.decode("ascii"))
             if re.fullmatch(rb"[0-9a-fA-F]{32,}", r) and len(r) % 2 == 0 else None),
            ("gzip", lambda r: gzip.decompress(r) if r[:2] == b"\x1f\x8b" else None),
            ("zlib", lambda r: zlib.decompress(r)),
            ("deflate", lambda r: zlib.decompress(r, -15)),
            ("bzip2", lambda r: bz2.decompress(r) if r[:3] == b"BZh" else None),
            ("lzma", lambda r: lzma.decompress(r) if r[:6] == b"\xfd7zXZ\x00" else None),
        ]
        for naam, fn in pogingen:
            try:
                d = fn(re.sub(rb"\s", b"", raw))
            except Exception:
                d = None
            if not d or not _plausibel(d):
                continue
            k = f"{keten}->{naam}" if keten else naam
            self.vind(f"codec: {k}", bron,
                      f"{len(raw)} -> {len(d)} bytes. Inhoud: {d[:110]!r}",
                      "H" if diep else "M", "AVG art. 12 lid 1 leesbare vorm")
            self._pel(d, bron, k, diep + 1)

    def _blokken(self, raw, bron):
        gezien, n = set(), 0
        for pat, naam in ((rb"[A-Za-z0-9+/]{40,}={0,2}", "base64"),
                          (rb"[A-Z2-7]{40,}=*", "base32"),
                          (rb"[0-9a-fA-F]{48,}", "hex")):
            for m in re.finditer(pat, raw):
                b = m.group(0)
                h = hashlib.sha256(b).hexdigest()
                if h in gezien:
                    continue
                gezien.add(h)
                voor = len(self.bevindingen)
                self._pel(b, bron, f"blok/{naam}")
                if len(self.bevindingen) > voor:
                    n += 1
                if n >= 25:
                    return

    # ── XOR-bruteforce (uit V7/V8) ──
    def _xor(self, raw, bron):
        if len(raw) < 20:
            return
        head = raw[:200]
        # XOR-obfuscatie verbergt payload in BINAIRE data; leesbare tekst overslaan
        if _plausibel(head):
            return
        low0 = head.lower()
        if any(k in low0 for k in (b"http", b"cmd", b"powershell")):
            return  # keyword staat al leesbaar in het bestand → niet verborgen
        for key in range(1, 256):
            if key == 0x20:
                continue  # 0x20 is puur hoofdletter-omkering → vals-positief op tekst
            dec = bytes(b ^ key for b in head[:120])
            low = dec.lower()
            if b"http" in low or b"cmd" in low or b"powershell" in low:
                self.vind("XOR-versluiering", bron,
                          f"XOR-sleutel 0x{key:02x} onthult leesbare payload: {dec[:80]!r}",
                          "H", "AVG art. 5(1)(d); art. 12 lid 1", True)
                return

    # ── Unicode-scan ──
    def _unicode(self, t, bron):
        if not t:
            return
        z = Counter(c for c in t if ord(c) in _ONZICHTBAAR)
        if z:
            self.vind("onzichtbare tekens", bron,
                      "; ".join(f"U+{ord(c):04X} {_ONZICHTBAAR[ord(c)]} x{n}"
                                for c, n in z.most_common()),
                      "M", "AVG art. 12 lid 1")
        b = Counter(c for c in t if ord(c) in _BIDI)
        if b:
            zwaar = any(ord(c) in (0x202d, 0x202e) for c in b)
            self.vind("bidi-stuurtekens", bron,
                      "; ".join(f"U+{ord(c):04X} {_BIDI[ord(c)]} x{n}"
                                for c, n in b.most_common())
                      + (". OVERRIDE: getoonde leesvolgorde kan omgekeerd zijn aan de "
                         "opgeslagen tekst." if zwaar else ""),
                      "H" if zwaar else "M", "AVG art. 5(1)(d)")
        tg = [c for c in t if 0xE0000 <= ord(c) <= 0xE007F]
        if tg:
            self.vind("Unicode tags-blok (steganografie)", bron,
                      f"{len(tg)} onzichtbare tekens. Gedecodeerd: "
                      + repr("".join(chr(ord(c) - 0xE0000) for c in tg
                                     if 0xE0020 <= ord(c) <= 0xE007E))[:160],
                      "H", "AVG art. 5(1)(d); art. 12 lid 1")
        h = Counter(c for c in t if c in _HOMO)
        if h:
            self.vind("homogliefen", bron,
                      f"{sum(h.values())} tekens die op een Latijnse letter lijken maar het "
                      "niet zijn: "
                      + "; ".join(f"U+{ord(c):04X} lijkt op {_HOMO[c]!r} x{n}"
                                  for c, n in h.most_common(10))
                      + ". Zoeken op de gewone spelling vindt deze regels niet.",
                      "H", "AVG art. 5(1)(d); art. 15")
        gem = []
        for w in re.findall(r"\S{3,40}", t)[:20000]:
            s = {_script_van(c) for c in w if c.isalpha()}
            s.discard("")
            if len(s) > 1:
                gem.append(f"{w!r}={'+'.join(sorted(s))}")
        if gem:
            self.vind("gemengde schriften binnen een woord", bron,
                      f"{len(gem)} woorden met tekens uit meerdere schriften: "
                      + "; ".join(gem[:8]), "H", "AVG art. 5(1)(d)", True)
        try:
            if unicodedata.normalize("NFKC", t) != t:
                self.vind("normalisatie-divergentie", bron,
                          "NFKC verandert de tekst: opgeslagen tekens zijn niet de "
                          "getoonde tekens.", "M", "AVG art. 5(1)(d)", True)
        except Exception:
            pass

    # ── medische patronen + BSN 11-proef ──
    def _medisch(self, t, bron):
        for cat, pat in _MED.items():
            treffers = re.findall(pat, t)
            if not treffers:
                continue
            if cat == "BSN":
                bsns = [m if isinstance(m, str) else m[0] for m in treffers]
                ongeldig = [b for b in set(bsns)
                            if len(str(b)) == 9 and not _valide_bsn(b)[0]]
                self.vind("medische context: BSN", bron,
                          f"{len(bsns)} BSN-patroon/patronen; "
                          + (f"{len(ongeldig)} faalt de 11-proef (mogelijk ruis of "
                             f"vervalsing): {ongeldig[:5]}" if ongeldig
                             else "alle geteste patronen zijn structureel valide."),
                          "M", "AVG art. 9 bijzondere persoonsgegevens")
            else:
                self.vind(f"medische context: {cat}", bron,
                          f"{len(treffers)} match(es)", "L",
                          "AVG art. 9 bijzondere persoonsgegevens")

    # ── UUIDv1 → MAC + tijdstip ──
    def _uuids(self, t, bron):
        gevonden = re.findall(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", t)
        v1 = []
        for m in list(dict.fromkeys(gevonden))[:400]:
            try:
                u = _uuid.UUID(m)
            except Exception:
                continue
            if u.version != 1:
                continue
            mac = ":".join(f"{(u.node >> s) & 0xff:02x}" for s in (40, 32, 24, 16, 8, 0))
            try:
                dt = datetime(1970, 1, 1) + timedelta(
                    seconds=(u.time - 0x01b21dd213814000) / 1e7)
                tijd = dt.isoformat(timespec="seconds")
            except Exception:
                tijd = ""
            v1.append((mac, tijd))
        if v1:
            macs = Counter(x[0] for x in v1)
            tijden = sorted(x[1] for x in v1 if x[1])
            for mac in macs:
                self.corpus["macs"][mac].add(pathlib.Path(bron).name)
            self.vind("UUIDv1: machine-identiteit en tijdstip", bron,
                      f"{len(v1)} tijdgebonden UUID's. Node(s): "
                      + "; ".join(f"{k} x{n}" for k, n in macs.most_common(5))
                      + (f". Tijd in de UUID: {tijden[0]} tot {tijden[-1]}" if tijden else "")
                      + ". Twee exports met verschillende nodes zijn op verschillende "
                        "machines gemaakt.",
                      "H", "AVG art. 5(1)(d); art. 15 lid 1 sub g herkomst", True)

    # ── PDF ──
    def _pdf(self, pad, raw):
        eofs = raw.count(b"%%EOF")
        prev = len(re.findall(rb"/Prev\s+\d+", raw))
        if eofs > 1 or prev:
            self.vind("incrementele update", pad,
                      f"{eofs}x %%EOF en {prev}x /Prev. Het bestand is na aanmaak bewerkt "
                      "en opnieuw opgeslagen; de vorige versie staat nog fysiek in het bestand.",
                      "H", "AVG art. 5(1)(d); art. 32; art. 225 Sr")
        if not _HAS_FITZ:
            return
        try:
            d = fitz.open(pad)
        except Exception as e:
            self.vind("PDF niet te openen", pad, str(e), "L")
            return

        def dat(s):
            g = re.search(r"D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})"
                          r"(?:([Zz+\-])(\d{2})'?(\d{2})?)?", s or "")
            if not g:
                return "", ""
            y, mo, dd, h, mi, se, sg, oh, om = g.groups()
            tz = "+00:00" if sg in ("Z", "z") else (f"{sg}{oh}:{om or '00'}" if sg else "")
            return f"{y}-{mo}-{dd} {h}:{mi}:{se}", tz

        m = d.metadata or {}
        c, ctz = dat(m.get("creationDate", ""))
        w, wtz = dat(m.get("modDate", ""))
        self.vind("PDF-metadata", pad,
                  f"producer={m.get('producer', '')}; creator={m.get('creator', '')}; "
                  f"aangemaakt {c} {ctz}; gewijzigd {w} {wtz}; {d.page_count} pagina's", "L")
        if ctz and wtz and ctz != wtz:
            self.vind("tijdzoneverschil binnen een document", pad,
                      f"aangemaakt met offset {ctz}, gewijzigd met offset {wtz}.",
                      "M", "AVG art. 5(1)(d)", True)

        onz, buiten, mini = [], [], []
        for n in range(d.page_count):
            try:
                pg = d[n]; vlak = pg.rect
            except Exception:
                continue
            try:
                spans = pg.get_texttrace()
            except Exception:
                spans = []
            for s in spans:
                ch = s.get("chars") or []
                t = "".join(chr(x[0]) for x in ch
                            if isinstance(x, (list, tuple)) and x).strip()
                if not t:
                    continue
                r = []
                if s.get("type") == 3:
                    r.append("render mode 3, wordt niet getekend")
                try:
                    if s.get("opacity") is not None and float(s["opacity"]) == 0:
                        r.append("dekking 0")
                except Exception:
                    pass
                k = s.get("color")
                if isinstance(k, (list, tuple)) and k and all(
                        isinstance(x, (int, float)) and x >= 0.98 for x in k):
                    r.append("witte tekstkleur")
                if r:
                    onz.append((n + 1, t[:100], " + ".join(r)))
                if 0 < (s.get("size") or 0) < 1.0:
                    mini.append((n + 1, t[:60]))
                bb = s.get("bbox")
                if bb:
                    try:
                        if not fitz.Rect(bb).intersects(vlak):
                            buiten.append((n + 1, t[:100]))
                    except Exception:
                        pass
            try:
                ex = len(re.sub(r"\s", "", pg.get_text("text")))
                zicht = sum(len(s.get("chars") or []) for s in spans
                            if s.get("type") != 3
                            and (s.get("opacity") is None or float(s.get("opacity", 1)) != 0))
                if ex > zicht * 1.25 and ex - zicht > 40:
                    self.vind("divergentie tekstlaag tegen weergave", pad,
                              f"Pagina {n + 1}: extractie {ex} tekens, zichtbaar {zicht}. "
                              "Er zit meer tekst in het bestand dan te zien is.",
                              "H", "AVG art. 12 lid 1; art. 15", True)
            except Exception:
                pass

        if onz:
            self.vind("onzichtbare tekst", pad,
                      f"{len(onz)} spans staan wel in het bestand maar zijn niet zichtbaar. "
                      "Eerste: " + "; ".join(f"p{a} {b!r} ({c_})" for a, b, c_ in onz[:5]),
                      "H", "AVG art. 12 lid 1; art. 15")
        if buiten:
            self.vind("tekst buiten het paginavlak", pad,
                      f"{len(buiten)} spans staan buiten de MediaBox. Eerste: "
                      + "; ".join(f"p{a} {b!r}" for a, b in buiten[:5]),
                      "H", "AVG art. 12 lid 1; art. 15", True)
        if mini:
            self.vind("onleesbaar kleine tekst", pad,
                      f"{len(mini)} spans onder 1 punt: "
                      + "; ".join(f"p{a} {b!r}" for a, b in mini[:5]),
                      "M", "AVG art. 12 lid 1")
        try:
            o = d.get_ocgs() or {}
            uit = [v for v in o.values() if v.get("on") is False]
            if o:
                self.vind("optionele contentlagen", pad,
                          f"{len(o)} laag/lagen: {[v.get('name') for v in o.values()][:6]}"
                          + (f". {len(uit)} standaard UIT (onzichtbaar bij openen)."
                             if uit else ""),
                          "H" if uit else "L", "AVG art. 12 lid 1")
        except Exception:
            pass
        vb = []
        for n in range(d.page_count):
            try:
                for a in d[n].annots() or []:
                    if a.flags & 2:
                        vb.append(f"p{n + 1} {(a.info or {}).get('content', '')[:50]!r}")
            except Exception:
                pass
        if vb:
            self.vind("annotatie met hidden-vlag", pad,
                      f"{len(vb)} verborgen annotaties: {vb[:5]}", "H", "AVG art. 15")
        try:
            t = "".join(d[i].get_text("text") for i in range(min(d.page_count, 60)))
            self._unicode(t, pad + " [tekstlaag]")
        except Exception:
            pass
        try:
            d.close()
        except Exception:
            pass

    # ── Office (docx/xlsx/pptx) ──
    def _office(self, pad, raw):
        try:
            z = zipfile.ZipFile(io.BytesIO(raw)); n = z.namelist()
        except Exception:
            return
        if "word/document.xml" in n:
            x = z.read("word/document.xml").decode("utf-8", "replace")
            v = len(re.findall(r'<w:vanish\b(?![^>]*w:val="(?:0|false)")', x))
            if v:
                st = re.findall(r"<w:r\b(?:(?!</w:r>).)*?<w:vanish\b(?:(?!</w:r>).)*?</w:r>",
                                x, re.S)
                tk = ["".join(re.findall(r"<w:t[^>]*>([^<]*)", s)).strip()[:70]
                      for s in st[:8]]
                self.vind("Word verborgen tekst (w:vanish)", pad,
                          f"{v} tekstlopen met verborgen-vlag. Voorbeeld: "
                          f"{[t for t in tk if t][:5]}", "H", "AVG art. 15; art. 12 lid 1")
            i, dl = len(re.findall(r"<w:ins\b", x)), len(re.findall(r"<w:del\b", x))
            if i or dl:
                self.vind("bijgehouden wijzigingen", pad,
                          f"{i} invoegingen, {dl} verwijderingen. Verwijderde tekst nog leesbaar: "
                          f"{[t[:60] for t in re.findall(r'<w:delText[^>]*>([^<]*)', x)][:5]}",
                          "H", "AVG art. 5(1)(d); art. 15")
            rs = set(re.findall(r'w:rsid[A-Za-z]*="([0-9A-Fa-f]{8})"', x))
            if len(rs) > 1:
                self.vind("bewerkingssessies (rsid)", pad,
                          f"{len(rs)} verschillende revision save ID's: minstens zoveel "
                          "losse bewerksessies.", "M", "AVG art. 5(1)(d)", True)
        if "xl/workbook.xml" in n:
            w = z.read("xl/workbook.xml").decode("utf-8", "replace")
            vb = re.findall(r'<sheet[^>]*name="([^"]+)"[^>]*state="(hidden|veryHidden)"', w)
            if vb:
                self.vind("verborgen werkbladen", pad,
                          "; ".join(f"{a} ({b})" for a, b in vb)
                          + ". veryHidden is via de interface niet zichtbaar te maken.",
                          "H", "AVG art. 15")
            for sh in [q for q in n if q.startswith("xl/worksheets/sheet")]:
                x = z.read(sh).decode("utf-8", "replace")
                r = len(re.findall(r'<row[^>]*hidden="1"', x))
                k = len(re.findall(r'<col[^>]*hidden="1"', x))
                if r or k:
                    self.vind("verborgen rijen of kolommen", pad,
                              f"{sh}: {r} rijen, {k} kolommen", "M", "AVG art. 15")
        if "xl/sharedStrings.xml" in n:
            s = z.read("xl/sharedStrings.xml").decode("utf-8", "replace")
            alle = re.findall(r"<t[^>]*>([^<]*)", s)
            gebruikt = set()
            for sh in [q for q in n if q.startswith("xl/worksheets/sheet")]:
                gebruikt |= {int(v) for v in re.findall(
                    r'<c[^>]*t="s"[^>]*>\s*<v>(\d+)',
                    z.read(sh).decode("utf-8", "replace"))}
            wees = [alle[i] for i in range(len(alle))
                    if i not in gebruikt and alle[i].strip()]
            if len(wees) > 3:
                self.vind("gedeelde teksten zonder cel", pad,
                          f"{len(wees)} teksten staan in het bestand maar worden door geen "
                          f"cel gebruikt (resten van verwijderde inhoud): {wees[:6]}",
                          "H", "AVG art. 5(1)(d); art. 15", True)
        # docProps (auteur/laatst-gewijzigd-door/revisie/bedrijf)
        for docprop in ("docProps/core.xml", "docProps/app.xml"):
            if docprop in n:
                try:
                    x = z.read(docprop).decode("utf-8", "replace")
                except Exception:
                    continue
                velden = {}
                for tag in ("dc:creator", "cp:lastModifiedBy", "cp:revision",
                            "dcterms:created", "dcterms:modified", "Company",
                            "Application", "TotalTime"):
                    m = re.search(rf"<{tag}[^>]*>([^<]*)</{tag}>", x)
                    if m and m.group(1).strip():
                        velden[tag.split(":")[-1]] = m.group(1).strip()
                if velden:
                    self.vind("Office-documentmetadata", pad,
                              "; ".join(f"{k}={v}" for k, v in velden.items()),
                              "M", "AVG art. 5(1)(d); art. 15 lid 1 sub g herkomst")
                cre = velden.get("creator")
                lmb = velden.get("lastModifiedBy")
                if cre and lmb and cre != lmb:
                    self.vind("auteur is niet de laatste bewerker", pad,
                              f"aangemaakt door {cre!r}, laatst gewijzigd door {lmb!r}: "
                              "het document is door een ander bewerkt dan de opsteller.",
                              "M", "AVG art. 5(1)(d)", True)

    # ── ZIP-residu ──
    def _zip_residu(self, pad, raw):
        try:
            z = zipfile.ZipFile(io.BytesIO(raw))
        except Exception:
            return
        dek = []
        for i in z.infolist():
            try:
                a, b = struct.unpack("<HH", raw[i.header_offset + 26:i.header_offset + 30])
                s = i.header_offset
                e = s + 30 + a + b + i.compress_size + (16 if i.flag_bits & 8 else 0)
                dek.append((s, e))
            except Exception:
                pass
        eo = raw.rfind(b"PK\x05\x06")
        if eo != -1:
            try:
                cs, co = struct.unpack("<II", raw[eo + 12:eo + 20])
                cl = struct.unpack("<H", raw[eo + 20:eo + 22])[0]
                dek += [(co, co + cs), (eo, eo + 22 + cl)]
                if cl:
                    self.vind("ZIP-archiefcommentaar", pad,
                              f"{cl} bytes in het commentaarveld, buiten elk bestand om: "
                              f"{raw[eo + 22:eo + 22 + cl][:150]!r}", "M", "AVG art. 5(1)(d)")
            except Exception:
                pass
        dek.sort()
        sam = []
        for s, e in dek:
            if sam and s <= sam[-1][1]:
                sam[-1][1] = max(sam[-1][1], e)
            else:
                sam.append([s, e])
        cur, gaten = 0, []
        for s, e in sam:
            if s > cur:
                gaten.append((cur, s))
            cur = max(cur, e)
        if cur < len(raw):
            gaten.append((cur, len(raw)))
        for s, e in gaten:
            blok = raw[s:e]
            if e - s < 8 or not blok.strip(b"\x00"):
                continue
            self.vind("onverklaarde bytes in ZIP", pad,
                      f"{e - s} bytes op offset {s} horen bij geen enkel bestand, niet bij "
                      f"de central directory en niet bij de EOCD. Inhoud: {blok[:110]!r}",
                      "H", "AVG art. 5(1)(d); art. 32", True)
        cd = {i.filename for i in z.infolist()}
        lok = set()
        for m in re.finditer(rb"PK\x03\x04", raw):
            try:
                ln = struct.unpack("<H", raw[m.start() + 26:m.start() + 28])[0]
                nm = raw[m.start() + 30:m.start() + 30 + ln].decode("utf-8", "replace")
                if nm:
                    lok.add(nm)
            except Exception:
                pass
        wees = lok - cd
        if wees:
            self.vind("ZIP-entry buiten de central directory", pad,
                      f"{len(wees)} bestand(en) staan fysiek in het archief maar niet in de "
                      f"inhoudsopgave: {sorted(wees)[:8]}", "H",
                      "AVG art. 15; art. 12 lid 1", True)

    # ── PNG ──
    def _png(self, pad, raw):
        if raw[:8] != b"\x89PNG\r\n\x1a\n":
            return
        pos, onb, tk = 8, [], []
        while pos + 8 <= len(raw):
            try:
                ln = struct.unpack(">I", raw[pos:pos + 4])[0]
                nm = raw[pos + 4:pos + 8]
                dt = raw[pos + 8:pos + 8 + ln]
            except Exception:
                break
            if nm in (b"tEXt", b"zTXt", b"iTXt"):
                try:
                    if nm == b"tEXt":
                        k, _, v = dt.partition(b"\x00")
                        tk.append(f"{k.decode('latin-1')}={v.decode('latin-1')[:150]}")
                    elif nm == b"zTXt":
                        k, _, r = dt.partition(b"\x00")
                        tk.append(f"{k.decode('latin-1')}="
                                  f"{zlib.decompress(r[1:]).decode('latin-1')[:150]}")
                    else:
                        d = dt.split(b"\x00", 5)
                        tk.append(f"{d[0].decode('latin-1')}="
                                  f"{d[-1][:150].decode('utf-8', 'replace')}")
                except Exception:
                    tk.append(f"{nm.decode('latin-1')} ({ln} bytes, niet te lezen)")
            elif nm not in _PNG_STD:
                onb.append(f"{nm.decode('latin-1', 'replace')} ({ln} bytes @ {pos})")
            if nm == b"IEND":
                break
            pos += 8 + ln + 4
        if tk:
            self.vind("PNG-tekstblokken", pad, "; ".join(tk[:6]), "M", "AVG art. 15")
        if onb:
            self.vind("onbekende PNG-chunk", pad,
                      f"{len(onb)} chunk(s) buiten de PNG-standaard: {onb[:6]}",
                      "H", "AVG art. 5(1)(d); art. 15", True)

    # ── staartdata na EOF-marker ──
    def _staart(self, pad, raw, t):
        m = {"pdf": b"%%EOF", "jpg": b"\xff\xd9", "png": b"IEND\xaeB`\x82",
             "gif": b"\x00\x3b"}.get(t)
        if not m:
            return
        i = raw.rfind(m)
        if i == -1:
            return
        r = raw[i + len(m):].strip(b"\r\n \t\x00")
        if len(r) < 8:
            return
        self.vind("data voorbij het einde van het bestand", pad,
                  f"{len(r)} bytes na de laatste {m!r}. Geen viewer toont dit. "
                  f"Inhoud: {r[:110]!r}. sha256={hashlib.sha256(r).hexdigest()[:24]}",
                  "H", "AVG art. 5(1)(d); art. 15", True)

    # ── HTML verbergende opmaak ──
    def _html(self, pad, raw):
        t = raw.decode("utf-8", "replace")
        regels = [
            (r"display\s*:\s*none", "display:none"),
            (r"visibility\s*:\s*hidden", "visibility:hidden"),
            (r"opacity\s*:\s*0(?!\.\d*[1-9])", "opacity:0"),
            (r"font-size\s*:\s*0(?:px|pt|em)?\b", "font-size:0"),
            (r"text-indent\s*:\s*-\s*\d{3,}", "tekst buiten beeld geschoven"),
            (r"(?:left|top)\s*:\s*-\s*\d{4,}", "absoluut buiten beeld"),
            (r'aria-hidden\s*=\s*["\']true', "aria-hidden"),
            (r'class\s*=\s*"[^"]*\b(?:sr-only|visually-hidden)\b', "alleen schermlezer"),
            (r'type\s*=\s*["\']hidden["\']', "verborgen formulierveld"),
        ]
        g = [f"{naam} x{len(re.findall(r_, t, re.I))}"
             for r_, naam in regels if re.search(r_, t, re.I)]
        if g:
            self.vind("verbergende opmaak", pad, "; ".join(g), "M", "AVG art. 12 lid 1")
        pr = re.findall(r"@media\s+print\s*{((?:[^{}]|{[^{}]*})*)}", t, re.I)
        if pr:
            self.vind("afwijkende regels bij printen", pad,
                      f"{len(pr)} @media print-blokken; afdruk wijkt af van scherm.",
                      "M", "AVG art. 12 lid 1", True)
        cm = [c.strip() for c in re.findall(r"<!--(.*?)-->", t, re.S) if len(c.strip()) > 80]
        if cm:
            self.vind("HTML-commentaar met inhoud", pad,
                      f"{len(cm)} commentaarblokken >80 tekens. Eerste: {cm[0][:180]!r}",
                      "M", "AVG art. 15")

    # ── entropie-eilanden ──
    def _entro(self, pad, raw, t):
        if len(raw) < 8192:
            return
        W = 4096
        v = [(i, _entropie(raw[i:i + W])) for i in range(0, len(raw) - W, W)]
        if not v:
            return
        gem = sum(e for _, e in v) / len(v)
        if t not in ("zip", "gz", "png", "jpg", "docx", "xlsx", "pptx", "bz2"):
            hoog = [i for i, e in v if e > 7.5]
            if hoog and len(hoog) < len(v) * 0.5:
                self.vind("entropie-eiland", pad,
                          f"{len(hoog)} blokken met entropie > 7,5 bits/byte in een bestand met "
                          f"gemiddeld {gem:.2f}. Eerste offset {hoog[0]}. Wijst op versleutelde "
                          "of gecomprimeerde inhoud op een plek waar dat niet hoort.",
                          "M", "AVG art. 12 lid 1", True)

    # ── ZIP-inversie (Matroesjka) ──
    def _zip_inversie(self, pad, raw):
        if raw.endswith(b"PK\x03\x04") or b"PK\x03\x04" in raw[-100:]:
            self.vind("ZIP-inversie (Matroesjka)", pad,
                      "PK-header aangetroffen aan het EINDE van het bestand: klassieke "
                      "anti-forensische omkering.", "H",
                      "AVG art. 5(1)(d); art. 32", True)
            # poging tot reparatie + recursieve scan van de inhoud
            try:
                hersteld = raw[::-1]
                if hersteld.startswith(b"PK\x03\x04"):
                    z = zipfile.ZipFile(io.BytesIO(hersteld))
                    for nm in z.namelist()[:50]:
                        self._scan_bytes(z.read(nm), f"{pathlib.Path(pad).name}::{nm}", 1)
            except Exception:
                pass

    # ── magic-byte-mismatch (extensie vs. echte inhoud) ──
    def _magic_mismatch(self, pad, raw, t):
        ext = pathlib.Path(pad).suffix.lower().lstrip(".")
        norm = {"htm": "html", "jpeg": "jpg", "har": "json",
                "cda": "xml", "xsl": "xml", "tif": "tiff"}.get(ext, ext)
        # alleen melden als extensie een echt formaat claimt dat afwijkt van de magic
        bekend = {"pdf", "png", "jpg", "gif", "zip", "docx", "xlsx", "pptx", "gz", "bz2"}
        if norm in bekend and t != norm and not (norm in ("docx", "xlsx", "pptx") and t == "zip"):
            self.vind("magic-byte-mismatch", pad,
                      f"Bestand heet .{ext} maar de bytes zijn een {t}. Het bestandstype is "
                      "vermomd.", "H", "AVG art. 5(1)(d); art. 225 Sr", True)

    # ── NL zorg-identifiers (OID-context) + verdachte actoren ──
    def _nl_identifiers(self, t, bron):
        # <id root="OID" extension="VALUE"/>
        paren = re.findall(r'root="([0-9.]+)"[^>]*?extension="([^"]*)"', t)
        paren += [(r, e) for e, r in re.findall(
            r'extension="([^"]*)"[^>]*?root="([0-9.]+)"', t)]
        gezien = Counter()
        for root, ext in paren:
            sys = _OID_SYSTEM.get(root)
            if sys:
                gezien[sys] += 1
        if gezien:
            self.vind("NL zorg-identifiers", bron,
                      "; ".join(f"{k} x{v}" for k, v in gezien.most_common()),
                      "L", "AVG art. 15 lid 1 sub g herkomst")
        # verdachte/ongeïdentificeerde actoren
        for ext, uitleg in _VERDACHTE_ACTOREN.items():
            if re.search(rf'extension="{re.escape(ext)}"', t) or f'>{ext}<' in t:
                self.vind(f"verdachte actor ext={ext}", bron, uitleg,
                          "H", "WGBO 7:454; AVG art. 5(1)(a); art. 15 lid 1 sub g")
        if re.search(r'nullFlavor="UNK"', t):
            n = len(re.findall(r'nullFlavor="UNK"', t))
            self.vind("nullFlavor=UNK (identiteit onbekend)", bron,
                      f"{n}x nullFlavor=UNK: identiteit van auteur/ondertekenaar is als "
                      "onbekend gemarkeerd.", "M", "WGBO 7:454; AVG art. 5(1)(a)")

    # ── forensische SNOMED/LOINC-codes ──
    def _med_codes(self, t, bron):
        for code, uitleg in _SNOMED_FORENSISCH.items():
            if code in t:
                self.vind(f"SNOMED {code}", bron,
                          f"{uitleg}. Stigmatiserende codering vereist onderbouwing.",
                          "H", "AVG art. 9 bijzondere persoonsgegevens; WGBO 7:454")
        for code, uitleg in _LOINC_FORENSISCH.items():
            if code in t:
                waarde = "H" if code == "10160-0" else "L"
                self.vind(f"LOINC {code}", bron, uitleg, waarde,
                          "WGBO 7:454; AVG art. 15/20")

    # ── dossier-sabotagemarkers ──
    def _markers(self, t, bron):
        low = t.lower()
        gevonden = [m for m in _SABOTAGE_MARKERS if m in low]
        if gevonden:
            self.vind("sabotage-/injectiemarker", bron,
                      "Dossier-marker(s) aangetroffen: " + ", ".join(gevonden),
                      "H", "AVG art. 5(1)(d); art. 32; art. 138ab Sr (computervredebreuk)")

    # ════════════════════════════════════════════════════════════════════
    #  ONTDEKKINGSLAAG — vindt zelf, sluit niet uit (anti-tunnelvisie)
    #  Draait op ELKE tekst. Enumereert alles, voedt het corpus, en meldt
    #  afwijkingen van de norm — zonder vaste lijst van "wat verdacht is".
    # ════════════════════════════════════════════════════════════════════
    def _ontdek(self, t, bron):
        naam = pathlib.Path(bron).name
        # 1. alle OID-autoriteiten (root=) — onbekende PREFIX wordt gemeld, niet genegeerd
        for root in re.findall(r'root="([0-9][0-9.]{4,})"', t):
            self.corpus["oid_roots"][root] += 1
            if not any(root.startswith(p) for p in _BEKENDE_OID_PREFIXEN):
                self.vind("onbekende identifier-autoriteit", bron,
                          f"OID-root {root} hoort bij geen bekende zorgautoriteit "
                          "(HL7/NL/Epic/IHE). Handmatig verifiëren — mogelijk nieuwe of "
                          "niet-geregistreerde bron.",
                          "M", "AVG art. 5(1)(d); art. 15 lid 1 sub g", True)
        # 2. alle codeSystem + code-paren — onbekend codeSystem gemeld; alles verzameld
        for cs, code in re.findall(
                r'codeSystem="([0-9.]+)"[^>]*?\bcode="([^"]+)"', t) + \
                [(cs, code) for code, cs in re.findall(
                    r'\bcode="([^"]+)"[^>]*?codeSystem="([0-9.]+)"', t)]:
            self.corpus["code_systems"][cs] += 1
            self.corpus["codes"][cs][code] += 1
            if cs not in _BEKENDE_CODESYSTEMEN:
                self.vind("onbekend codeSystem", bron,
                          f"codeSystem {cs} (code {code}) is geen standaard "
                          "terminologie (SNOMED/LOINC/ICD/ATC/RxNorm/G-Standaard).",
                          "M", "AVG art. 5(1)(d)", True)
        # 3. alle numerieke identifiers (extension=/id) — voedt singleton-analyse;
        #    herhaald-cijfer-placeholder wordt DIRECT gemeld (vangt 000000/999999 e.d.)
        for ext in re.findall(r'extension="([0-9]{5,})"', t):
            self.corpus["actoren"][ext].add(naam)
            if len(set(ext)) == 1:
                self.vind("placeholder-identifier (herhaald cijfer)", bron,
                          f"identifier {ext} bestaat uit één herhaald cijfer: kenmerk van "
                          "een opvul-/anonimisatiewaarde in plaats van een echte actor.",
                          "H", "WGBO 7:454; AVG art. 5(1)(a)", True)
        # 4. alle XML-namespaces
        for ns in re.findall(r'xmlns(?::\w+)?="([^"]+)"', t):
            self.corpus["namespaces"][ns] += 1
        # 5. alle tijdzone-offsets (per bestand + corpus-breed)
        for tz in re.findall(r'value="\d{8,14}([+\-]\d{4})"', t):
            self.corpus["tijdzones"][tz] += 1
        # 6. setId -> versienummers (cross-document rotatie-detectie in corpus)
        sid = re.search(r'<setId\b[^>]*extension="([^"]+)"', t, re.I)
        if sid:
            for v in re.findall(r'<versionNumber\b[^>]*value="([^"]+)"', t, re.I) or ["?"]:
                self.corpus["setids"][sid.group(1)].add(v)

    # ── corpus-brede analyse: draait NA alle bestanden (zoals _nb224) ──
    def _corpus_analyse(self):
        cp = self.corpus
        # singleton-actoren: numeriek ID dat in het HELE corpus één keer voorkomt
        singletons = [k for k, files in cp["actoren"].items()
                      if len(files) == 1 and len(k) >= 6 and len(set(k)) > 1]
        if singletons:
            self.vind("singleton-actor(en)", "[corpus]",
                      f"{len(singletons)} numerieke identifier(s) komen in het hele corpus "
                      f"exact één keer voor: {singletons[:12]}. Eenmalige actoren zijn "
                      "kandidaat voor nadere identificatie (ongeïdentificeerde invoerder).",
                      "M", "AVG art. 15 lid 1 sub g herkomst", True)
        # zeldzame codes: waarden die corpus-breed één keer voorkomen
        zeldzaam = []
        for cs, teller in cp["codes"].items():
            naam_cs = _BEKENDE_CODESYSTEMEN.get(cs, cs)
            zeldzaam += [f"{naam_cs}:{code}" for code, n in teller.items() if n == 1]
        if zeldzaam:
            self.vind("zeldzame codering(en)", "[corpus]",
                      f"{len(zeldzaam)} code(s) komen corpus-breed één keer voor "
                      f"(mogelijk uitzonderlijk/afwijkend): {zeldzaam[:15]}",
                      "L", "AVG art. 9 bijzondere persoonsgegevens", True)
        # tijdzone-spreiding over het corpus
        if len(cp["tijdzones"]) > 1:
            self.vind("tijdzone-spreiding (corpus)", "[corpus]",
                      f"het corpus bevat meerdere tijdzone-offsets: "
                      f"{dict(cp['tijdzones'])}. Inconsistente offsets wijzen op "
                      "verschillende generatiemachines/-momenten.",
                      "M", "AVG art. 5(1)(d)", True)
        # meerdere MAC-nodes (uit UUIDv1) over het corpus
        if len(cp["macs"]) > 1:
            self.vind("meerdere machine-identiteiten (corpus)", "[corpus]",
                      "UUIDv1-nodes wijzen op meerdere aanmaakmachines: "
                      + "; ".join(f"{mac} in {sorted(f)[:3]}"
                                 for mac, f in list(cp["macs"].items())[:6]),
                      "H", "AVG art. 5(1)(d); art. 15 lid 1 sub g", True)
        # setId met meerdere versienummers = rotatie/herziening over documenten
        for sid, versies in cp["setids"].items():
            if len(versies) > 1:
                self.vind("setId-rotatie (corpus)", "[corpus]",
                          f"setId {sid} verschijnt met versienummers {sorted(versies)}: "
                          "hetzelfde logische document bestaat in meerdere versies.",
                          "M", "HL7 CDA R2 §4.3.1; AVG art. 18", True)
        # volledige enumeratie zodat NIETS onzichtbaar blijft (analist ziet alles)
        self.vind("corpus-overzicht (volledige enumeratie)", "[corpus]",
                  f"OID-autoriteiten: {dict(cp['oid_roots'].most_common(20))} | "
                  f"codeSystemen: {dict(cp['code_systems'].most_common(10))} | "
                  f"namespaces: {list(cp['namespaces'])[:10]} | "
                  f"tijdzones: {dict(cp['tijdzones'])} | "
                  f"unieke actor-ID's: {len(cp['actoren'])}",
                  "L", "referentie/overzicht")

    # ── HL7 CDA R2 (verdiept) ──
    def _cda(self, t, bron):
        kop = t[:6000].lower()
        if "clinicaldocument" not in kop and _NS_CDA not in kop:
            return
        auteurblokken = re.findall(r"<author\b.*?</author>", t, re.S | re.I)
        exts = []
        for blk in auteurblokken:
            exts += re.findall(r'<id\b[^>]*\bextension="([^"]+)"', blk, re.I)
        c = Counter(exts)
        legal = "legalauthenticator" in t.lower()
        ver = sorted(set(re.findall(r'<versionNumber\b[^>]*value="([^"]+)"', t, re.I)))
        sid = re.search(r'<setId\b[^>]*extension="([^"]*)"', t, re.I)
        nf = Counter(re.findall(r'nullFlavor="([A-Z]+)"', t))
        parent = "parentdocument" in t.lower()
        self.vind("CDA-structuur", bron,
                  f"{len(auteurblokken)} auteurblokken, {len(c)} unieke ext; "
                  f"versionNumber={ver or '-'}; setId={sid.group(1) if sid else '-'}; "
                  f"nullFlavor {sum(nf.values())} ({dict(nf.most_common(4))}); "
                  f"parentDocument={'ja' if parent else 'nee'}; "
                  f"legalAuthenticator {'aanwezig' if legal else 'ONTBREEKT'}",
                  "M", "WGBO 7:454; HL7 CDA R2 §4.3.1")
        if c.get("999999"):
            self.vind("anonieme auteur ext=999999", bron,
                      f"{c['999999']} van {len(exts)} auteurverwijzingen zijn volledig "
                      "anoniem: geen naam, geen BIG, geen AGB.",
                      "H", "WGBO 7:454; AVG art. 5(1)(a); art. 15 lid 1 sub g")
        if not legal:
            self.vind("legalAuthenticator ontbreekt", bron,
                      "Het document draagt geen juridische ondertekenaar.",
                      "M", "WGBO 7:454")
        if ver and any(int(x) > 1 for x in ver if x.isdigit()):
            self.vind("versie-escalatie (CDA)", bron,
                      f"versionNumber {ver}: document is na eerste vaststelling herzien. "
                      "Bij bevriezing/inzageverzoek is dit relevant.",
                      "M", "AVG art. 18; HL7 CDA R2 §4.3.1")
        # tijdzone-anomalie: +0000 naast +0200 in dezelfde effectiveTime-tijden
        tzs = set(re.findall(r'value="\d{8,14}([+\-]\d{4})"', t))
        if len(tzs) > 1:
            self.vind("tijdzone-anomalie (CDA)", bron,
                      f"meerdere tijdzone-offsets in één document: {sorted(tzs)}. "
                      "+0000 naast +0200 wijst op machinematige (her)generatie.",
                      "M", "AVG art. 5(1)(d)", True)
        self._nl_identifiers(t, bron)
        self._med_codes(t, bron)
        self._uuids(t, bron)

    # ── FHIR (Bundle/Patient/Observation) ──
    def _fhir(self, t, bron):
        if '"resourceType"' not in t:
            return
        typen = Counter(re.findall(r'"resourceType"\s*:\s*"([^"]+)"', t))
        if not typen:
            return
        self.vind("FHIR-resources", bron,
                  "; ".join(f"{k} x{v}" for k, v in typen.most_common(8)),
                  "L", "AVG art. 15/20 dataportabiliteit")
        vids = re.findall(r'"versionId"\s*:\s*"([^"]+)"', t)
        if vids and any(v.isdigit() and int(v) > 1 for v in vids):
            self.vind("FHIR versie-escalatie", bron,
                      f"meta.versionId {sorted(set(vids))}: resource(s) zijn na aanmaak "
                      "gewijzigd.", "M", "AVG art. 18")
        self._med_codes(t, bron)

    # ── IHE XDM METADATA.XML + MedMij-portabiliteitsrapport ──
    def _xdm_medmij(self, t, bron):
        low = t.lower()
        if _NS_XDM in low or "submissionset" in low:
            self.vind("IHE XDM metadata", bron,
                      "XDM SubmissionSet-metadata aangetroffen. Verifieer de SHA-1 "
                      "integriteitswaarde tegen de daadwerkelijke documentinhoud.",
                      "L", "NEN 7510; AVG art. 5(1)(f)")
        if _NS_MEDMIJ in low or "portabiliteitsrapport" in low:
            za = Counter(re.findall(r'za="?([A-Za-z0-9_@.\-]+)"?', t))
            self.vind("MedMij-portabiliteitsrapport", bron,
                      f"portabiliteitsrapport; {sum(za.values())} verzoekregels over "
                      f"{len(za)} zorgaanbieder(s). LET OP: entries zijn eigen "
                      "PGO-opvragingen, niet per se onrechtmatig.",
                      "L", "AVG art. 15/20; WABVPZ")

    # ── Apple .ips / .crash / .diag ──
    def _apple(self, pad, raw):
        naam = pathlib.Path(pad).name.lower()
        if not naam.endswith((".ips", ".crash", ".diag")):
            return
        t = raw.decode("utf-8", "replace")
        bug = re.search(r'"bug_type"\s*:\s*"?(\d+)"?', t)
        proc = re.search(r'"procName"\s*:\s*"([^"]+)"', t)
        obo = re.findall(r'"On Behalf Of"|onBehalfOf|"responsible"\s*:\s*"([^"]+)"', t)
        detail = []
        if bug:
            detail.append(f"bug_type={bug.group(1)}"
                          + (" (resource/aandacht)" if bug.group(1) == "145" else ""))
        if proc:
            detail.append(f"proces={proc.group(1)}")
        proces_flags = {"bird": "iCloud-sync", "mediaanalysisd": "ML-analyse",
                        "callservicesd": "camera/telefonie"}
        for p, uit in proces_flags.items():
            if re.search(rf'"{p}"', t):
                detail.append(f"{p}={uit}")
        if obo:
            detail.append(f"On-Behalf-Of/responsible: {[o for o in obo if o][:3]}")
        if "UNKNOWN" in t:
            detail.append("UNKNOWN-veld aanwezig (anomalie)")
        self.vind("Apple-diagnostiek", pad,
                  "; ".join(detail) or "diagnosticbestand herkend",
                  "M" if ("UNKNOWN" in t or (bug and bug.group(1) == "145")) else "L",
                  "AVG art. 5(1)(d) systeemherkomst")

    # ── HAR / Proxyman netwerk-capture ──
    def _har(self, pad, raw):
        try:
            data = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            return
        entries = (data.get("log", {}) or {}).get("entries") if isinstance(data, dict) else None
        if not entries:
            return
        urls = Counter()
        for e in entries[:5000]:
            u = ((e.get("request") or {}).get("url") or "")
            if u:
                m = re.match(r"https?://([^/]+)", u)
                if m:
                    urls[m.group(1)] += 1
        self.vind("HAR/netwerk-capture", pad,
                  f"{len(entries)} requests over {len(urls)} host(s). Top: "
                  + "; ".join(f"{k} x{v}" for k, v in urls.most_common(6)),
                  "L", "AVG art. 5(1)(d)")
        # sabotagemarkers over de volledige capture
        self._markers(raw.decode("utf-8", "replace")[:5_000_000], pad)

    # ── byte-scan (nested archief-members, matroesjka-inhoud) ──
    def _scan_bytes(self, raw, naam, diepte=0):
        if diepte > 3 or not raw:
            return
        t = self._soort(naam, raw)
        try:
            self._staart(naam, raw, t)
            self._xor(raw, naam)
            if t == "pdf":
                # PDF via bytes: alleen de goedkope byte-checks
                eofs = raw.count(b"%%EOF")
                if eofs > 1:
                    self.vind("incrementele update (genest)", naam,
                              f"{eofs}x %%EOF in genest PDF.", "H",
                              "AVG art. 5(1)(d); art. 32")
            elif t in ("docx", "xlsx", "pptx"):
                self._office(naam, raw)
            elif t == "zip":
                self._zip_residu(naam, raw)
                try:
                    z = zipfile.ZipFile(io.BytesIO(raw))
                    for nm in z.namelist()[:50]:
                        self._scan_bytes(z.read(nm), f"{naam}::{nm}", diepte + 1)
                except Exception:
                    pass
            elif t == "png":
                self._png(naam, raw)
            else:
                txt = raw.decode("utf-8", "replace")
                self._ontdek(txt[:2_000_000], naam)
                self._unicode(txt[:2_000_000], naam)
                self._medisch(txt[:2_000_000], naam)
                self._cda(txt, naam)
                self._fhir(txt, naam)
                self._uuids(txt[:2_000_000], naam)
                self._markers(txt[:2_000_000], naam)
                self._blokken(raw[:1_000_000], naam)
        except Exception:
            pass

    # ── één bestand ──
    def scan_bestand(self, pad):
        try:
            raw = pathlib.Path(pad).read_bytes()
        except Exception as e:
            self.vind("leesfout", pad, str(e), "L")
            return
        sha, md5, n = self._hashes(pad)
        t = self._soort(pad, raw)
        self.inventaris.append({"naam": pathlib.Path(pad).name, "pad": str(pad),
                                "type": t, "grootte": n, "sha256": sha, "md5": md5})
        if self.kluis:
            status, vorige = self.kluis.audit(pad, sha, n)
            if status == "GEWIJZIGD":
                self.vind("stille wijziging t.o.v. vorige run", pad,
                          f"SHA-256 veranderd sinds {vorige.get('gezien', '?')} "
                          f"({vorige['sha256'][:16]} -> {sha[:16]}).",
                          "H", "AVG art. 5(1)(d); art. 32", True)
        naam = pathlib.Path(pad).name.lower()
        try:
            self._zip_inversie(pad, raw)
            self._magic_mismatch(pad, raw, t)
            self._staart(pad, raw, t)
            self._entro(pad, raw, t)
            self._xor(raw, pad)
            if naam.endswith((".ips", ".crash", ".diag")):
                self._apple(pad, raw)
            if t == "pdf":
                self._pdf(pad, raw)
            elif t in ("docx", "xlsx", "pptx"):
                self._office(pad, raw); self._zip_residu(pad, raw)
            elif t == "zip":
                self._zip_residu(pad, raw)
                try:
                    z = zipfile.ZipFile(io.BytesIO(raw))
                    for nm in z.namelist()[:50]:
                        self._scan_bytes(z.read(nm), f"{pathlib.Path(pad).name}::{nm}", 1)
                except Exception:
                    pass
            elif t == "png":
                self._png(pad, raw)
            elif t in ("xml", "html", "txt", "json", "csv", "log", "bin"):
                txt = raw.decode("utf-8", "replace")
                if t == "html":
                    self._html(pad, raw)
                if t == "json" or naam.endswith((".har", ".json")):
                    self._har(pad, raw)
                self._ontdek(txt[:3_000_000], pad)          # ONTDEKKINGSLAAG eerst
                self._unicode(txt[:3_000_000], pad)
                self._medisch(txt[:3_000_000], pad)
                self._cda(txt, pad)
                self._fhir(txt, pad)
                self._xdm_medmij(txt, pad)
                self._uuids(txt[:3_000_000], pad)
                self._nl_identifiers(txt[:3_000_000], pad)
                self._med_codes(txt[:3_000_000], pad)
                self._markers(txt[:3_000_000], pad)
                self._blokken(raw[:2_000_000], pad)
            else:
                # niets stil wegslikken: onbekend/niet-geclassificeerd type melden
                txt = raw.decode("utf-8", "replace")
                if _plausibel(raw[:512]):
                    self._ontdek(txt[:2_000_000], pad)
                    self._unicode(txt[:2_000_000], pad)
                    self._markers(txt[:2_000_000], pad)
                elif t not in ("jpg", "gif", "gz", "bz2"):
                    self.vind("onbekend/niet-geclassificeerd bestandstype", pad,
                              f"type '{t}' wordt niet inhoudelijk ontleed; alleen hash, "
                              "entropie, staart- en XOR-checks uitgevoerd. Handmatige "
                              "inspectie aanbevolen zodat niets buiten beeld blijft.",
                              "L", "AVG art. 5(1)(d)", True)
        except Exception as e:
            self.vind("scanfout", pad, str(e), "L")

    # ── hele map ──
    def scan_map(self, map_in):
        paden = sorted(str(p) for p in pathlib.Path(map_in).rglob("*")
                       if p.is_file() and not p.name.startswith(".")
                       and "__MACOSX" not in str(p) and "_uitgepakt" not in str(p))
        print(f"[*] {len(paden)} bestanden in {map_in}\n")
        for i, p in enumerate(paden, 1):
            print(f"[{i}/{len(paden)}] {pathlib.Path(p).name[:60]}")
            self.scan_bestand(p)
        self._nb224()
        self._corpus_analyse()   # ontdekkingslaag: corpus-brede afwijkingen
        print(f"\n[*] Klaar: {len(self.bevindingen)} bevindingen.")
        return self.bevindingen

    # ── gelijke lengte / andere hash (NB-224) ──
    def _nb224(self):
        per = defaultdict(list)
        for f in self.inventaris:
            per[f["grootte"]].append(f)
        for g, fs in per.items():
            h = {f["sha256"] for f in fs}
            if len(fs) > 1 and len(h) > 1:
                self.vind("GELIJKE LENGTE, ANDERE HASH", fs[0]["pad"],
                          f"{len(fs)} bestanden van exact {g:,} bytes met {len(h)} "
                          f"verschillende hashes: {', '.join(f['naam'] for f in fs)}. "
                          "Signatuur van een lengte-neutrale herschrijving (NB-224).",
                          "H", "AVG art. 5(1)(d); art. 32; art. 225 Sr", True)


# ════════════════════════════════════════════════════════════════════════════
#  4. RAPPORT  (vervangt alle losse HTML/PDF/CSV/Excel-cellen)
# ════════════════════════════════════════════════════════════════════════════
def genereer_rapport(engine, map_uit="/content/uitvoer"):
    os.makedirs(map_uit, exist_ok=True)
    V = engine.bevindingen

    # JSON-register
    reg = os.path.join(map_uit, f"register_{TS}.json")
    with open(reg, "w", encoding="utf-8") as f:
        json.dump({"dossier": "Grothe C/15/376914",
                   "tijdstip": datetime.now().isoformat(),
                   "bestanden": engine.inventaris, "bevindingen": V},
                  f, ensure_ascii=False, indent=1)

    # SHA-256-bewijs
    with open(os.path.join(map_uit, f"sha256_bewijs_{TS}.txt"), "w") as f:
        for x in engine.inventaris:
            f.write(f"{x['sha256']}|{x['md5']}|{x['grootte']}|{x['pad']}\n")

    # CSV (+ Excel indien pandas)
    if _HAS_PD and V:
        df = pd.DataFrame(V)
        df.to_csv(os.path.join(map_uit, f"bevindingen_{TS}.csv"),
                  index=False, encoding="utf-8-sig")
        pd.DataFrame(engine.inventaris).to_csv(
            os.path.join(map_uit, f"inventaris_{TS}.csv"),
            index=False, encoding="utf-8-sig")
        try:
            df.to_excel(os.path.join(map_uit, f"bevindingen_{TS}.xlsx"), index=False)
        except Exception:
            pass

    # HTML-rapport
    kleur = {"H": "#f87171", "M": "#fbbf24", "L": "#38bdf8"}
    rijen = "".join(
        f"<tr><td>{b['bestand']}</td><td style='color:{kleur.get(b['bewijswaarde'], '#ccc')};"
        f"font-weight:bold'>{b['bewijswaarde']}</td><td>{b['techniek']}</td>"
        f"<td>{b['detail'][:400]}</td><td>{b['juridisch']}</td></tr>"
        for b in sorted(V, key=lambda x: {"H": 0, "M": 1, "L": 2}.get(x["bewijswaarde"], 9)))
    html = f"""<!DOCTYPE html><html lang="nl"><head><meta charset="UTF-8">
<title>Forensisch Rapport {TS}</title><style>
body{{font-family:'Segoe UI',Arial,sans-serif;background:#0f172a;color:#e2e8f0;padding:32px}}
h1{{color:#38bdf8}} table{{width:100%;border-collapse:collapse;margin-top:20px;font-size:13px}}
th{{background:#1e293b;color:#38bdf8;text-align:left;padding:10px;position:sticky;top:0}}
td{{padding:8px;border-bottom:1px solid #334155;vertical-align:top}}
</style></head><body>
<h1>Forensisch Rapport — Dossier Grothe C/15/376914</h1>
<p>Gegenereerd {datetime.now().strftime('%d-%m-%Y %H:%M:%S')} ·
{len(engine.inventaris)} bestanden · {len(V)} bevindingen
({sum(1 for b in V if b['bewijswaarde'] == 'H')} met bewijswaarde H)</p>
<table><thead><tr><th>Bestand</th><th>Bewijs</th><th>Techniek</th>
<th>Detail</th><th>Juridische grond</th></tr></thead><tbody>{rijen}</tbody></table>
</body></html>"""
    html_pad = os.path.join(map_uit, f"Forensisch_Eindrapport_{TS}.html")
    with open(html_pad, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[OK] Rapport: {html_pad}")
    print(f"[OK] Register: {reg}")
    return html_pad


# ════════════════════════════════════════════════════════════════════════════
#  5. TIMESTOMPING-ANALYSE  (vervangt alle regressie-/heatmap-/residual-cellen)
# ════════════════════════════════════════════════════════════════════════════
def timestomping_analyse(engine):
    """Lineaire regressie mtime vs. scanvolgorde; lage R² = mogelijke manipulatie."""
    if not _HAS_PD:
        print("[!] pandas vereist."); return None
    import numpy as np
    rijen = []
    for i, f in enumerate(engine.inventaris):
        try:
            mt = os.path.getmtime(f["pad"])
        except Exception:
            continue
        rijen.append({"bestand": f["naam"], "mtime": mt, "volgorde": i})
    if len(rijen) < 3:
        print("[!] Te weinig bestanden."); return None
    df = pd.DataFrame(rijen)
    x, y = df["mtime"].to_numpy(), df["volgorde"].to_numpy()
    slope, intercept = np.polyfit(x, y, 1)
    voorspeld = slope * x + intercept
    ss_res = float(((y - voorspeld) ** 2).sum())
    ss_tot = float(((y - y.mean()) ** 2).sum()) or 1.0
    r2 = 1 - ss_res / ss_tot
    df["afwijking"] = np.abs(y - voorspeld)
    print(f"### Timestomping — R² = {r2:.3f}")
    print("⚠️ Lage correlatie: mogelijke metadata-manipulatie."
          if r2 < 0.6 else "✅ Tijdlijn consistent met detectievolgorde.")
    top = df.sort_values("afwijking", ascending=False).head(10).copy()
    top["mtime_dt"] = pd.to_datetime(top["mtime"], unit="s")
    try:
        from IPython.display import display
        display(top[["bestand", "mtime_dt", "afwijking"]])
    except Exception:
        print(top[["bestand", "mtime_dt", "afwijking"]].to_string(index=False))
    return df


# ════════════════════════════════════════════════════════════════════════════
#  6. INTERACTIEF DASHBOARD  (vervangt alle losse HTML/JS-dashboard-cellen)
# ════════════════════════════════════════════════════════════════════════════
def dashboard():
    if not _IN_COLAB:
        print("[!] Dashboard vereist Google Colab."); return
    from IPython.display import display, HTML
    from google.colab import output
    base = mount_drive() or "/content"
    _eng = {"e": None}

    def get_folders():
        items = ["(root)"] + sorted(
            m for m in os.listdir(base) if os.path.isdir(os.path.join(base, m)))
        return json.dumps([{"id": i, "name": m} for i, m in enumerate(items)])

    def run_scan(idx):
        idx = int(idx)
        mappen = sorted(m for m in os.listdir(base) if os.path.isdir(os.path.join(base, m)))
        target = base if idx == 0 else os.path.join(base, mappen[idx - 1])
        e = ForensicEngineV18()
        e.scan_map(target)
        _eng["e"] = e
        return json.dumps(e.bevindingen)

    output.register_callback("get_folders", get_folders)
    output.register_callback("run_scan", run_scan)
    display(HTML("""
<div style="background:#0f172a;color:#e2e8f0;font-family:sans-serif;padding:20px;border-radius:10px">
  <h3 style="color:#38bdf8">Forensisch Dashboard</h3>
  <select id="fs" style="padding:8px;border-radius:4px"></select>
  <button onclick="scan()" style="background:#38bdf8;border:none;padding:8px 20px;border-radius:4px;cursor:pointer">SCAN</button>
  <div id="out" style="margin-top:15px;font-family:monospace;font-size:12px;max-height:400px;overflow:auto"></div>
</div>
<script>
async function init(){const r=await google.colab.kernel.invokeFunction('get_folders',[],{});
 const f=JSON.parse(r.data['application/json']);
 document.getElementById('fs').innerHTML=f.map(x=>`<option value="${x.id}">${x.name}</option>`).join('');}
async function scan(){document.getElementById('out').innerHTML='Scannen...';
 const id=document.getElementById('fs').value;
 const r=await google.colab.kernel.invokeFunction('run_scan',[id],{});
 const d=JSON.parse(r.data['application/json']);
 document.getElementById('out').innerHTML='<b>'+d.length+' bevindingen:</b><br>'+
  d.map(i=>`[${i.bewijswaarde}] ${i.bestand}: ${i.techniek} — ${i.detail.slice(0,120)}`).join('<br>');}
init();
</script>"""))


# ════════════════════════════════════════════════════════════════════════════
#  7. ORKESTRATIE
# ════════════════════════════════════════════════════════════════════════════
def run(map_in=None, kluis="/content/uitvoer/integriteit.json"):
    """Volledige gang: (mount + kies map) → scan → rapport. Geeft het DataFrame terug."""
    if map_in is None:
        map_in = mount_en_kies_map()
    if not map_in or not os.path.isdir(map_in):
        print("[!] Geen geldige invoermap."); return None
    engine = ForensicEngineV18(kluis_pad=kluis)
    engine.scan_map(map_in)
    genereer_rapport(engine)
    globals()["engine"] = engine  # zodat losse cellen `engine` kunnen gebruiken
    if _HAS_PD:
        df = pd.DataFrame(engine.bevindingen)
        try:
            from IPython.display import display
            display(df.groupby("techniek").size().sort_values(ascending=False)
                    .to_frame("aantal"))
        except Exception:
            pass
        return df
    return engine.bevindingen


if __name__ == "__main__":
    # Buiten Colab: python forensic_engine_colab.py <map_in>
    import sys
    doel = sys.argv[1] if len(sys.argv) > 1 else "/content/invoer"
    if os.path.isdir(doel):
        eng = ForensicEngineV18(kluis_pad=os.path.join("uitvoer", "integriteit.json"))
        eng.scan_map(doel)
        genereer_rapport(eng, "uitvoer")
    else:
        print(f"Map niet gevonden: {doel}")
