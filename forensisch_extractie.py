#!/usr/bin/env python3
"""forensisch_extractie.py - Universeel forensisch extractiegereedschap.

Gebruik in de terminal:

    python3 forensisch_extractie.py                    # analyseer huidige map
    python3 forensisch_extractie.py <bestand>          # analyseer een bestand
    python3 forensisch_extractie.py <map>              # analyseer een map (recursief)
    python3 forensisch_extractie.py <pad> <output>     # eigen output-map

Iedere run maakt een nieuwe map aan naast de invoer:

    <invoer>_forensisch_<UTC-tijdstempel>/
        manifest.json           - chain-of-custody logboek (SHA-256 per bestand)
        rapport.txt             - leesbare samenvatting
        extractie/              - alle geextraheerde bestanden, gescheiden per bron

Ondersteunde formaten (stdlib + optionele hulpmodules):

    Structuurdata   : XML, XHTML, JSON, YAML, CSV, TSV, TOML, INI, plist
    Archieven       : ZIP, JAR, TAR, TAR.GZ, TAR.BZ2, TAR.XZ, GZIP, BZIP2, XZ
    Netwerkcapture  : HAR, Proxyman .proxymanlogv2, Charles .dat/.chlsj
    Documenten      : PDF (via PyMuPDF), DOCX, XLSX, PPTX, RTF, HTML
    Communicatie    : EML, MBOX
    Databases       : SQLite (.db, .sqlite, .sqlite3)
    Media/metadata  : PNG/JPEG (EXIF headers), afbeeldingen algemeen
    Fallback        : magic-byte detectie + hex-dump preview van elk onbekend bestand

Forensische waarborgen:

    - SHA-256 van elke invoer en elke uitvoer, vastgelegd in manifest.json
    - ISO-8601 UTC tijdstempels
    - Invoer wordt read-only behandeld (nooit gewijzigd)
    - Geen crash op corrupte invoer: fouten worden geregistreerd als waarschuwingen
    - Alleen Python-stdlib vereist; optionele modules met nette fallback
"""

from __future__ import annotations

# --------------------------------------------------------------------------- #
# BESCHERM STDLIB TEGEN LOKALE SHADOWING
# Als de gebruiker een bestand zoals `string.py`, `email.py`, `csv.py` naast dit
# script of in de huidige map heeft staan, zou dat Python's eigen modules
# schaduwen en elke import breken. Dit MOET vooraan staan, vóór alle andere
# imports, en gebruikt alleen built-in modules (sys/os hebben geen sys.path
# nodig).
# --------------------------------------------------------------------------- #
import sys as _sys
import os as _os

_hier = _os.path.abspath(_os.path.dirname(__file__) if "__file__" in dir() else ".")
_cwd = _os.path.abspath(".")
_sys.path[:] = [p for p in _sys.path if p and _os.path.abspath(p) not in (_hier, _cwd)]
del _sys, _os, _hier, _cwd

import base64
import binascii
import configparser
import csv
import email
import email.policy
import gzip
import hashlib
import io
import json
import mailbox
import os
import platform
import plistlib
import re
import shutil
import sqlite3
import sys
import tarfile
import time
import traceback
import uuid
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, List, Tuple

try:
    import bz2
    HAS_BZ2 = True
except ImportError:
    HAS_BZ2 = False

try:
    import lzma
    HAS_LZMA = True
except ImportError:
    HAS_LZMA = False

try:
    import tomllib
    HAS_TOML = True
except ImportError:
    try:
        import tomli as tomllib
        HAS_TOML = True
    except ImportError:
        HAS_TOML = False

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    import fitz
    HAS_PYMUPDF = True
except ImportError:
    HAS_PYMUPDF = False

try:
    import docx
    HAS_DOCX = True
except ImportError:
    HAS_DOCX = False

try:
    import openpyxl
    HAS_OPENPYXL = True
except ImportError:
    HAS_OPENPYXL = False


HEX_PREVIEW_BYTES = 512
LARGE_FILE_WARN = 256 * 1024 * 1024  # 256 MiB
MAX_RECURSION_DEPTH = 6
TEXT_SAMPLE_BYTES = 65536
BASE64_MIN_LEN = 64
MAGIC_BYTES: list[tuple[bytes, str]] = [
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"BM", "image/bmp"),
    (b"II*\x00", "image/tiff-le"),
    (b"MM\x00*", "image/tiff-be"),
    (b"%PDF-", "application/pdf"),
    (b"PK\x03\x04", "application/zip"),
    (b"PK\x05\x06", "application/zip-empty"),
    (b"Rar!\x1a\x07", "application/x-rar"),
    (b"\x1f\x8b", "application/gzip"),
    (b"BZh", "application/x-bzip2"),
    (b"\xfd7zXZ\x00", "application/x-xz"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
    (b"SQLite format 3\x00", "application/x-sqlite3"),
    (b"OggS", "audio/ogg"),
    (b"ID3", "audio/mpeg"),
    (b"RIFF", "container/riff"),
    (b"\x00\x00\x00\x18ftyp", "video/mp4"),
    (b"\x00\x00\x00\x20ftyp", "video/mp4"),
    (b"{\\rtf", "application/rtf"),
    (b"MZ", "application/x-dosexec"),
    (b"\x7fELF", "application/x-elf"),
    (b"<!DOCTYPE html", "text/html"),
    (b"<html", "text/html"),
    (b"<?xml", "application/xml"),
    (b"bplist00", "application/x-plist-binary"),
]


# --------------------------------------------------------------------------- #
# Datamodel
# --------------------------------------------------------------------------- #


@dataclass
class Uitvoer:
    pad: str
    sha256: str
    grootte: int
    beschrijving: str = ""


@dataclass
class Invoervermelding:
    pad_relatief: str
    pad_absoluut: str
    sha256: str
    grootte: int
    formaat: str
    handler: str
    uitvoeren: list[Uitvoer] = field(default_factory=list)
    waarschuwingen: list[str] = field(default_factory=list)
    fouten: list[str] = field(default_factory=list)


@dataclass
class Manifest:
    sessie_id: str
    tijd_start: str
    tijd_eind: str = ""
    invoer_wortel: str = ""
    uitvoer_wortel: str = ""
    machine: dict = field(default_factory=dict)
    optionele_modules: dict = field(default_factory=dict)
    invoer: list[Invoervermelding] = field(default_factory=list)
    totalen: dict = field(default_factory=dict)

    def naar_dict(self) -> dict:
        return {
            "sessie_id": self.sessie_id,
            "tijd_start_utc": self.tijd_start,
            "tijd_eind_utc": self.tijd_eind,
            "invoer_wortel": self.invoer_wortel,
            "uitvoer_wortel": self.uitvoer_wortel,
            "machine": self.machine,
            "optionele_modules": self.optionele_modules,
            "totalen": self.totalen,
            "invoer": [
                {
                    "pad_relatief": v.pad_relatief,
                    "pad_absoluut": v.pad_absoluut,
                    "sha256": v.sha256,
                    "grootte_bytes": v.grootte,
                    "formaat": v.formaat,
                    "handler": v.handler,
                    "uitvoeren": [
                        {
                            "pad": u.pad,
                            "sha256": u.sha256,
                            "grootte_bytes": u.grootte,
                            "beschrijving": u.beschrijving,
                        }
                        for u in v.uitvoeren
                    ],
                    "waarschuwingen": v.waarschuwingen,
                    "fouten": v.fouten,
                }
                for v in self.invoer
            ],
        }


# --------------------------------------------------------------------------- #
# Hulpfuncties
# --------------------------------------------------------------------------- #


def sha256_bestand(pad: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    grootte = 0
    with pad.open("rb") as f:
        for blok in iter(lambda: f.read(1024 * 1024), b""):
            h.update(blok)
            grootte += len(blok)
    return h.hexdigest(), grootte


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_nu() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def veilige_naam(naam: str, max_len: int = 120) -> str:
    schoon = re.sub(r"[^A-Za-z0-9._\-]+", "_", naam).strip("._")
    if not schoon:
        schoon = "onbekend"
    if len(schoon) > max_len:
        schoon = schoon[:max_len]
    return schoon


def detecteer_formaat(pad: Path, sample: bytes) -> str:
    ext = pad.suffix.lower()
    ext_map = {
        ".xml": "xml", ".xhtml": "xml", ".xsd": "xml", ".xsl": "xml",
        ".json": "json", ".jsonl": "json", ".ndjson": "json",
        ".har": "har",
        ".yaml": "yaml", ".yml": "yaml",
        ".csv": "csv", ".tsv": "csv",
        ".toml": "toml", ".ini": "ini", ".cfg": "ini", ".conf": "ini",
        ".plist": "plist",
        ".zip": "zip", ".jar": "zip", ".war": "zip", ".apk": "zip",
        ".docx": "docx", ".xlsx": "xlsx", ".pptx": "pptx",
        ".tar": "tar", ".tgz": "tar-gz", ".tar.gz": "tar-gz",
        ".tbz2": "tar-bz2", ".tar.bz2": "tar-bz2",
        ".txz": "tar-xz", ".tar.xz": "tar-xz",
        ".gz": "gzip", ".bz2": "bzip2", ".xz": "xz",
        ".proxymanlogv2": "proxyman",
        ".chlsj": "charles-json", ".dat": "charles-dat",
        ".pdf": "pdf",
        ".rtf": "rtf",
        ".html": "html", ".htm": "html",
        ".eml": "eml", ".mbox": "mbox",
        ".db": "sqlite", ".sqlite": "sqlite", ".sqlite3": "sqlite",
        ".txt": "text", ".log": "text", ".md": "text",
        ".png": "image", ".jpg": "image", ".jpeg": "image", ".gif": "image",
        ".bmp": "image", ".tiff": "image", ".webp": "image",
    }
    if pad.name.lower().endswith(".tar.gz"):
        return "tar-gz"
    if pad.name.lower().endswith(".tar.bz2"):
        return "tar-bz2"
    if pad.name.lower().endswith(".tar.xz"):
        return "tar-xz"
    if ext in ext_map:
        return ext_map[ext]

    for magic, naam in MAGIC_BYTES:
        if sample.startswith(magic):
            if naam == "application/pdf":
                return "pdf"
            if naam == "application/zip":
                return "zip"
            if naam == "application/gzip":
                return "gzip"
            if naam == "application/x-bzip2":
                return "bzip2"
            if naam == "application/x-xz":
                return "xz"
            if naam == "application/x-sqlite3":
                return "sqlite"
            if naam.startswith("image/"):
                return "image"
            if naam in ("text/html",):
                return "html"
            if naam == "application/xml":
                return "xml"
            if naam == "application/rtf":
                return "rtf"
            if naam == "application/x-plist-binary":
                return "plist"

    if is_waarschijnlijk_tekst(sample):
        return "text"
    return "binair"


def is_waarschijnlijk_tekst(sample: bytes) -> bool:
    if not sample:
        return True
    if b"\x00" in sample[:4096]:
        return False
    afdrukbaar = sum(1 for b in sample[:4096] if 32 <= b < 127 or b in (9, 10, 13))
    return afdrukbaar / min(len(sample), 4096) > 0.85


def maak_output_map(basis: Path, invoer: Path) -> Path:
    tijdstempel = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    naam = veilige_naam(invoer.name or "map")
    doel = basis / f"{naam}_forensisch_{tijdstempel}"
    doel.mkdir(parents=True, exist_ok=False)
    (doel / "extractie").mkdir()
    return doel


def schrijf_uitvoer(basis: Path, relatief: str, inhoud: bytes | str,
                    beschrijving: str = "") -> Uitvoer:
    doelpad = basis / relatief
    doelpad.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(inhoud, str):
        data = inhoud.encode("utf-8")
    else:
        data = inhoud
    doelpad.write_bytes(data)
    return Uitvoer(
        pad=str(doelpad.relative_to(basis.parent)) if basis.parent in doelpad.parents else str(doelpad),
        sha256=sha256_bytes(data),
        grootte=len(data),
        beschrijving=beschrijving,
    )


# --------------------------------------------------------------------------- #
# XML → JSON (uit oorspronkelijk script, verhard tegen crashes)
# --------------------------------------------------------------------------- #


def xml_naar_dict(element: ET.Element) -> Any:
    tag = element.tag.split("}")[-1]
    data: dict[str, Any] = {}
    if element.attrib:
        data[f"@{tag}_attributen"] = dict(element.attrib)
    if element.text and element.text.strip():
        data["waarde"] = element.text.strip()
    for kind in element:
        kind_data = xml_naar_dict(kind)
        kind_tag = kind.tag.split("}")[-1]
        if kind_tag in data:
            if isinstance(data[kind_tag], list):
                data[kind_tag].append(kind_data)
            else:
                data[kind_tag] = [data[kind_tag], kind_data]
        else:
            data[kind_tag] = kind_data
    if data:
        return data
    if element.text and element.text.strip():
        return element.text.strip()
    return None


# --------------------------------------------------------------------------- #
# Handlers
# --------------------------------------------------------------------------- #


HandlerResult = Tuple[List[Uitvoer], List[str]]
Handler = Callable[[Path, Path, int], HandlerResult]


def handler_xml(bron: Path, doel: Path, diepte: int) -> HandlerResult:
    uitvoer: list[Uitvoer] = []
    waarschuwingen: list[str] = []
    try:
        boom = ET.parse(str(bron))
        data = xml_naar_dict(boom.getroot())
        payload = json.dumps(data, indent=4, ensure_ascii=False)
        uitvoer.append(schrijf_uitvoer(
            doel, f"{veilige_naam(bron.stem)}_blootgelegd.json",
            payload, "XML omgezet naar JSON",
        ))
    except ET.ParseError as exc:
        waarschuwingen.append(f"XML parse fout: {exc}")
        uitvoer.extend(_bewaar_ruw(bron, doel, "onparseerbare_xml"))
    return uitvoer, waarschuwingen


def handler_json(bron: Path, doel: Path, diepte: int) -> HandlerResult:
    uitvoer: list[Uitvoer] = []
    waarschuwingen: list[str] = []
    try:
        tekst = bron.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], [f"Kon bestand niet lezen: {exc}"]

    if bron.suffix.lower() in (".jsonl", ".ndjson"):
        regels = []
        for i, r in enumerate(tekst.splitlines()):
            if not r.strip():
                continue
            try:
                regels.append(json.loads(r))
            except json.JSONDecodeError as exc:
                waarschuwingen.append(f"regel {i + 1}: {exc}")
        payload = json.dumps(regels, indent=2, ensure_ascii=False)
        uitvoer.append(schrijf_uitvoer(
            doel, f"{veilige_naam(bron.stem)}_regels.json", payload,
            f"JSON-Lines: {len(regels)} records",
        ))
    else:
        try:
            data = json.loads(tekst)
            payload = json.dumps(data, indent=2, ensure_ascii=False)
            uitvoer.append(schrijf_uitvoer(
                doel, f"{veilige_naam(bron.stem)}_geformatteerd.json",
                payload, "JSON hergeformatteerd",
            ))
        except json.JSONDecodeError as exc:
            waarschuwingen.append(f"JSON parse fout: {exc}")
            uitvoer.extend(_bewaar_ruw(bron, doel, "onparseerbare_json"))
    return uitvoer, waarschuwingen


def handler_har(bron: Path, doel: Path, diepte: int) -> HandlerResult:
    uitvoer: list[Uitvoer] = []
    waarschuwingen: list[str] = []
    try:
        data = json.loads(bron.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        return [], [f"HAR laden mislukt: {exc}"]

    entries = data.get("log", {}).get("entries", []) if isinstance(data, dict) else []
    if not entries:
        waarschuwingen.append("HAR bevat geen entries")
        return uitvoer, waarschuwingen

    for i, entry in enumerate(entries):
        try:
            req = entry.get("request", {})
            resp = entry.get("response", {})
            url = req.get("url", "geen-url")
            method = req.get("method", "?")
            veilige_url = veilige_naam(url.replace("://", "_"), max_len=80)
            sub = f"har/{i:05d}_{method}_{veilige_url}"

            samenvatting = {
                "url": url,
                "method": method,
                "status": resp.get("status"),
                "statusText": resp.get("statusText"),
                "startedDateTime": entry.get("startedDateTime"),
                "time_ms": entry.get("time"),
                "request_headers": req.get("headers", []),
                "response_headers": resp.get("headers", []),
            }
            uitvoer.append(schrijf_uitvoer(
                doel, f"{sub}/samenvatting.json",
                json.dumps(samenvatting, indent=2, ensure_ascii=False),
                f"HAR entry {i}",
            ))

            req_body = req.get("postData", {}).get("text")
            if req_body:
                uitvoer.append(schrijf_uitvoer(
                    doel, f"{sub}/request_body.txt", req_body,
                    "HAR request body",
                ))

            content = resp.get("content", {})
            body = content.get("text")
            if body:
                if content.get("encoding") == "base64":
                    try:
                        decoded = base64.b64decode(body)
                        uitvoer.append(schrijf_uitvoer(
                            doel, f"{sub}/response_body.bin", decoded,
                            f"HAR response body ({content.get('mimeType')})",
                        ))
                    except binascii.Error:
                        uitvoer.append(schrijf_uitvoer(
                            doel, f"{sub}/response_body.base64", body,
                            "HAR response body (base64 kon niet decoderen)",
                        ))
                else:
                    uitvoer.append(schrijf_uitvoer(
                        doel, f"{sub}/response_body.txt", body,
                        f"HAR response body ({content.get('mimeType')})",
                    ))
        except Exception as exc:
            waarschuwingen.append(f"HAR entry {i}: {exc}")
    return uitvoer, waarschuwingen


def handler_zip(bron: Path, doel: Path, diepte: int) -> HandlerResult:
    uitvoer: list[Uitvoer] = []
    waarschuwingen: list[str] = []
    try:
        with zipfile.ZipFile(bron, "r") as zf:
            uit_root = doel / f"zip/{veilige_naam(bron.stem)}"
            uit_root.mkdir(parents=True, exist_ok=True)
            for info in zf.infolist():
                if info.is_dir():
                    continue
                intern_naam = _veilig_extract_pad(info.filename)
                if intern_naam is None:
                    waarschuwingen.append(f"onveilig pad overgeslagen: {info.filename}")
                    continue
                doelbestand = uit_root / intern_naam
                doelbestand.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with zf.open(info) as bron_f, doelbestand.open("wb") as doel_f:
                        shutil.copyfileobj(bron_f, doel_f)
                    sha, groo = sha256_bestand(doelbestand)
                    uitvoer.append(Uitvoer(
                        pad=str(doelbestand),
                        sha256=sha,
                        grootte=groo,
                        beschrijving=f"uit ZIP: {info.filename}",
                    ))
                except Exception as exc:
                    waarschuwingen.append(f"ZIP-lid {info.filename}: {exc}")
    except zipfile.BadZipFile as exc:
        return [], [f"Corrupte ZIP: {exc}"]
    return uitvoer, waarschuwingen


def handler_tar(bron: Path, doel: Path, diepte: int, mode: str) -> HandlerResult:
    uitvoer: list[Uitvoer] = []
    waarschuwingen: list[str] = []
    try:
        with tarfile.open(str(bron), mode) as tf:
            uit_root = doel / f"tar/{veilige_naam(bron.stem)}"
            uit_root.mkdir(parents=True, exist_ok=True)
            for lid in tf.getmembers():
                if not lid.isfile():
                    continue
                intern_naam = _veilig_extract_pad(lid.name)
                if intern_naam is None:
                    waarschuwingen.append(f"onveilig pad overgeslagen: {lid.name}")
                    continue
                doelbestand = uit_root / intern_naam
                doelbestand.parent.mkdir(parents=True, exist_ok=True)
                try:
                    f = tf.extractfile(lid)
                    if f is None:
                        continue
                    with doelbestand.open("wb") as out:
                        shutil.copyfileobj(f, out)
                    sha, groo = sha256_bestand(doelbestand)
                    uitvoer.append(Uitvoer(
                        pad=str(doelbestand),
                        sha256=sha,
                        grootte=groo,
                        beschrijving=f"uit TAR: {lid.name}",
                    ))
                except Exception as exc:
                    waarschuwingen.append(f"TAR-lid {lid.name}: {exc}")
    except tarfile.TarError as exc:
        return [], [f"Corrupte TAR: {exc}"]
    return uitvoer, waarschuwingen


def handler_gzip(bron: Path, doel: Path, diepte: int) -> HandlerResult:
    uitvoer: list[Uitvoer] = []
    waarschuwingen: list[str] = []
    try:
        with gzip.open(bron, "rb") as f:
            data = f.read()
        naam = bron.stem or "uitgepakt"
        uitv = schrijf_uitvoer(doel, f"gzip/{veilige_naam(naam)}", data,
                               f"gedecomprimeerd uit {bron.name}")
        uitvoer.append(uitv)
    except (OSError, EOFError) as exc:
        waarschuwingen.append(f"GZIP fout: {exc}")
    return uitvoer, waarschuwingen


def handler_bzip2(bron: Path, doel: Path, diepte: int) -> HandlerResult:
    if not HAS_BZ2:
        return [], ["bz2 module niet beschikbaar in deze Python"]
    uitvoer: list[Uitvoer] = []
    waarschuwingen: list[str] = []
    try:
        with bz2.open(bron, "rb") as f:
            data = f.read()
        naam = bron.stem or "uitgepakt"
        uitvoer.append(schrijf_uitvoer(doel, f"bzip2/{veilige_naam(naam)}", data,
                                       f"gedecomprimeerd uit {bron.name}"))
    except (OSError, EOFError) as exc:
        waarschuwingen.append(f"BZIP2 fout: {exc}")
    return uitvoer, waarschuwingen


def handler_xz(bron: Path, doel: Path, diepte: int) -> HandlerResult:
    if not HAS_LZMA:
        return [], ["lzma module niet beschikbaar"]
    uitvoer: list[Uitvoer] = []
    waarschuwingen: list[str] = []
    try:
        with lzma.open(bron, "rb") as f:
            data = f.read()
        naam = bron.stem or "uitgepakt"
        uitvoer.append(schrijf_uitvoer(doel, f"xz/{veilige_naam(naam)}", data,
                                       f"gedecomprimeerd uit {bron.name}"))
    except (OSError, EOFError, lzma.LZMAError) as exc:
        waarschuwingen.append(f"XZ fout: {exc}")
    return uitvoer, waarschuwingen


def handler_pdf(bron: Path, doel: Path, diepte: int) -> HandlerResult:
    uitvoer: list[Uitvoer] = []
    waarschuwingen: list[str] = []
    if not HAS_PYMUPDF:
        waarschuwingen.append("PyMuPDF niet geinstalleerd; PDF wordt niet ge-parsed. "
                              "Installeer met: pip install PyMuPDF")
        uitvoer.extend(_bewaar_ruw(bron, doel, "pdf_ongeparsed"))
        return uitvoer, waarschuwingen
    try:
        pdf = fitz.open(str(bron))
    except Exception as exc:
        return [], [f"PDF openen mislukt: {exc}"]
    try:
        tekst_stukken = []
        for pnr, pagina in enumerate(pdf):
            try:
                tekst = pagina.get_text("text")
                tekst_stukken.append(f"=== Pagina {pnr + 1} ===\n{tekst}\n")
            except Exception as exc:
                waarschuwingen.append(f"pagina {pnr + 1} tekst: {exc}")
        uitvoer.append(schrijf_uitvoer(
            doel, f"pdf/{veilige_naam(bron.stem)}/tekst.txt",
            "\n".join(tekst_stukken), "PDF tekst",
        ))
        metadata = pdf.metadata or {}
        uitvoer.append(schrijf_uitvoer(
            doel, f"pdf/{veilige_naam(bron.stem)}/metadata.json",
            json.dumps(metadata, indent=2, ensure_ascii=False),
            "PDF metadata",
        ))
        for i in range(pdf.embfile_count()):
            try:
                info = pdf.embfile_info(i)
                bestand_bytes = pdf.embfile_get(i)
                naam = veilige_naam(info.get("filename", f"embed_{i}"))
                sub = f"pdf/{veilige_naam(bron.stem)}/embedded/{i:03d}_{naam}"
                uitvoer.append(schrijf_uitvoer(doel, sub, bestand_bytes,
                                               "PDF ingebedde bijlage"))
            except Exception as exc:
                waarschuwingen.append(f"embedded {i}: {exc}")
    finally:
        pdf.close()
    return uitvoer, waarschuwingen


def handler_docx(bron: Path, doel: Path, diepte: int) -> HandlerResult:
    uitvoer: list[Uitvoer] = []
    waarschuwingen: list[str] = []
    if HAS_DOCX:
        try:
            doc = docx.Document(str(bron))
            tekst = "\n".join(p.text for p in doc.paragraphs)
            uitvoer.append(schrijf_uitvoer(
                doel, f"docx/{veilige_naam(bron.stem)}/tekst.txt",
                tekst, "DOCX tekst",
            ))
            props = doc.core_properties
            meta = {
                "title": props.title, "author": props.author,
                "subject": props.subject, "created": str(props.created),
                "modified": str(props.modified),
                "last_modified_by": props.last_modified_by,
                "revision": props.revision, "version": props.version,
            }
            uitvoer.append(schrijf_uitvoer(
                doel, f"docx/{veilige_naam(bron.stem)}/metadata.json",
                json.dumps(meta, indent=2, ensure_ascii=False, default=str),
                "DOCX metadata",
            ))
        except Exception as exc:
            waarschuwingen.append(f"python-docx fout: {exc}; val terug op ZIP-uitpakken")
    # DOCX is een ZIP - altijd de ruwe XML ontsluiten
    zip_out, zip_warn = handler_zip(bron, doel, diepte)
    uitvoer.extend(zip_out)
    waarschuwingen.extend(zip_warn)
    return uitvoer, waarschuwingen


def handler_xlsx(bron: Path, doel: Path, diepte: int) -> HandlerResult:
    uitvoer: list[Uitvoer] = []
    waarschuwingen: list[str] = []
    if HAS_OPENPYXL:
        try:
            wb = openpyxl.load_workbook(str(bron), data_only=False, read_only=True)
            for blad_naam in wb.sheetnames:
                blad = wb[blad_naam]
                buffer = io.StringIO()
                schrijver = csv.writer(buffer)
                for rij in blad.iter_rows(values_only=True):
                    schrijver.writerow(["" if c is None else c for c in rij])
                uitvoer.append(schrijf_uitvoer(
                    doel,
                    f"xlsx/{veilige_naam(bron.stem)}/{veilige_naam(blad_naam)}.csv",
                    buffer.getvalue(), f"XLSX blad: {blad_naam}",
                ))
        except Exception as exc:
            waarschuwingen.append(f"openpyxl fout: {exc}; val terug op ZIP-uitpakken")
    zip_out, zip_warn = handler_zip(bron, doel, diepte)
    uitvoer.extend(zip_out)
    waarschuwingen.extend(zip_warn)
    return uitvoer, waarschuwingen


def handler_csv(bron: Path, doel: Path, diepte: int) -> HandlerResult:
    uitvoer: list[Uitvoer] = []
    waarschuwingen: list[str] = []
    try:
        tekst = bron.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], [f"Kon niet lezen: {exc}"]
    scheider = "\t" if bron.suffix.lower() == ".tsv" else ","
    try:
        rijen = list(csv.DictReader(io.StringIO(tekst), delimiter=scheider))
        uitvoer.append(schrijf_uitvoer(
            doel, f"{veilige_naam(bron.stem)}_rijen.json",
            json.dumps(rijen, indent=2, ensure_ascii=False),
            f"CSV: {len(rijen)} rijen",
        ))
    except csv.Error as exc:
        waarschuwingen.append(f"CSV parse fout: {exc}")
        uitvoer.extend(_bewaar_ruw(bron, doel, "onparseerbare_csv"))
    return uitvoer, waarschuwingen


def handler_yaml(bron: Path, doel: Path, diepte: int) -> HandlerResult:
    if not HAS_YAML:
        return _bewaar_ruw(bron, doel, "yaml_ongeparsed"), \
               ["PyYAML niet beschikbaar; installeer met: pip install PyYAML"]
    try:
        with bron.open("rb") as f:
            data = list(yaml.safe_load_all(f))
        payload = data[0] if len(data) == 1 else data
        return [schrijf_uitvoer(
            doel, f"{veilige_naam(bron.stem)}_yaml.json",
            json.dumps(payload, indent=2, ensure_ascii=False, default=str),
            "YAML omgezet naar JSON",
        )], []
    except yaml.YAMLError as exc:
        return _bewaar_ruw(bron, doel, "onparseerbare_yaml"), [f"YAML fout: {exc}"]


def handler_toml(bron: Path, doel: Path, diepte: int) -> HandlerResult:
    if not HAS_TOML:
        return _bewaar_ruw(bron, doel, "toml_ongeparsed"), \
               ["tomllib/tomli niet beschikbaar (Python < 3.11 vereist tomli)"]
    try:
        with bron.open("rb") as f:
            data = tomllib.load(f)
        return [schrijf_uitvoer(
            doel, f"{veilige_naam(bron.stem)}_toml.json",
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            "TOML omgezet naar JSON",
        )], []
    except tomllib.TOMLDecodeError as exc:
        return _bewaar_ruw(bron, doel, "onparseerbare_toml"), [f"TOML fout: {exc}"]


def handler_ini(bron: Path, doel: Path, diepte: int) -> HandlerResult:
    parser = configparser.ConfigParser()
    try:
        parser.read(str(bron), encoding="utf-8")
    except configparser.Error as exc:
        return _bewaar_ruw(bron, doel, "onparseerbare_ini"), [f"INI fout: {exc}"]
    data = {sec: dict(parser.items(sec)) for sec in parser.sections()}
    return [schrijf_uitvoer(
        doel, f"{veilige_naam(bron.stem)}_ini.json",
        json.dumps(data, indent=2, ensure_ascii=False),
        "INI omgezet naar JSON",
    )], []


def handler_plist(bron: Path, doel: Path, diepte: int) -> HandlerResult:
    try:
        with bron.open("rb") as f:
            data = plistlib.load(f)
        return [schrijf_uitvoer(
            doel, f"{veilige_naam(bron.stem)}_plist.json",
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            "plist omgezet naar JSON",
        )], []
    except (plistlib.InvalidFileException, ValueError) as exc:
        return _bewaar_ruw(bron, doel, "onparseerbare_plist"), [f"plist fout: {exc}"]


def handler_html(bron: Path, doel: Path, diepte: int) -> HandlerResult:
    uitvoer: list[Uitvoer] = []
    try:
        tekst = bron.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], [f"Kon niet lezen: {exc}"]
    kaal = re.sub(r"<script.*?</script>", "", tekst, flags=re.DOTALL | re.I)
    kaal = re.sub(r"<style.*?</style>", "", kaal, flags=re.DOTALL | re.I)
    kaal = re.sub(r"<[^>]+>", " ", kaal)
    kaal = re.sub(r"\s+", " ", kaal).strip()
    uitvoer.append(schrijf_uitvoer(
        doel, f"html/{veilige_naam(bron.stem)}/tekst.txt", kaal,
        "HTML zichtbare tekst",
    ))
    links = re.findall(r'href=[\'"]([^\'"]+)[\'"]', tekst, flags=re.I)
    scripts = re.findall(r'src=[\'"]([^\'"]+)[\'"]', tekst, flags=re.I)
    forms = re.findall(r'<form[^>]*action=[\'"]([^\'"]+)[\'"]', tekst, flags=re.I)
    uitvoer.append(schrijf_uitvoer(
        doel, f"html/{veilige_naam(bron.stem)}/artefacten.json",
        json.dumps({"links": links, "scripts": scripts, "forms": forms},
                   indent=2, ensure_ascii=False),
        "HTML artefacten",
    ))
    return uitvoer, []


def handler_eml(bron: Path, doel: Path, diepte: int) -> HandlerResult:
    uitvoer: list[Uitvoer] = []
    waarschuwingen: list[str] = []
    try:
        with bron.open("rb") as f:
            msg = email.message_from_binary_file(f, policy=email.policy.default)
    except Exception as exc:
        return [], [f"EML fout: {exc}"]

    headers = {k: str(v) for k, v in msg.items()}
    sub = f"eml/{veilige_naam(bron.stem)}"
    uitvoer.append(schrijf_uitvoer(
        doel, f"{sub}/headers.json",
        json.dumps(headers, indent=2, ensure_ascii=False),
        "EML headers",
    ))
    body_stukken = []
    for i, deel in enumerate(msg.walk()):
        if deel.is_multipart():
            continue
        try:
            payload = deel.get_content()
        except Exception as exc:
            waarschuwingen.append(f"onderdeel {i}: {exc}")
            continue
        naam = deel.get_filename()
        ctype = deel.get_content_type()
        if naam:
            if isinstance(payload, str):
                payload_b = payload.encode("utf-8")
            else:
                payload_b = payload
            uitvoer.append(schrijf_uitvoer(
                doel, f"{sub}/bijlagen/{i:03d}_{veilige_naam(naam)}",
                payload_b, f"EML bijlage ({ctype})",
            ))
        else:
            if isinstance(payload, bytes):
                payload = payload.decode("utf-8", errors="replace")
            body_stukken.append(f"=== deel {i} ({ctype}) ===\n{payload}\n")
    if body_stukken:
        uitvoer.append(schrijf_uitvoer(
            doel, f"{sub}/body.txt", "\n".join(body_stukken), "EML body",
        ))
    return uitvoer, waarschuwingen


def handler_mbox(bron: Path, doel: Path, diepte: int) -> HandlerResult:
    uitvoer: list[Uitvoer] = []
    waarschuwingen: list[str] = []
    try:
        mb = mailbox.mbox(str(bron))
    except Exception as exc:
        return [], [f"mbox openen mislukt: {exc}"]
    sub = f"mbox/{veilige_naam(bron.stem)}"
    for i, msg in enumerate(mb):
        try:
            headers = {k: str(v) for k, v in msg.items()}
            uitvoer.append(schrijf_uitvoer(
                doel, f"{sub}/{i:05d}_headers.json",
                json.dumps(headers, indent=2, ensure_ascii=False),
                f"mbox bericht {i} headers",
            ))
            payload = msg.get_payload()
            if isinstance(payload, list):
                payload = "\n".join(str(p) for p in payload)
            uitvoer.append(schrijf_uitvoer(
                doel, f"{sub}/{i:05d}_body.txt",
                str(payload), f"mbox bericht {i} body",
            ))
        except Exception as exc:
            waarschuwingen.append(f"bericht {i}: {exc}")
    return uitvoer, waarschuwingen


def handler_sqlite(bron: Path, doel: Path, diepte: int) -> HandlerResult:
    uitvoer: list[Uitvoer] = []
    waarschuwingen: list[str] = []
    try:
        conn = sqlite3.connect(f"file:{bron}?mode=ro", uri=True)
        cur = conn.cursor()
    except sqlite3.Error as exc:
        return [], [f"SQLite openen mislukt: {exc}"]
    try:
        sub = f"sqlite/{veilige_naam(bron.stem)}"
        cur.execute("SELECT name, type, sql FROM sqlite_master")
        schema = [{"name": n, "type": t, "sql": s} for n, t, s in cur.fetchall()]
        uitvoer.append(schrijf_uitvoer(
            doel, f"{sub}/schema.json",
            json.dumps(schema, indent=2, ensure_ascii=False),
            "SQLite schema",
        ))
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        for (tabel,) in cur.fetchall():
            try:
                cur.execute(f'SELECT * FROM "{tabel}"')
                kolommen = [d[0] for d in cur.description]
                buffer = io.StringIO()
                schrijver = csv.writer(buffer)
                schrijver.writerow(kolommen)
                for rij in cur.fetchall():
                    schrijver.writerow(["" if c is None else c for c in rij])
                uitvoer.append(schrijf_uitvoer(
                    doel, f"{sub}/tabel_{veilige_naam(tabel)}.csv",
                    buffer.getvalue(), f"SQLite tabel: {tabel}",
                ))
            except sqlite3.Error as exc:
                waarschuwingen.append(f"tabel {tabel}: {exc}")
    finally:
        conn.close()
    return uitvoer, waarschuwingen


def handler_tekst(bron: Path, doel: Path, diepte: int) -> HandlerResult:
    uitvoer: list[Uitvoer] = []
    waarschuwingen: list[str] = []
    try:
        tekst = bron.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], [f"Kon niet lezen: {exc}"]
    uitvoer.extend(_bewaar_ruw(bron, doel, "tekst"))
    # zoek naar mogelijke base64-blobs
    kandidaten = re.findall(r"[A-Za-z0-9+/]{%d,}={0,2}" % BASE64_MIN_LEN, tekst)
    voor_dump = kandidaten[:20]  # cap
    for i, blob in enumerate(voor_dump):
        try:
            data = base64.b64decode(blob, validate=True)
        except binascii.Error:
            continue
        if is_waarschijnlijk_tekst(data[:1024]):
            uitvoer.append(schrijf_uitvoer(
                doel, f"tekst/{veilige_naam(bron.stem)}/base64_{i:03d}.txt",
                data.decode("utf-8", errors="replace"),
                "gedecodeerde base64 blob (tekst)",
            ))
        else:
            uitvoer.append(schrijf_uitvoer(
                doel, f"tekst/{veilige_naam(bron.stem)}/base64_{i:03d}.bin",
                data, "gedecodeerde base64 blob (binair)",
            ))
    if len(kandidaten) > len(voor_dump):
        waarschuwingen.append(
            f"{len(kandidaten) - len(voor_dump)} extra base64-kandidaten overgeslagen "
            "(limiet: 20)"
        )
    return uitvoer, waarschuwingen


def handler_binair(bron: Path, doel: Path, diepte: int) -> HandlerResult:
    uitvoer: list[Uitvoer] = []
    waarschuwingen: list[str] = []
    try:
        with bron.open("rb") as f:
            kop = f.read(HEX_PREVIEW_BYTES)
    except OSError as exc:
        return [], [f"Kon niet lezen: {exc}"]
    magic = "onbekend"
    for m, naam in MAGIC_BYTES:
        if kop.startswith(m):
            magic = naam
            break
    hex_regels = []
    for i in range(0, len(kop), 16):
        blok = kop[i:i + 16]
        hex_str = " ".join(f"{b:02x}" for b in blok)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in blok)
        hex_regels.append(f"{i:08x}  {hex_str:<47}  {ascii_str}")
    beschrijving = (
        f"binair bestand ({magic}), grootte {bron.stat().st_size} bytes\n"
        f"eerste {len(kop)} bytes:\n\n" + "\n".join(hex_regels)
    )
    uitvoer.append(schrijf_uitvoer(
        doel, f"binair/{veilige_naam(bron.stem)}_preview.txt",
        beschrijving, "hex-preview van binair bestand",
    ))
    uitvoer.extend(_bewaar_ruw(bron, doel, "binair"))
    return uitvoer, waarschuwingen


def handler_afbeelding(bron: Path, doel: Path, diepte: int) -> HandlerResult:
    # kopieer bit-for-bit + registreer hash; verdergaande EXIF-parsing zou
    # third-party libs vereisen die niet gegarandeerd aanwezig zijn.
    return _bewaar_ruw(bron, doel, "afbeelding"), []


def handler_proxyman(bron: Path, doel: Path, diepte: int) -> HandlerResult:
    """Proxyman .proxymanlogv2 archieven zijn ZIPs met JSON-transacties."""
    return handler_zip(bron, doel, diepte)


# --------------------------------------------------------------------------- #
# Hulpfuncties handlers
# --------------------------------------------------------------------------- #


def _veilig_extract_pad(intern: str) -> str | None:
    """Blokkeer path traversal (zip slip)."""
    p = Path(intern)
    if p.is_absolute():
        return None
    delen = p.parts
    if any(d == ".." for d in delen):
        return None
    return str(p)


def _bewaar_ruw(bron: Path, doel: Path, categorie: str) -> list[Uitvoer]:
    """Kopieer het originele bestand door voor bewijsbehoud."""
    doelbestand = doel / categorie / veilige_naam(bron.name)
    doelbestand.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(bron), str(doelbestand))
    sha, groo = sha256_bestand(doelbestand)
    return [Uitvoer(
        pad=str(doelbestand),
        sha256=sha,
        grootte=groo,
        beschrijving=f"kopie van origineel ({categorie})",
    )]


# --------------------------------------------------------------------------- #
# Router
# --------------------------------------------------------------------------- #


HANDLERS: dict[str, tuple[str, Callable]] = {
    "xml": ("handler_xml", handler_xml),
    "json": ("handler_json", handler_json),
    "har": ("handler_har", handler_har),
    "yaml": ("handler_yaml", handler_yaml),
    "toml": ("handler_toml", handler_toml),
    "ini": ("handler_ini", handler_ini),
    "plist": ("handler_plist", handler_plist),
    "csv": ("handler_csv", handler_csv),
    "zip": ("handler_zip", handler_zip),
    "docx": ("handler_docx", handler_docx),
    "xlsx": ("handler_xlsx", handler_xlsx),
    "pptx": ("handler_docx", handler_docx),  # pptx is ook een ZIP met XML
    "tar": ("handler_tar", lambda b, d, k: handler_tar(b, d, k, "r:")),
    "tar-gz": ("handler_tar_gz", lambda b, d, k: handler_tar(b, d, k, "r:gz")),
    "tar-bz2": ("handler_tar_bz2", lambda b, d, k: handler_tar(b, d, k, "r:bz2")),
    "tar-xz": ("handler_tar_xz", lambda b, d, k: handler_tar(b, d, k, "r:xz")),
    "gzip": ("handler_gzip", handler_gzip),
    "bzip2": ("handler_bzip2", handler_bzip2),
    "xz": ("handler_xz", handler_xz),
    "pdf": ("handler_pdf", handler_pdf),
    "html": ("handler_html", handler_html),
    "eml": ("handler_eml", handler_eml),
    "mbox": ("handler_mbox", handler_mbox),
    "sqlite": ("handler_sqlite", handler_sqlite),
    "text": ("handler_tekst", handler_tekst),
    "image": ("handler_afbeelding", handler_afbeelding),
    "proxyman": ("handler_proxyman", handler_proxyman),
    "charles-json": ("handler_json", handler_json),
    "charles-dat": ("handler_json", handler_json),
    "rtf": ("handler_tekst", handler_tekst),
    "binair": ("handler_binair", handler_binair),
}


def analyseer_bestand(bron: Path, doel: Path, invoer_wortel: Path,
                      diepte: int = 0) -> Invoervermelding:
    try:
        sha, grootte = sha256_bestand(bron)
    except OSError as exc:
        vermelding = Invoervermelding(
            pad_relatief=_relatief(bron, invoer_wortel),
            pad_absoluut=str(bron.resolve()),
            sha256="", grootte=0, formaat="ontoegankelijk",
            handler="geen",
            fouten=[f"Kon SHA-256 niet berekenen: {exc}"],
        )
        return vermelding

    try:
        with bron.open("rb") as f:
            sample = f.read(TEXT_SAMPLE_BYTES)
    except OSError as exc:
        return Invoervermelding(
            pad_relatief=_relatief(bron, invoer_wortel),
            pad_absoluut=str(bron.resolve()),
            sha256=sha, grootte=grootte, formaat="ontoegankelijk",
            handler="geen", fouten=[f"Kon sample niet lezen: {exc}"],
        )

    formaat = detecteer_formaat(bron, sample)
    handler_naam, handler_fn = HANDLERS.get(formaat, ("handler_binair", handler_binair))
    vermelding = Invoervermelding(
        pad_relatief=_relatief(bron, invoer_wortel),
        pad_absoluut=str(bron.resolve()),
        sha256=sha,
        grootte=grootte,
        formaat=formaat,
        handler=handler_naam,
    )
    if grootte > LARGE_FILE_WARN:
        vermelding.waarschuwingen.append(
            f"groot bestand ({grootte} bytes) - verwerking kan traag zijn"
        )
    if diepte > MAX_RECURSION_DEPTH:
        vermelding.waarschuwingen.append(
            f"maximum recursiediepte {MAX_RECURSION_DEPTH} bereikt; overslaan"
        )
        return vermelding

    try:
        uitvoer, warns = handler_fn(bron, doel / "extractie", diepte)
        vermelding.uitvoeren.extend(uitvoer)
        vermelding.waarschuwingen.extend(warns)
    except Exception:
        spoor = traceback.format_exc(limit=8)
        vermelding.fouten.append(f"handler crashte:\n{spoor}")
    return vermelding


def _relatief(pad: Path, wortel: Path) -> str:
    try:
        return str(pad.resolve().relative_to(wortel.resolve()))
    except ValueError:
        return str(pad.resolve())


def loop_invoer(invoer: Path) -> Iterable[Path]:
    if invoer.is_file():
        yield invoer
        return
    for pad in sorted(invoer.rglob("*")):
        if pad.is_file():
            yield pad


# --------------------------------------------------------------------------- #
# Rapport
# --------------------------------------------------------------------------- #


def schrijf_rapport(manifest: Manifest, doel: Path) -> None:
    regels = [
        "=" * 78,
        "FORENSISCH EXTRACTIERAPPORT",
        "=" * 78,
        f"Sessie:        {manifest.sessie_id}",
        f"Start (UTC):   {manifest.tijd_start}",
        f"Eind  (UTC):   {manifest.tijd_eind}",
        f"Invoer:        {manifest.invoer_wortel}",
        f"Uitvoer:       {manifest.uitvoer_wortel}",
        f"Python:        {manifest.machine.get('python_versie')}",
        f"Systeem:       {manifest.machine.get('platform')}",
        "",
        "Optionele modules:",
    ]
    for mod, aanwezig in manifest.optionele_modules.items():
        regels.append(f"  {mod:<14} {'JA' if aanwezig else 'NEE'}")
    regels.append("")
    regels.append(f"Totaal invoerbestanden : {manifest.totalen.get('invoer', 0)}")
    regels.append(f"Totaal uitvoerbestanden: {manifest.totalen.get('uitvoer', 0)}")
    regels.append(f"Waarschuwingen         : {manifest.totalen.get('waarschuwingen', 0)}")
    regels.append(f"Fouten                 : {manifest.totalen.get('fouten', 0)}")
    regels.append("")
    regels.append("-" * 78)
    regels.append("PER BESTAND")
    regels.append("-" * 78)
    for v in manifest.invoer:
        regels.append("")
        regels.append(f"[{v.formaat}] {v.pad_relatief}")
        regels.append(f"    SHA-256 : {v.sha256}")
        regels.append(f"    grootte : {v.grootte} bytes")
        regels.append(f"    handler : {v.handler}")
        regels.append(f"    uitvoer : {len(v.uitvoeren)} bestand(en)")
        for u in v.uitvoeren:
            regels.append(f"        + {u.pad}  ({u.sha256[:16]}...  {u.grootte}b)")
        for w in v.waarschuwingen:
            regels.append(f"    ! {w}")
        for e in v.fouten:
            regels.append(f"    X {e}")
    (doel / "rapport.txt").write_text("\n".join(regels) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- #
# Hoofdroutine
# --------------------------------------------------------------------------- #


def uitvoeren(invoer: Path, uitvoer_basis: Path | None = None) -> Path:
    invoer = invoer.resolve()
    if not invoer.exists():
        raise SystemExit(f"[-] Pad bestaat niet: {invoer}")

    ouder = uitvoer_basis.resolve() if uitvoer_basis else invoer.parent
    ouder.mkdir(parents=True, exist_ok=True)
    doel = maak_output_map(ouder, invoer)

    manifest = Manifest(
        sessie_id=str(uuid.uuid4()),
        tijd_start=utc_nu(),
        invoer_wortel=str(invoer),
        uitvoer_wortel=str(doel),
        machine={
            "python_versie": sys.version.split()[0],
            "platform": platform.platform(),
            "host": platform.node(),
        },
        optionele_modules={
            "bz2": HAS_BZ2,
            "lzma": HAS_LZMA,
            "tomllib/tomli": HAS_TOML,
            "PyYAML": HAS_YAML,
            "PyMuPDF": HAS_PYMUPDF,
            "python-docx": HAS_DOCX,
            "openpyxl": HAS_OPENPYXL,
        },
    )

    print(f"[*] Forensische extractie gestart")
    print(f"    Invoer : {invoer}")
    print(f"    Uitvoer: {doel}")
    print()

    invoer_wortel = invoer if invoer.is_dir() else invoer.parent
    aantal = 0
    for bestand in loop_invoer(invoer):
        aantal += 1
        rel = _relatief(bestand, invoer_wortel)
        print(f"[+] ({aantal:04d}) {rel}")
        vermelding = analyseer_bestand(bestand, doel, invoer_wortel)
        manifest.invoer.append(vermelding)
        if vermelding.waarschuwingen:
            for w in vermelding.waarschuwingen:
                print(f"    ! {w}")
        if vermelding.fouten:
            for e in vermelding.fouten:
                print(f"    X {e.splitlines()[0]}")

    manifest.tijd_eind = utc_nu()
    manifest.totalen = {
        "invoer": len(manifest.invoer),
        "uitvoer": sum(len(v.uitvoeren) for v in manifest.invoer),
        "waarschuwingen": sum(len(v.waarschuwingen) for v in manifest.invoer),
        "fouten": sum(len(v.fouten) for v in manifest.invoer),
    }

    (doel / "manifest.json").write_text(
        json.dumps(manifest.naar_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    schrijf_rapport(manifest, doel)

    print()
    print(f"[=] Klaar. {manifest.totalen['invoer']} invoer, "
          f"{manifest.totalen['uitvoer']} uitvoer, "
          f"{manifest.totalen['waarschuwingen']} waarschuwing(en), "
          f"{manifest.totalen['fouten']} fout(en).")
    print(f"[=] Resultaten: {doel}")
    return doel


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if any(a in ("-h", "--help") for a in argv):
        print(__doc__)
        return 0

    invoer = Path(argv[0]) if argv else Path.cwd()
    uitvoer = Path(argv[1]) if len(argv) > 1 else None
    try:
        uitvoeren(invoer, uitvoer)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        print("\n[!] Onderbroken door gebruiker", file=sys.stderr)
        return 130
    except Exception:
        traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
