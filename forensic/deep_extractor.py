#!/usr/bin/env python3
"""
Diepte-extractor: matryoshka-bestanden, base64, EXIF, embedded data.
Elk gevonden artefact wordt gelogd met SHA-256 en herkomst.
"""

import zipfile, base64, re, json, hashlib, datetime, struct
from pathlib import Path

ROOT    = Path(__file__).parent.parent
REPORTS = ROOT / "reports"

# Base64 blokken (min 100 chars, typisch voor embedded data)
B64_PATTERN = re.compile(rb'(?:[A-Za-z0-9+/]{4}){25,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')

# XML base64 content (CDA, HL7)
XML_B64_PATTERN = re.compile(r'<(?:content|representation|value)[^>]*>([A-Za-z0-9+/\s]{80,}={0,2})</[^>]+>', re.IGNORECASE)

MATRYOSHKA_EXTENSIONS = {'.zip','.docx','.xlsx','.pptx','.jar','.apk','.odt','.ods'}

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def log_entry(audit_log, level, msg, extra=None):
    entry = {
        "ts":    datetime.datetime.utcnow().isoformat() + "Z",
        "level": level,
        "msg":   msg,
    }
    if extra:
        entry.update(extra)
    audit_log.append(entry)
    prefix = {"INFO":"  ","WARN":"⚠ ","FIND":"★ ","ERR ":"✗ "}.get(level,"  ")
    print(f"{prefix}{msg}")

def extract_zip_layer(path, audit_log, depth=0, parent=""):
    """Extraheer ZIP/DOCX/XLSX recursief. Detecteer embedded bestanden."""
    if depth > 5:
        return []
    findings = []
    label = f"{parent} → {path.name}" if parent else path.name

    try:
        with zipfile.ZipFile(path) as zf:
            log_entry(audit_log, "INFO", f"[D{depth}] ZIP-laag: {label} ({len(zf.namelist())} entries)")
            for name in zf.namelist():
                info = zf.getinfo(name)
                if info.file_size == 0:
                    continue
                try:
                    data = zf.read(name)
                    h = sha256_bytes(data)

                    # Detecteer geneste zip/office
                    ext = Path(name).suffix.lower()
                    if ext in MATRYOSHKA_EXTENSIONS and len(data) > 100:
                        # Schrijf tijdelijk en ga dieper
                        tmp = REPORTS / f"_tmp_nested_{h[:8]}{ext}"
                        tmp.write_bytes(data)
                        nested = extract_zip_layer(tmp, audit_log, depth+1, label)
                        findings.extend(nested)
                        tmp.unlink(missing_ok=True)

                    # Detecteer base64 blokken in tekst-entries
                    if ext in ('.xml','.html','.txt','.json','.rels'):
                        b64_hits = extract_base64(data, f"{label}/{name}", audit_log)
                        findings.extend(b64_hits)

                    # Detecteer binaire blobs in niet-tekst-entries
                    if ext in ('.bin','.dat','') and len(data) > 512:
                        log_entry(audit_log, "FIND", f"Binair blob: {name} ({len(data)} bytes, sha256={h[:16]}…)",
                                  {"source": label, "inner_file": name, "sha256": h, "size": len(data)})
                        findings.append({"type":"binary_blob","source":label,"name":name,"sha256":h,"size":len(data)})

                except Exception as e:
                    log_entry(audit_log, "ERR ", f"Kan {name} niet lezen: {e}")
    except zipfile.BadZipFile:
        log_entry(audit_log, "WARN", f"Geen geldig ZIP: {label}")
    except Exception as e:
        log_entry(audit_log, "ERR ", f"Fout bij {label}: {e}")

    return findings

def extract_base64(data: bytes, source: str, audit_log) -> list:
    """Detecteer en decodeer base64-blokken in bytes-data."""
    findings = []
    text = data.decode('utf-8', errors='replace')

    # XML-specifieke base64 (CDA/HL7)
    for m in XML_B64_PATTERN.finditer(text):
        raw = m.group(1).replace('\n','').replace('\r','').replace(' ','')
        try:
            decoded = base64.b64decode(raw + '==')
            h = sha256_bytes(decoded)
            # Detecteer bestandstype via magic bytes
            ftype = detect_filetype(decoded)
            log_entry(audit_log, "FIND",
                      f"Base64 in XML ({len(decoded)} bytes, {ftype}, sha256={h[:16]}…)",
                      {"source": source, "type": "xml_base64", "decoded_type": ftype,
                       "sha256": h, "decoded_size": len(decoded)})
            findings.append({"type":"xml_base64","source":source,"decoded_type":ftype,
                             "sha256":h,"size":len(decoded)})
            # Sla op als apart bestand voor nadere analyse
            out = REPORTS / f"EMBEDDED_{h[:12]}.{ftype or 'bin'}"
            if not out.exists():
                out.write_bytes(decoded)
                log_entry(audit_log, "INFO", f"  → Opgeslagen: {out.name}")
        except Exception:
            pass

    # Generieke base64 blokken (binary scan)
    for m in B64_PATTERN.finditer(data):
        raw = m.group(0)
        if len(raw) < 200:
            continue
        try:
            decoded = base64.b64decode(raw + b'==')
            if len(decoded) < 100:
                continue
            h = sha256_bytes(decoded)
            ftype = detect_filetype(decoded)
            if ftype in ('pdf','png','jpg','zip','docx'):  # Alleen interessante typen
                log_entry(audit_log, "FIND",
                          f"Embedded {ftype.upper()} in binair blok ({len(decoded)} bytes, sha256={h[:16]}…)",
                          {"source": source, "type": "binary_base64", "decoded_type": ftype,
                           "sha256": h, "decoded_size": len(decoded)})
                findings.append({"type":"binary_base64","source":source,"decoded_type":ftype,
                                 "sha256":h,"size":len(decoded)})
                out = REPORTS / f"EMBEDDED_{h[:12]}.{ftype}"
                if not out.exists():
                    out.write_bytes(decoded)
        except Exception:
            pass

    return findings

def detect_filetype(data: bytes) -> str:
    """Magic bytes detectie."""
    if len(data) < 4:
        return "unknown"
    magic = {
        b'%PDF':   'pdf',
        b'\x89PNG': 'png',
        b'\xff\xd8\xff': 'jpg',
        b'PK\x03\x04': 'zip',   # ook .docx/.xlsx
        b'GIF8':   'gif',
        b'BM':     'bmp',
        b'II*\x00':'tif',
        b'MM\x00*':'tif',
        b'\x1f\x8b': 'gz',
        b'Rar!':   'rar',
        b'7z\xbc\xaf': '7z',
        b'<xml':   'xml',
        b'<?xml':  'xml',
        b'<ClinicalDocument': 'cda',
    }
    for sig, name in magic.items():
        if data[:len(sig)] == sig:
            return name
    # XML check
    try:
        start = data[:100].decode('utf-8','ignore').lstrip()
        if start.startswith('<?xml') or start.startswith('<'):
            return 'xml'
    except:
        pass
    # Tekst check
    try:
        data[:512].decode('utf-8')
        return 'txt'
    except:
        return 'bin'

def extract_exif(path: Path, audit_log) -> list:
    """EXIF metadata en steganografie-detectie in afbeeldingen."""
    findings = []
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
        img = Image.open(path)
        exif_data = img._getexif() if hasattr(img,'_getexif') else None
        info = img.info

        if exif_data:
            exif_clean = {}
            for tag_id, val in exif_data.items():
                tag = TAGS.get(tag_id, str(tag_id))
                if isinstance(val, bytes):
                    try:
                        val = val.decode('utf-8','replace')
                    except:
                        val = val.hex()
                exif_clean[tag] = str(val)[:200]

            log_entry(audit_log, "FIND", f"EXIF in {path.name}: {len(exif_clean)} velden",
                      {"source": str(path), "type": "exif", "fields": exif_clean})
            findings.append({"type":"exif","source":str(path),"fields":exif_clean})

        # PNG/JPEG comment velden
        for key in ('Comment','comment','UserComment','Artist','Copyright','Make','Software'):
            if key in info:
                log_entry(audit_log, "FIND", f"Metadata-veld {key}: {str(info[key])[:100]}",
                          {"source": str(path), "type": "image_metadata", "field": key, "value": str(info[key])[:500]})

        # LSB steganografie check (simpel: kijk of LSBs niet-uniform zijn)
        if img.mode in ('RGB','RGBA') and img.size[0] * img.size[1] > 1000:
            import numpy as np
            try:
                arr = np.array(img)
                lsb = arr & 1
                # Als LSBs niet ~50/50 zijn, verdacht
                ratio = lsb.mean()
                if ratio < 0.3 or ratio > 0.7:
                    log_entry(audit_log, "WARN",
                              f"Afwijkende LSB-verhouding in {path.name}: {ratio:.3f} (mogelijk steganografie)",
                              {"source": str(path), "type": "steganography_suspect", "lsb_ratio": ratio})
                    findings.append({"type":"steganography_suspect","source":str(path),"lsb_ratio":ratio})
            except ImportError:
                pass  # numpy niet beschikbaar

    except Exception as e:
        log_entry(audit_log, "INFO", f"Geen EXIF leesbaar: {path.name} ({e})")

    return findings

def analyse_file(path: Path, audit_log) -> list:
    """Analyseer één bestand op alle diepte-patronen."""
    path = Path(path)
    findings = []
    ext = path.suffix.lower()

    log_entry(audit_log, "INFO", f"Analyseer: {path.name} ({path.stat().st_size} bytes)")

    if ext in MATRYOSHKA_EXTENSIONS:
        findings += extract_zip_layer(path, audit_log)
    elif ext in ('.xml','.html','.htm','.txt','.json','.har'):
        try:
            data = path.read_bytes()
            findings += extract_base64(data, str(path), audit_log)
        except Exception as e:
            log_entry(audit_log, "ERR ", f"Leesbaar fout {path.name}: {e}")
    elif ext in ('.png','.jpg','.jpeg','.tif','.bmp','.gif'):
        findings += extract_exif(path, audit_log)

    return findings

def run_deep_analysis(target_dir=None, audit_log=None):
    """Voer diepte-analyse uit op alle relevante bestanden."""
    if audit_log is None:
        audit_log = []
    if target_dir is None:
        target_dir = ROOT / "extracted_docs"

    ts = datetime.datetime.utcnow().isoformat() + "Z"
    log_entry(audit_log, "INFO", f"=== DIEPTE-EXTRACTOR START {ts} ===")

    all_findings = []
    target = Path(target_dir)

    for path in sorted(target.rglob("*")):
        if not path.is_file():
            continue
        if any(ex in path.parts for ex in {'.git','__pycache__'}):
            continue
        ext = path.suffix.lower()
        if ext in MATRYOSHKA_EXTENSIONS | {'.xml','.json','.html','.har','.png','.jpg','.jpeg','.txt'}:
            findings = analyse_file(path, audit_log)
            all_findings.extend(findings)

    log_entry(audit_log, "INFO", f"=== DIEPTE-EXTRACTOR KLAAR: {len(all_findings)} artefacten ===")
    return all_findings, audit_log

if __name__ == "__main__":
    import sys
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "extracted_docs"
    findings, log = run_deep_analysis(target)
    print(f"\nTotaal: {len(findings)} artefacten")
