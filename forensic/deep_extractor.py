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


# Patronen voor verborgen/transparante tekst in XML/HTML/DOCX/PDF
HIDDEN_TEXT_PATTERNS = [
    # Word OOXML: onzichtbare tekst
    (r'<w:vanish/?>',                          'w:vanish (verborgen tekst Word)'),
    (r'<w:color\s+w:val="(?:FFFFFF|ffffff|white|F{6})"', 'witte tekst (w:color FFFFFF)'),
    (r'<w:sz\s+w:val="[01]"',                  'font-grootte ≤1 (sub-pixel tekst)'),
    # HTML/CSS stealth
    (r'(?:color|colour)\s*:\s*(?:#fff{3,6}|white|rgba?\([^)]*,\s*0\.?0*\s*\))', 'CSS witte/transparante kleur'),
    (r'(?:opacity|visibility)\s*:\s*(?:0(?:\.0+)?|hidden)',   'CSS opacity:0 / visibility:hidden'),
    (r'display\s*:\s*none',                    'CSS display:none'),
    (r'font-size\s*:\s*0',                     'CSS font-size:0'),
    (r'(?:left|top|margin)\s*:\s*-\d{3,}px',  'tekst buiten beeld (negatieve positie)'),
    (r'z-index\s*:\s*-\d+',                    'z-index negatief (tekst onder laag)'),
    # PDF raw tekst stealth
    (rb'Tf\s+0\s+Tf',                          'PDF font-grootte 0'),
    (rb'rg\s+1\s+1\s+1\s+rg',                 'PDF witte tekstvulling (1 1 1 rg)'),
    (rb'0\s+0\s+0\s+0\s+k\b.*?Tj',            'PDF CMYK 0000 (wit op wit)'),
    (rb'BT.*?(\d+)\s+(\d+)\s+Td.*?ET',        'PDF tekst buiten paginagebied (check coords)'),
]

def detect_hidden_text(data: bytes, source: str, audit_log) -> list:
    """Detecteer verborgen/transparante tekst in XML, HTML, DOCX, PDF."""
    findings = []
    is_binary = source.endswith('.pdf')

    for pattern, label in HIDDEN_TEXT_PATTERNS:
        if isinstance(pattern, bytes):
            if not is_binary and not source.endswith('.bin'):
                continue
            hits = re.findall(pattern, data, re.DOTALL)
        else:
            try:
                text = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            hits = re.findall(pattern, text, re.IGNORECASE)

        if hits:
            log_entry(audit_log, "FIND",
                      f"Verborgen tekst [{label}] in {Path(source).name}: {len(hits)} treffer(s)",
                      {"source": source, "type": "hidden_text", "technique": label,
                       "count": len(hits)})
            findings.append({"type": "hidden_text", "source": source,
                             "technique": label, "count": len(hits)})

    # PDF-specifiek: kleurbalken met ingesloten data (jouw groene balk-vondst)
    if source.endswith('.pdf') or source.endswith('.bin'):
        colored_text_blocks = re.findall(
            rb'(\d+(?:\.\d+)?\s+\d+(?:\.\d+)?\s+\d+(?:\.\d+)?)\s+rg(.*?)Tj',
            data, re.DOTALL)
        for color_cmd, text_block in colored_text_blocks[:20]:
            # Detecteer kleur die overeenkomt met achtergrond (niet-zwart, niet-wit)
            parts = color_cmd.decode('ascii','ignore').split()
            if len(parts) == 3:
                r, g, b = float(parts[0]), float(parts[1]), float(parts[2])
                # Kleur is NIET zwart (niet ≈0,0,0) en NIET wit (niet ≈1,1,1)
                if not (r < 0.1 and g < 0.1 and b < 0.1) and not (r > 0.9 and g > 0.9 and b > 0.9):
                    txt = text_block.decode('latin-1', errors='replace').strip()[:80]
                    if txt:
                        log_entry(audit_log, "WARN",
                                  f"PDF tekst in gekleurde balk (RGB {r:.2f},{g:.2f},{b:.2f}): {txt!r}",
                                  {"source": source, "type": "colored_bar_text",
                                   "rgb": [r, g, b], "text_snippet": txt})
                        findings.append({"type": "colored_bar_text", "source": source,
                                        "rgb": [r, g, b], "snippet": txt})

    return findings


def analyse_file(path: Path, audit_log) -> list:
    """Analyseer één bestand op alle diepte-patronen."""
    path = Path(path)
    findings = []
    ext = path.suffix.lower()

    log_entry(audit_log, "INFO", f"Analyseer: {path.name} ({path.stat().st_size} bytes)")

    if ext in MATRYOSHKA_EXTENSIONS:
        findings += extract_zip_layer(path, audit_log)
        # Matryoshka kan ook hidden text bevatten in de XML-lagen
        try:
            data = path.read_bytes()
            findings += detect_hidden_text(data, str(path), audit_log)
        except Exception:
            pass
    elif ext in ('.xml','.html','.htm','.txt','.json','.har'):
        try:
            data = path.read_bytes()
            findings += extract_base64(data, str(path), audit_log)
            findings += detect_hidden_text(data, str(path), audit_log)
        except Exception as e:
            log_entry(audit_log, "ERR ", f"Leesbaar fout {path.name}: {e}")
    elif ext in ('.png','.jpg','.jpeg','.tif','.bmp','.gif'):
        findings += extract_exif(path, audit_log)
    elif ext == '.pdf':
        try:
            data = path.read_bytes()
            findings += detect_hidden_text(data, str(path), audit_log)
            # PDF kan ook ZIP bevatten (jouw vondst: PDF→ZIP→bestanden)
            zip_sig = data.find(b'PK\x03\x04')
            if zip_sig != -1:
                log_entry(audit_log, "FIND",
                          f"ZIP-handtekening in PDF op offset {zip_sig}: mogelijk ingesloten archief",
                          {"source": str(path), "type": "zip_in_pdf", "offset": zip_sig})
                findings.append({"type": "zip_in_pdf", "source": str(path), "offset": zip_sig})
                # Sla het ZIP-deel op voor nadere analyse
                zip_data = data[zip_sig:]
                h = sha256_bytes(zip_data)
                tmp = REPORTS / f"_tmp_pdf_zip_{h[:8]}.zip"
                tmp.write_bytes(zip_data)
                nested = extract_zip_layer(tmp, audit_log, depth=1, parent=path.name)
                findings.extend(nested)
                tmp.unlink(missing_ok=True)
        except Exception as e:
            log_entry(audit_log, "ERR ", f"PDF-analyse fout {path.name}: {e}")

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
        if ext in MATRYOSHKA_EXTENSIONS | {'.xml','.json','.html','.har','.png','.jpg','.jpeg','.txt','.pdf','.htm'}:
            findings = analyse_file(path, audit_log)
            all_findings.extend(findings)

    log_entry(audit_log, "INFO", f"=== DIEPTE-EXTRACTOR KLAAR: {len(all_findings)} artefacten ===")
    return all_findings, audit_log

if __name__ == "__main__":
    import sys
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "extracted_docs"
    findings, log = run_deep_analysis(target)
    print(f"\nTotaal: {len(findings)} artefacten")
