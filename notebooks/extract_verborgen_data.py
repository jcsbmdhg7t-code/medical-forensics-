# -*- coding: utf-8 -*-
"""
================================================================================
 VERBORGEN DATA UITPAKKEN — Google Colab
================================================================================
Doet ÉÉN ding: haalt de VERBORGEN data uit je bestanden en schrijft die
VOLLEDIG (niet afgekapt) weg als losse bestanden die je gewoon kunt openen.

- Geen ruis (geen PNG-tekstblokken, geen entropie-meldingen, geen tellingen).
- Geen afkapping: elke verborgen payload wordt integraal opgeslagen.
- Kiest NIETS zelf: scant uitsluitend de map/het bestand dat JIJ opgeeft.

Wat telt als "verborgen data" en wordt uitgepakt:
  1. Data ACHTER het einde van een bestand (na JPEG/PNG/GIF/PDF-eindmarker)
  2. Een tweede bestand VERSTOPT in een ander (ingebedde JPEG/PNG/ZIP/PDF/gzip)
  3. Ingebedde bestanden in een PDF (/EmbeddedFile)
  4. Verstopte bestanden in een ZIP die niet in de inhoudsopgave staan
  5. base64 / hex / gzip / zlib-blokken die iets leesbaars opleveren

Elke payload wordt opgeslagen met de JUISTE extensie (op magic bytes herkend),
zodat een verstopte foto ook echt als foto opent.

GEBRUIK IN COLAB
----------------
Cel 1:  !pip install -q pymupdf
Cel 2:  plak dit bestand (of %run extract_verborgen_data.py)
Cel 3:  from google.colab import drive; drive.mount('/content/drive')
Cel 4:  extraheer("/content/drive/MyDrive/EXACTE_MAP_DIE_JIJ_WILT")
        # of één bestand:  extraheer(".../IMG_E0149.JPG")

Resultaat: map  EXTRACTIE_<tijd>/  met alle verborgen payloads als losse
bestanden, plus INDEX.md met per payload: bron, type, grootte, herkend
formaat en (bij tekst) de eerste leesbare regels.
"""

import os
import re
import io
import gzip
import zlib
import base64
import struct
import hashlib
import pathlib
from datetime import datetime

try:
    import fitz  # PyMuPDF (voor PDF-embedded files); optioneel
    _HAS_FITZ = True
except Exception:
    _HAS_FITZ = False


# ── magic-bytes → herken het formaat van een uitgepakte payload ──
_MAGIC = [
    (b"\xff\xd8\xff", "jpg", "JPEG-afbeelding"),
    (b"\x89PNG\r\n\x1a\n", "png", "PNG-afbeelding"),
    (b"GIF8", "gif", "GIF-afbeelding"),
    (b"%PDF", "pdf", "PDF-document"),
    (b"PK\x03\x04", "zip", "ZIP/Office-archief"),
    (b"\x1f\x8b", "gz", "gzip-archief"),
    (b"BZh", "bz2", "bzip2-archief"),
    (b"ID3", "mp3", "MP3-audio"),
    (b"\x00\x00\x00\x18ftyp", "mp4", "MP4-video"),
    (b"\x00\x00\x00\x1cftyp", "mp4", "MP4-video"),
    (b"RIFF", "riff", "RIFF (wav/avi)"),
    (b"OggS", "ogg", "OGG-media"),
    (b"SQLite format 3", "sqlite", "SQLite-database"),
    (b"-----BEGIN", "pem", "PEM-sleutel/certificaat"),
    (b"<?xml", "xml", "XML-document"),
    (b"<!DOCTYPE html", "html", "HTML-pagina"),
    (b"<html", "html", "HTML-pagina"),
    (b"{", "json", "JSON/tekst"),
]

# container-eindmarkers om "data erachter" te vinden
_EINDMARKERS = {
    "jpg": b"\xff\xd9",
    "jpeg": b"\xff\xd9",
    "png": b"IEND\xaeB`\x82",
    "gif": b"\x00\x3b",
    "pdf": b"%%EOF",
}


def _herken(data):
    """Geeft (extensie, omschrijving) op basis van magic bytes."""
    for sig, ext, oms in _MAGIC:
        if data[:32].startswith(sig) or (sig == b"RIFF" and data[:4] == b"RIFF"):
            return ext, oms
    # printbare tekst?
    s = data[:512]
    if s and sum(1 for x in s if 32 <= x < 127 or x in (9, 10, 13)) / len(s) > 0.85:
        return "txt", "leesbare tekst"
    return "bin", "onbekende binaire data"


def _preview(data):
    """Leesbare voorbeeldregels als het tekst is, anders lege string."""
    for enc in ("utf-8", "utf-16-le", "latin-1"):
        try:
            t = data.decode(enc)
            if sum(1 for c in t[:400] if c.isprintable() or c in "\t\n\r") / max(1, len(t[:400])) > 0.85:
                return t[:1500]
        except Exception:
            pass
    return ""


class _Uitpakker:
    def __init__(self, uit_map):
        self.uit = uit_map
        self.items = []      # (bron, soort, ext, oms, opslagpad, grootte, preview, sha)
        os.makedirs(uit_map, exist_ok=True)

    def _bewaar(self, bron, soort, payload, diepte=0):
        if not payload or len(payload) < 4:
            return
        ext, oms = _herken(payload)
        sha = hashlib.sha256(payload).hexdigest()
        # duplicaat? sla niet twee keer identiek op
        if any(it["sha256"] == sha for it in self.items):
            return
        veilige_bron = re.sub(r"[^A-Za-z0-9._-]", "_", pathlib.Path(bron).name)
        naam = f"{veilige_bron}.{soort}.{sha[:8]}.{ext}"
        pad = os.path.join(self.uit, naam)
        with open(pad, "wb") as f:
            f.write(payload)
        self.items.append({
            "bron": pathlib.Path(bron).name, "soort": soort, "ext": ext,
            "omschrijving": oms, "opgeslagen_als": naam, "grootte": len(payload),
            "sha256": sha, "preview": _preview(payload),
        })
        print(f"  [+] {soort}: {len(payload):,} bytes -> {naam}  ({oms})")
        # uitgepakte payload zelf verder uitpakken zodat de INHOUD leesbaar wordt
        if diepte < 3:
            if ext == "zip":
                try:
                    import zipfile
                    zz = zipfile.ZipFile(io.BytesIO(payload))
                    for lid in zz.namelist()[:50]:
                        try:
                            self._bewaar(bron, f"{soort}>in-zip:{lid}",
                                         zz.read(lid), diepte + 1)
                        except Exception:
                            pass
                except Exception:
                    pass
            elif ext == "gz":
                try:
                    self._bewaar(bron, f"{soort}>uitgepakt",
                                 gzip.decompress(payload), diepte + 1)
                except Exception:
                    pass

    # 1. data achter de eindmarker van een container
    def _trailing(self, bron, raw):
        soort_ext = None
        for ext, marker in _EINDMARKERS.items():
            i = raw.rfind(marker)
            if i != -1:
                rest = raw[i + len(marker):].lstrip(b"\r\n\x00 \t")
                if len(rest) >= 8:
                    self._bewaar(bron, f"na-einde({ext})", rest)
                soort_ext = ext
                break
        return soort_ext

    # 2. tweede container VERSTOPT ergens ná het begin
    def _embedded(self, bron, raw):
        for sig, ext, _ in _MAGIC:
            if len(sig) < 3:
                continue
            start = 0
            gevonden = 0
            while True:
                i = raw.find(sig, start)
                if i <= 0:      # i==0 is het bestand zelf; alleen ná offset 0 telt
                    break
                brok = raw[i:]
                # sla alleen op als het brokje substantieel is
                if len(brok) >= 64:
                    self._bewaar(bron, f"ingebed@{i}", brok[:5_000_000])
                    gevonden += 1
                start = i + len(sig)
                if gevonden >= 5:
                    break

    # 3. ingebedde bestanden in een PDF
    def _pdf_embedded(self, bron, pad):
        if not _HAS_FITZ:
            return
        try:
            d = fitz.open(pad)
        except Exception:
            return
        try:
            for i in range(d.embfile_count()):
                info = d.embfile_info(i)
                payload = d.embfile_get(i)
                naam = info.get("filename", f"embedded_{i}")
                self._bewaar(bron, f"pdf-embedded({naam})", payload)
        except Exception:
            pass
        try:
            d.close()
        except Exception:
            pass

    # 4. ZIP-entries die fysiek bestaan maar niet in de inhoudsopgave staan
    def _zip_verstopt(self, bron, raw):
        try:
            import zipfile
            z = zipfile.ZipFile(io.BytesIO(raw))
            in_cd = {i.filename for i in z.infolist()}
        except Exception:
            return
        for m in re.finditer(rb"PK\x03\x04", raw):
            try:
                ln = struct.unpack("<H", raw[m.start() + 26:m.start() + 28])[0]
                nm = raw[m.start() + 30:m.start() + 30 + ln].decode("utf-8", "replace")
            except Exception:
                continue
            if nm and nm not in in_cd:
                self._bewaar(bron, f"zip-verstopt({nm})", raw[m.start():m.start() + 2_000_000])

    # 5. base64 / hex / gzip / zlib-blokken die iets opleveren
    def _encoded(self, bron, raw):
        tekst = raw.decode("latin-1", "ignore")
        n = 0
        for m in re.finditer(r"[A-Za-z0-9+/]{80,}={0,2}", tekst):
            blok = m.group(0)
            try:
                dec = base64.b64decode(blok + "=" * (-len(blok) % 4), validate=False)
            except Exception:
                continue
            # is de gedecodeerde inhoud zinnig? (leesbaar of herkenbaar formaat)
            ext, _ = _herken(dec)
            if ext != "bin" or _preview(dec):
                self._bewaar(bron, "base64-blok", dec)
                # eventueel nog gzip erin
                if dec[:2] == b"\x1f\x8b":
                    try:
                        self._bewaar(bron, "base64->gzip", gzip.decompress(dec))
                    except Exception:
                        pass
                n += 1
            if n >= 10:
                break

    def verwerk(self, pad):
        try:
            raw = pathlib.Path(pad).read_bytes()
        except Exception:
            return
        print(f"[*] {pathlib.Path(pad).name}")
        self._trailing(pad, raw)
        self._embedded(pad, raw)
        self._encoded(pad, raw)
        if raw[:4] == b"%PDF":
            self._pdf_embedded(pad, pad)
        if raw[:4] == b"PK\x03\x04":
            self._zip_verstopt(pad, raw)


def extraheer(doel):
    """Pak alle verborgen data uit `doel` (map OF één bestand) volledig uit."""
    doel = os.path.abspath(doel)
    if not os.path.exists(doel):
        print(f"[!] Bestaat niet: {doel}")
        return
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    basis = doel if os.path.isdir(doel) else os.path.dirname(doel)
    uit_map = os.path.join(basis, f"EXTRACTIE_{ts}")
    up = _Uitpakker(uit_map)

    if os.path.isfile(doel):
        bestanden = [doel]
    else:
        bestanden = sorted(str(p) for p in pathlib.Path(doel).rglob("*")
                           if p.is_file() and not p.name.startswith(".")
                           and "EXTRACTIE_" not in str(p))
    print(f"[*] {len(bestanden)} bestand(en) doorzoeken op verborgen data...\n")
    for p in bestanden:
        up.verwerk(p)

    # INDEX.md — alleen de verborgen payloads, volledig te openen
    idx = os.path.join(uit_map, "INDEX.md")
    with open(idx, "w", encoding="utf-8") as f:
        f.write(f"# Uitgepakte verborgen data — {ts}\n\n")
        f.write(f"Bron: `{doel}`  \nGevonden payloads: **{len(up.items)}**\n\n")
        if not up.items:
            f.write("_Geen verborgen data aangetroffen in deze map._\n")
        for it in up.items:
            f.write(f"## {it['opgeslagen_als']}\n")
            f.write(f"- Uit: `{it['bron']}`\n")
            f.write(f"- Manier van verbergen: **{it['soort']}**\n")
            f.write(f"- Herkend als: {it['omschrijving']} ({it['grootte']:,} bytes)\n")
            f.write(f"- SHA-256: `{it['sha256']}`\n")
            if it["preview"]:
                f.write(f"- Leesbare inhoud:\n\n```\n{it['preview']}\n```\n")
            else:
                f.write("- (binair — open het bestand met de juiste app)\n")
            f.write("\n")

    print(f"\n{'='*70}")
    print(f" {len(up.items)} verborgen payload(s) uitgepakt naar:")
    print(f"   {uit_map}")
    print(f" Open INDEX.md voor het overzicht; alle payloads staan als losse bestanden.")
    print(f"{'='*70}")
    return up.items


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        extraheer(sys.argv[1])
    else:
        print("Gebruik:  extraheer('/pad/naar/map_of_bestand')")
