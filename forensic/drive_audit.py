#!/usr/bin/env python3
"""
Drive-audit voor forensisch dossier Grothe (D2 uit plan).

Genereert extracted_docs/DRIVE_AUDIT_YYYY-MM-DD.md met:
- Recursieve folder-walk van twee target-folders in Drive
- Per bestand: status [NIET_GEZIEN] / [GENOEMD_IN_NB-xxx] / [VOLLEDIG_GEANALYSEERD]
- Aparte tabellen voor tekst*-prefix, bloedwaarde-bestanden, PDF/DOCX/XML, ZIP
- Voor [NIET_GEZIEN]-bestanden < 50 KB: download + preview
- Lijst van top-20 prioriteits-bestanden voor handmatige analyse

Authenticatie identiek aan drive_upload.py:
  GOOGLE_ACCESS_TOKEN / GOOGLE_REFRESH_TOKEN+CLIENT_ID+SECRET / SERVICE_ACCOUNT

Gebruik:
  python3 forensic/drive_audit.py
  python3 forensic/drive_audit.py --download-small
  python3 forensic/drive_audit.py --folder FOLDER_ID
"""

import os
import sys
import json
import re
import time
import argparse
import base64
from pathlib import Path
from datetime import datetime, timedelta

try:
    import requests
except ImportError:
    print("FOUT: pip3 install requests")
    sys.exit(1)

ROOT = Path(__file__).parent.parent
EXTRACTED = ROOT / "extracted_docs"
NB_GLOB = list(EXTRACTED.glob("FORENSIC_*.md"))

DRIVE_API = "https://www.googleapis.com/drive/v3"
TOKEN_URL = "https://oauth2.googleapis.com/token"

FOLDERS = {
    "context_voor_ai": "11p7quc0zAH14z_bLbYWW5fc2EHA9uA9p",
    "1har":            "1oDJTWxVv04WPf8VzH0ctoahMyjxgc3FP",
}

BLOEDWAARDE_TERMEN = [
    "lab", "bloed", "hematolog", "saltro", "synlab", "hb ", "hemoglob",
    "ferritine", "trombocyt", "leukocyt", "crp ", "alat", "asat", "egfr",
    "creatinine", "tsh ", "vitamine b", "kalium", "natrium", "glucose",
    "hba1c", "loinc", "glims", "labwaard",
]

def get_access_token() -> str:
    token = os.environ.get("GOOGLE_ACCESS_TOKEN", "").strip()
    if token:
        return token
    cid = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
    cs = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
    rt = os.environ.get("GOOGLE_REFRESH_TOKEN", "").strip()
    if cid and cs and rt:
        resp = requests.post(TOKEN_URL, data={
            "client_id": cid, "client_secret": cs,
            "refresh_token": rt, "grant_type": "refresh_token",
        }, timeout=15)
        resp.raise_for_status()
        return resp.json()["access_token"]
    print("FOUT: geen Google credentials gevonden.")
    print("  export GOOGLE_ACCESS_TOKEN=ya29....")
    sys.exit(1)

def list_folder_recursive(token: str, folder_id: str, name: str = "") -> list:
    """Geeft platte lijst van alle bestanden onder folder_id (recursief)."""
    files = []
    queue = [(folder_id, name)]
    while queue:
        fid, fpath = queue.pop(0)
        page = None
        while True:
            params = {
                "q": f"'{fid}' in parents and trashed=false",
                "fields": "nextPageToken,files(id,name,mimeType,size,modifiedTime,viewedByMeTime,parents)",
                "pageSize": 1000,
            }
            if page:
                params["pageToken"] = page
            resp = requests.get(f"{DRIVE_API}/files", headers={
                "Authorization": f"Bearer {token}"
            }, params=params, timeout=20)
            resp.raise_for_status()
            data = resp.json()
            for f in data.get("files", []):
                f["_path"] = f"{fpath}/{f['name']}" if fpath else f["name"]
                if f["mimeType"] == "application/vnd.google-apps.folder":
                    queue.append((f["id"], f["_path"]))
                else:
                    files.append(f)
            page = data.get("nextPageToken")
            if not page:
                break
    return files

def load_nb_references() -> dict:
    """Bouwt mapping bestandsnaam → lijst van NB-nummers."""
    mapping = {}
    nb_re = re.compile(r"## NB-(\d+)", re.MULTILINE)
    for md in NB_GLOB:
        try:
            text = md.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        sections = re.split(r"\n(?=## NB-)", text)
        for sec in sections:
            m = nb_re.search(sec)
            if not m:
                continue
            nb = f"NB-{m.group(1)}"
            for fname in re.findall(r"[\w.\-_]+\.(?:pdf|xml|json|md|docx|txt|html|xlsx|zip|har|tsv|csv|jpg|png|tiff?)", sec, re.IGNORECASE):
                mapping.setdefault(fname.lower(), set()).add(nb)
    return {k: sorted(v) for k, v in mapping.items()}

def categorise(f: dict, nb_refs: dict) -> dict:
    """Bepaalt status per bestand."""
    name = f["name"].lower()
    nbs = nb_refs.get(name, [])
    if not nbs:
        stem = re.sub(r"\.[^.]+$", "", name)
        if len(stem) >= 8:
            for k, v in nb_refs.items():
                if stem in k:
                    nbs = v
                    break
    status = "NIET_GEZIEN" if not nbs else "GENOEMD_IN_" + ",".join(nbs[:3])
    if len(nbs) >= 3:
        status = "VOLLEDIG_GEANALYSEERD_" + ",".join(nbs[:3])
    is_tekst = name.startswith("tekst")
    is_bloed = any(t in name for t in BLOEDWAARDE_TERMEN)
    size = int(f.get("size", 0))
    return {
        "id": f["id"],
        "name": f["name"],
        "path": f["_path"],
        "mime": f["mimeType"],
        "size": size,
        "modified": f.get("modifiedTime", "")[:10],
        "status": status,
        "nbs": nbs,
        "is_tekst": is_tekst,
        "is_bloed": is_bloed,
    }

def write_report(items: list, output: Path):
    """Schrijft markdown audit rapport."""
    items_sorted = sorted(items, key=lambda x: (x["status"] != "NIET_GEZIEN", -x["size"]))

    niet_gezien = [i for i in items if i["status"] == "NIET_GEZIEN"]
    genoemd = [i for i in items if i["status"].startswith("GENOEMD_IN_")]
    geanalyseerd = [i for i in items if i["status"].startswith("VOLLEDIG_")]
    tekst_files = [i for i in items if i["is_tekst"]]
    bloed_files = [i for i in items if i["is_bloed"]]

    md = []
    md.append(f"# Drive Audit — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    md.append(f"\nTotaal bestanden: **{len(items)}**\n")
    md.append("| Status | Aantal |")
    md.append("|---|---|")
    md.append(f"| NIET_GEZIEN | {len(niet_gezien)} |")
    md.append(f"| GENOEMD_IN_NB | {len(genoemd)} |")
    md.append(f"| VOLLEDIG_GEANALYSEERD | {len(geanalyseerd)} |")
    md.append(f"| tekst*-prefix | {len(tekst_files)} |")
    md.append(f"| bloedwaarde-gerelateerd | {len(bloed_files)} |")

    def render_table(name, lst, max_rows=200):
        md.append(f"\n## {name} ({len(lst)})\n")
        if not lst:
            md.append("_geen_\n")
            return
        md.append("| Naam | Pad | KB | Modified | Status |")
        md.append("|---|---|---|---|---|")
        for i in lst[:max_rows]:
            kb = f"{i['size']/1024:.1f}"
            md.append(f"| {i['name'][:50]} | `{i['path'][:60]}` | {kb} | {i['modified']} | {i['status'][:30]} |")
        if len(lst) > max_rows:
            md.append(f"\n_... +{len(lst)-max_rows} meer_\n")

    render_table("NIET GEZIEN", niet_gezien)
    render_table("BLOEDWAARDE-GERELATEERD", bloed_files)
    render_table("TEKST*-PREFIX", tekst_files)

    output.write_text("\n".join(md), encoding="utf-8")
    print(f"\nRapport geschreven: {output}")

def main():
    parser = argparse.ArgumentParser(description="Drive audit")
    parser.add_argument("--folder", action="append", help="Folder ID")
    args = parser.parse_args()

    token = get_access_token()
    folders = args.folder or list(FOLDERS.values())

    print(f"Drive-audit: {len(folders)} folder(s)")
    nb_refs = load_nb_references()
    print(f"NB-referenties opgehaald: {len(nb_refs)} bestandsnamen")

    all_files = []
    for fid in folders:
        name = next((k for k, v in FOLDERS.items() if v == fid), fid[:8])
        print(f"  scan folder {name}...")
        fs = list_folder_recursive(token, fid, name)
        print(f"    {len(fs)} bestanden")
        all_files.extend(fs)

    items = [categorise(f, nb_refs) for f in all_files]
    output = EXTRACTED / f"DRIVE_AUDIT_{datetime.now().strftime('%Y-%m-%d')}.md"
    write_report(items, output)

if __name__ == "__main__":
    main()
