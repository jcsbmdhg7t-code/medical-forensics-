#!/usr/bin/env python3
"""
Google Drive sync — haalt nieuwe bestanden op via Claude MCP (mcp__558c7bd4-*)
Wordt aangeroepen vanuit de GitHub Action met: claude -p "run drive sync"
Read-only: downloadt bestanden naar extracted_docs/drive_imports/
"""

import os, json, datetime
from pathlib import Path

ROOT = Path(__file__).parent.parent
DRIVE_IMPORT_DIR = ROOT / "extracted_docs" / "drive_imports"
DRIVE_IMPORT_DIR.mkdir(parents=True, exist_ok=True)

DRIVE_FOLDERS = {
    "context_voor_ai": "11p7quc0zAH14z_bLbYWW5fc2EHA9uA9p",
    "1har":            "1oDJTWxVv04WPf8VzH0ctoahMyjxgc3FP",
}

CLAUDE_DRIVE_PROMPT = """
Gebruik de Google Drive MCP tools (mcp__558c7bd4-*) om:
1. List alle bestanden in folder ID: {folder_id} (naam: {folder_name})
2. Voor elk bestand dat NIEUW is (niet in de index hieronder):
   - Lees de metadata op
   - Lees de inhoud op (read_file_content)
   - Sla op als extracted_docs/drive_imports/{folder_name}_{filename}
3. Rapporteer: welke bestanden nieuw zijn, welke al bekend

Bekende bestanden (overslaan als hash matcht):
{known_files}

Schrijf ALLEEN naar extracted_docs/drive_imports/ — read-only op Drive zelf.
Samenvatting in JSON: {{"new": [...], "skipped": [...], "errors": [...]}}
"""

def get_known_files():
    """Return list of already-imported filenames."""
    known = []
    for f in DRIVE_IMPORT_DIR.rglob("*"):
        if f.is_file():
            known.append(f.name)
    return known

def write_sync_prompt(folder_name, folder_id):
    """Write a prompt file that the GitHub Action feeds to claude -p."""
    known = get_known_files()
    prompt = CLAUDE_DRIVE_PROMPT.format(
        folder_id=folder_id,
        folder_name=folder_name,
        known_files="\n".join(known) if known else "(geen)"
    )
    prompt_file = ROOT / "forensic" / f"_sync_prompt_{folder_name}.txt"
    prompt_file.write_text(prompt)
    return prompt_file

def run():
    """Called from GitHub Action or manually."""
    results = {}
    for name, fid in DRIVE_FOLDERS.items():
        pf = write_sync_prompt(name, fid)
        print(f"Sync prompt geschreven: {pf}")
        # In GitHub Action: claude -p "$(cat {pf})" --output-format json
        results[name] = str(pf)

    manifest = DRIVE_IMPORT_DIR / "sync_manifest.json"
    existing = json.loads(manifest.read_text()) if manifest.exists() else {}
    existing[datetime.date.today().isoformat()] = results
    manifest.write_text(json.dumps(existing, indent=2))
    print(f"Manifest: {manifest}")

if __name__ == "__main__":
    run()
