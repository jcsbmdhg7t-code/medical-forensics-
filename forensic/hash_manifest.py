#!/usr/bin/env python3
"""
SHA-256 manifest + wijzigingsdetectie voor alle bewijs-bestanden.
Genereert een gesigneerde manifest die naar git gepusht wordt
zodat GitHub als onafhankelijk tijdstempel fungeert.

Gebruik:
  python3 -m forensic.hash_manifest           # scan + vergelijk + rapport
  python3 -m forensic.hash_manifest --init    # eerste run, sla baseline op
"""

import hashlib, json, datetime, sys, os
from pathlib import Path

ROOT     = Path(__file__).parent.parent
MANIFEST = ROOT / "forensic" / "SHA256_MANIFEST.json"
REPORTS  = ROOT / "reports"

SCAN_DIRS = [
    ROOT / "extracted_docs",
    ROOT / "forensic",
    ROOT / ".github",
]
SCAN_EXTENSIONS = {
    '.md','.txt','.json','.xml','.csv','.py','.js','.yml','.yaml',
    '.pdf','.docx','.xlsx','.png','.jpg','.jpeg','.har','.zip',
    '.html','.htm','.eml','.msg',
}
EXCLUDE_DIRS = {'.git','__pycache__','node_modules'}

def sha256(path):
    h = hashlib.sha256()
    with open(path,'rb') as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def scan_all():
    """Scan alle bewijs-bestanden, geef {relpad: {hash, size, mtime}}."""
    results = {}
    for base in SCAN_DIRS:
        if not base.exists():
            continue
        for p in sorted(base.rglob("*")):
            if p.is_dir():
                continue
            if any(ex in p.parts for ex in EXCLUDE_DIRS):
                continue
            if p.suffix.lower() not in SCAN_EXTENSIONS and p.stat().st_size < 10_000_000:
                # Include unknown extensions if small enough
                pass
            try:
                stat = p.stat()
                results[str(p.relative_to(ROOT))] = {
                    "sha256":  sha256(p),
                    "size":    stat.st_size,
                    "mtime":   datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                }
            except Exception as e:
                results[str(p.relative_to(ROOT))] = {"error": str(e)}
    return results

def load_manifest():
    if MANIFEST.exists():
        with open(MANIFEST) as f:
            return json.load(f)
    return {}

def save_manifest(data, entries):
    obj = {
        "generated":    datetime.datetime.utcnow().isoformat() + "Z",
        "tool":         "forensic/hash_manifest.py",
        "dossier":      "Grothe BSN 215672185",
        "total_files":  len(entries),
        "files":        entries,
    }
    MANIFEST.parent.mkdir(exist_ok=True)
    with open(MANIFEST,'w') as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
    return obj

def compare(old_entries, new_entries):
    """Detecteer toegevoegde, verwijderde en gewijzigde bestanden."""
    added    = {k: v for k,v in new_entries.items() if k not in old_entries}
    removed  = {k: v for k,v in old_entries.items() if k not in new_entries}
    changed  = {}
    for k in set(old_entries) & set(new_entries):
        if old_entries[k].get("sha256") != new_entries[k].get("sha256"):
            changed[k] = {
                "old_hash": old_entries[k].get("sha256","?"),
                "new_hash": new_entries[k].get("sha256","?"),
                "old_mtime": old_entries[k].get("mtime","?"),
                "new_mtime": new_entries[k].get("mtime","?"),
            }
    return added, removed, changed

def write_change_report(added, removed, changed, timestamp):
    REPORTS.mkdir(exist_ok=True)
    date = timestamp[:10]
    path = REPORTS / f"WIJZIGINGEN_{date}.md"

    lines = [
        f"# BEWIJS-INTEGRITEITSRAPPORT — {timestamp}",
        f"SHA-256 wijzigingsdetectie | Dossier Grothe BSN 215672185\n",
    ]

    if not added and not removed and not changed:
        lines.append("**Geen wijzigingen gedetecteerd.** Alle bestanden intact.")
    else:
        if changed:
            lines += [
                f"## ⚠️ GEWIJZIGDE BESTANDEN ({len(changed)})",
                "| Bestand | Oude hash | Nieuwe hash | Mtime oud | Mtime nieuw |",
                "|---------|-----------|-------------|-----------|-------------|",
            ]
            for f,d in sorted(changed.items()):
                lines.append(f"| `{f}` | `{d['old_hash'][:12]}…` | `{d['new_hash'][:12]}…` | {d['old_mtime'][:16]} | {d['new_mtime'][:16]} |")
            lines.append("\n> **KRITIEK:** gewijzigde bestanden kunnen bewijs-manipulatie indiceren. Vergelijk met Git-history en ingebrekestelling-versies.\n")

        if removed:
            lines += [f"\n## ❌ VERWIJDERDE BESTANDEN ({len(removed)})", ""]
            for f in sorted(removed):
                lines.append(f"- `{f}` (was: {removed[f].get('sha256','?')[:16]}…)")
            lines.append("\n> Verwijderde bestanden documenteren voor bewijslast-integriteit.\n")

        if added:
            lines += [f"\n## ✅ NIEUWE BESTANDEN ({len(added)})", ""]
            for f in sorted(added):
                lines.append(f"- `{f}` → SHA-256: `{added[f].get('sha256','?')}`")

    path.write_text('\n'.join(lines), encoding='utf-8')
    return path

def run(init=False):
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    print(f"[{ts}] SHA-256 manifest scan")

    old_manifest = load_manifest()
    old_entries  = old_manifest.get("files", {})

    new_entries = scan_all()
    print(f"  Bestanden gescand: {len(new_entries)}")

    added, removed, changed = compare(old_entries, new_entries)

    if changed:
        print(f"  ⚠️  GEWIJZIGD: {len(changed)} bestanden")
        for f in list(changed)[:5]:
            print(f"      {f}")
    if removed:
        print(f"  ❌ VERWIJDERD: {len(removed)} bestanden")
    if added:
        print(f"  ✅ NIEUW: {len(added)} bestanden")
    if not changed and not removed and not added:
        print("  Alle bestanden intact — geen wijzigingen")

    save_manifest({"generated": ts}, new_entries)
    rpt = write_change_report(added, removed, changed, ts)
    print(f"  Rapport: {rpt}")
    print(f"  Manifest: {MANIFEST}")

    return added, removed, changed

if __name__ == "__main__":
    init = "--init" in sys.argv
    run(init=init)
