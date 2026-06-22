#!/usr/bin/env python3
"""
Dagelijkse forensische analyse pipeline — Grothe dossier
Leest extracted_docs/ recursief, genereert index + Excel + todo-lijst.
Read-only op bronbestanden. Output naar reports/.
"""

import os, re, json, datetime, hashlib, textwrap
from pathlib import Path

ROOT = Path(__file__).parent.parent
EXTRACTED = ROOT / "extracted_docs"
REPORTS   = ROOT / "reports"
INDEX_FILE = ROOT / "forensic" / "evidence_index.json"
REPORTS.mkdir(exist_ok=True)

TODAY = datetime.date.today().isoformat()

# ── Juridische standaarden ─────────────────────────────────────────────────

BEWIJS_WEIGHTS = {"H": 3, "HOOG": 3, "MIDDEL": 2, "LAAG": 1, "PENDING": 0}

LEGAL_PATTERNS = {
    "AVG_art5":     (r"AVG\s+art\.?\s*5",             "AVG art. 5 (beginselen verwerking)"),
    "AVG_art15":    (r"AVG\s+art\.?\s*15",             "AVG art. 15 (inzagerecht)"),
    "AVG_art18":    (r"AVG\s+art\.?\s*18",             "AVG art. 18 (beperking verwerking)"),
    "WGBO_454":     (r"WGBO\s+7:454|7:454",            "WGBO art. 7:454 (dossierplicht)"),
    "WGBO_456":     (r"WGBO\s+7:456|7:456",            "WGBO art. 7:456 (inzage patiënt)"),
    "BIG_36":       (r"BIG\s+art\.?\s*36|art\.\s*36",  "Wet BIG art. 36 (behandelrelatie)"),
    "BIG_47":       (r"BIG\s+art\.?\s*47",             "Wet BIG art. 47 (tuchtrecht)"),
    "Sr_225":       (r"[Aa]rt\.?\s*225\s*Sr|225\s*Sr", "Art. 225 Sr (valsheid in geschrifte)"),
    "Sr_282":       (r"[Aa]rt\.?\s*282\s*Sr",          "Art. 282 Sr (vrijheidsberoving)"),
    "BW_6170":      (r"6:170\s*BW|art\.\s*6:170",      "Art. 6:170 BW (werkgeversaansp.)"),
    "NEN7510":      (r"NEN[\s-]?7510",                 "NEN 7510 (informatiebeveiliging zorg)"),
    "NEN7513":      (r"NEN[\s-]?7513",                 "NEN 7513 (logging zorgaanbieders)"),
}

ACTOR_PATTERNS = {
    "al_mousawi":   (r"[Aa]l[\s-]?[Mm]ousawi|MOUSAWI|84126524",    "A. al-Mousawi", "AGB 84126524"),
    "van_der_list": (r"[Vv]an\s+der\s+[Ll]ist|84115003",           "J.P.J. van der List", "AGB 84115003"),
    "nota":         (r"\bNota\b|N\.M\.\s*Nota|84107660|51504662",   "N.M. Nota", "AGB 84107660"),
    "blauw":        (r"\bBlauw\b|J\.M\.\s*Blauw",                  "J.M. Blauw", "AGB pending"),
    "van_der_kroon":(r"[Vv]an\s+der\s+[Kk]roon|MRK\b",            "M. van der Kroon (MRK)", "FACILITAIR"),
    "burlage":      (r"\bBurlage\b|AGB\s*67480",                   "K.J. Burlage", "AGB 67480 (deceased)"),
    "kox":          (r"\bKox\b|D\.\s*Kox",                        "D. Kox", "KNO-arts"),
    "nota_de_ree":  (r"[Dd]e\s+[Rr]ee\b",                         "J.E.L.M. de Ree", "Reumatoloog"),
    "van_lelyveld": (r"[Vv]an\s+[Ll]elyveld",                     "S.F.L. van Lelyveld", "Internist"),
    "verlaan":      (r"\bVerlaan\b",                               "Verlaan", "Huisarts"),
    "hoppinger":    (r"[Hh]oppinger",                              "Hoppinger B.V.", "Webontwikkelaar"),
}

NB_PATTERN = re.compile(r'NB[-‑](\d+)', re.IGNORECASE)
DATE_PATTERN = re.compile(r'\b(\d{2}-\d{2}-\d{4}|\d{4}-\d{2}-\d{2})\b')
BEWIJS_PATTERN = re.compile(r'Bewijswaarde[:\s]+([A-Z]+|HOOG|MIDDEL|LAAG)', re.IGNORECASE)
TODO_PATTERN = re.compile(r'- \[ \] (.+)')
HYPO_PATTERN = re.compile(r'(?:hypothese|scenario|vermoeden)[:\s]+(.{20,200})', re.IGNORECASE)

CAUSAL_KEYWORDS = [
    ("13-01-2020", "02-10-2024", "Al-Mousawi SEH-entry → Nota massa-sluiting (NB-108/160)"),
    ("04-12-2017", "02-10-2024", "F19.1 registratie → 5 diagnoses gesloten (CC-A kern)"),
    ("10-01-2026", "03:34:55",  "AVG-bevriezingsverzoek → nachtelijke batch edit (NB-166)"),
    ("Burlage",    "deceased",   "Post-mortem naam ingevoerd als huisarts (NB-36)"),
    ("override.css","MRK",      "Facilitair admin 2017 → CSS-hiding 2024-2025 (NB-168/CC-J)"),
]

# ── Extractor ──────────────────────────────────────────────────────────────

def file_hash(path):
    h = hashlib.md5()
    h.update(Path(path).read_bytes())
    return h.hexdigest()[:8]

def extract_from_file(path):
    """Extract structured data from a markdown/text file."""
    path = Path(path)
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except Exception as e:
        return None

    result = {
        "file": str(path.relative_to(ROOT)),
        "hash": file_hash(path),
        "size_kb": round(path.stat().st_size / 1024, 1),
        "modified": datetime.datetime.fromtimestamp(path.stat().st_mtime).isoformat()[:16],
        "analyzed": TODAY,
        "nb_refs": sorted(set(NB_PATTERN.findall(text)), key=lambda x: int(x)),
        "legal_refs": [],
        "actors": [],
        "dates_found": [],
        "todos": TODO_PATTERN.findall(text),
        "hypotheses": HYPO_PATTERN.findall(text),
        "bewijs_weight": "PENDING",
        "spoor": "ONBEKEND",
        "summary": "",
    }

    # Legal references
    for key, (pattern, label) in LEGAL_PATTERNS.items():
        if re.search(pattern, text):
            result["legal_refs"].append(label)

    # Actor detection
    for key, (pattern, name, role) in ACTOR_PATTERNS.items():
        if re.search(pattern, text):
            result["actors"].append(f"{name} ({role})")

    # Dates
    dates = DATE_PATTERN.findall(text)
    result["dates_found"] = sorted(set(dates))[:20]

    # Evidence weight (highest found wins)
    weights = BEWIJS_PATTERN.findall(text)
    if weights:
        best = max(weights, key=lambda w: BEWIJS_WEIGHTS.get(w.upper(), 0))
        result["bewijs_weight"] = best.upper()

    # Spoor detection
    text_lower = text.lower()
    has_spaarne = "spaarne" in text_lower or "spaarnegasthuis" in text_lower
    has_parnassia = "parnassia" in text_lower or "altrecht" in text_lower or "psyq" in text_lower
    if has_spaarne and has_parnassia:
        result["spoor"] = "BEIDE (check scheiding!)"
    elif has_spaarne:
        result["spoor"] = "Spaarne/huisarts"
    elif has_parnassia:
        result["spoor"] = "Parnassia/GGZ"

    # Short summary: first non-empty heading or first 200 chars
    heading = re.search(r'^#{1,3}\s+(.+)$', text, re.MULTILINE)
    if heading:
        result["summary"] = heading.group(1)[:200]
    else:
        result["summary"] = text.strip()[:200].replace('\n', ' ')

    return result

# ── Diepte-analyse bij patroondetectie ────────────────────────────────────

# Patronen die een volledige diepte-analyse triggeren
DEPTH_TRIGGERS = {
    "vierpatroon_bevoegdheid": {
        "pattern": r"(NB-173|J\.M\.\s*Blauw|84114458|basisarts.*29-11-2019)",
        "label":   "Bevoegdheidspatroon vierpatroon",
        "followup": [
            "Controleer alle andere laborders in het dossier: zijn er meer zonder gedocumenteerd consult?",
            "Zoek naar providers met enkel laborders maar geen bezoekentry in het overzicht",
            "Vergelijk alle AGB-codes met bezoekenoverzicht — welke AGB's verschijnen ALLEEN in labs?",
        ]
    },
    "nachtelijke_batch": {
        "pattern": r"(03:34:55|04:34|nachtelijk.*batch|batch.*nachtelijk|AVG.*bevriezing.*nacht)",
        "label":   "Nachtelijke batchoperatie",
        "followup": [
            "Zijn er andere tijdstippen tussen 00:00-05:00 in de XML/HAR bestanden?",
            "Controleer of de batch-timestamps samenvallen met andere juridische momenten (verzoeken, zittingen)",
            "Zoek naar identieke milliseconde-timestamps in meerdere documenten (verdere automatisering)",
        ]
    },
    "tweemansprocedure": {
        "pattern": r"(tweemansprocedure|NB-108|SUBSTANCEHXQNR.*Mousawi|Nota.*sluit.*Mousawi|02-10-2024.*beide)",
        "label":   "Tweemansprocedure 02-10-2024",
        "followup": [
            "Zijn er andere datums waarop Nota én Mousawi beiden actief waren in het dossier?",
            "Controleer alle SUBSTANCEHXQNR-entries: hoeveel zijn er zonder behandelrelatie?",
            "Zoek naar andere module-combinaties die hetzelfde patroon vertonen op andere data",
        ]
    },
    "tijdsdiscrepantie_agb": {
        "pattern": r"(84126524|84115003|84107660|te vroeg|3.5.*jr|1.5.*jr|vóór.*registratie)",
        "label":   "AGB-tijdsdiscrepantie",
        "followup": [
            "Zijn er nog meer AGB-codes in het dossier die niet in Vektis terugkomen?",
            "Controleer alle providers in BEVINDING C (bezoekenoverzicht) op Vektis-registratiedatum",
            "Zoek naar AGB-codes in de XML-bestanden die afwijken van de AANVULLEND-providers-lijst",
        ]
    },
    "spoorvermenging": {
        "pattern": r"(BEIDE.*check scheiding|Parnassia.*Spaarne|Spaarne.*Parnassia).*correspondentie",
        "label":   "Mogelijk spoorvermenging",
        "followup": [
            "KRITIEK: controleer dit bestand op vermenging Parnassia/Spaarne vóór gebruik in brieven",
        ]
    },
}

def run_depth_analysis(findings, index):
    """
    Bij elk gedetecteerd patroon: schrijf een volledig diepte-analyseverslag
    en genereer vervolgzoekopdrachten. Resultaat in reports/DIEPTE_[datum].md
    """
    triggered = {}  # trigger_key → list of (file, matches)

    for f in findings:
        text_check = f.get("summary","") + " ".join(f.get("nb_refs",[])) + " ".join(f.get("actors",[]))
        # Also check the actual file content for triggers
        fpath = ROOT / f["file"]
        try:
            full_text = fpath.read_text(encoding='utf-8', errors='replace')
        except:
            full_text = text_check

        for key, cfg in DEPTH_TRIGGERS.items():
            matches = re.findall(cfg["pattern"], full_text, re.IGNORECASE)
            if matches:
                if key not in triggered:
                    triggered[key] = []
                triggered[key].append({
                    "file": f["file"],
                    "matches": list(set(str(m) for m in matches))[:5],
                    "bewijs": f.get("bewijs_weight","?"),
                })

    if not triggered:
        return None

    lines = [f"# DIEPTE-ANALYSE RAPPORT — {TODAY}",
             f"Patronen gedetecteerd: {len(triggered)} | Gegenereerd door forensic/pipeline.py\n"]

    for key, hits in triggered.items():
        cfg = DEPTH_TRIGGERS[key]
        lines.append(f"## {cfg['label']}")
        lines.append(f"Gevonden in {len(hits)} bestand(en):\n")
        for h in hits:
            lines.append(f"- `{Path(h['file']).name}` (bewijs: {h['bewijs']}) — matches: {', '.join(h['matches'])}")

        lines.append("\n### Vervolgonderzoek vereist")
        for fu in cfg["followup"]:
            lines.append(f"- [ ] {fu}")
        lines.append("")

    # Cross-patroon verbanden
    if len(triggered) > 1:
        lines.append("## Kruisverbanden gedetecteerde patronen")
        keys = list(triggered.keys())
        lines.append(f"Meerdere patronen ({', '.join(keys)}) actief in zelfde dossier.")
        lines.append("Dit vergroot de kans op een gecoördineerd patroon ten opzichte van toevallige fouten.")
        lines.append("Aanbeveling: formaliseer causale verbanden in WERKDOCUMENT vóór volgende zitting.\n")

    path = REPORTS / f"DIEPTE_{TODAY}.md"
    path.write_text('\n'.join(lines), encoding='utf-8')
    return path

def scan_directory(directory):
    """Recursively scan all readable files."""
    findings = []
    for path in sorted(Path(directory).rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in ('.md', '.txt', '.json', '.xml', '.csv', '.py', '.js'):
            continue
        if '.git' in path.parts:
            continue
        r = extract_from_file(path)
        if r:
            findings.append(r)
    return findings

# ── Index management ───────────────────────────────────────────────────────

def load_index():
    if INDEX_FILE.exists():
        with open(INDEX_FILE) as f:
            return json.load(f)
    return {"created": TODAY, "entries": {}, "causal_map": [], "hypotheses": [], "todos": []}

def save_index(index):
    INDEX_FILE.parent.mkdir(exist_ok=True)
    with open(INDEX_FILE, 'w') as f:
        json.dump(index, f, indent=2, ensure_ascii=False)

def update_index(index, findings):
    """Merge new findings into the index, tracking changes."""
    new_count = 0
    updated_count = 0
    for f in findings:
        key = f["file"]
        existing = index["entries"].get(key, {})
        if existing.get("hash") != f["hash"]:
            if key in index["entries"]:
                updated_count += 1
            else:
                new_count += 1
            index["entries"][key] = f

    # Accumulate all todos and hypotheses
    all_todos = []
    all_hypos = []
    for entry in index["entries"].values():
        for t in entry.get("todos", []):
            if t not in all_todos:
                all_todos.append(t)
        for h in entry.get("hypotheses", []):
            if h not in all_hypos:
                all_hypos.append(h)
    index["todos"] = all_todos
    index["hypotheses"] = all_hypos
    index["last_updated"] = TODAY
    index["causal_map"] = CAUSAL_KEYWORDS

    return new_count, updated_count

# ── Report generators ──────────────────────────────────────────────────────

def generate_daily_todo(index):
    """Write daily TODO markdown."""
    path = REPORTS / f"TODO_{TODAY}.md"
    fixed_todos = [
        ("KRITIEK", "28-06-2026", "Parnassia M26015970: portaaltoegang + logging vervalt"),
        ("HOOG",    "22-07-2026", "Zitting Rechtbank Noord-Holland C/15/376914"),
        ("HOOG",    "03-08-2026", "Hof van Discipline 260153: uitspraak"),
        ("HOOG",    "PM",         "AGB J.M. Blauw opzoeken via Vektis → vs. 29-11-2019"),
        ("HOOG",    "PM",         "IGJ_VOLLEDIG_DOSSIER_20260621.docx lezen"),
        ("HOOG",    "PM",         "AP_VOLLEDIG_DOSSIER_20260621.docx lezen"),
        ("HOOG",    "PM",         "AP_klacht_aanvulling_driepatroon bijwerken met Blauw (NB-173)"),
        ("MIDDEL",  "PM",         "WERKDOCUMENT NB-173 formaliseren"),
        ("MIDDEL",  "PM",         "Actor 470154242 identificeren"),
        ("MIDDEL",  "PM",         "Caren person-ID 492769 screenshot analyseren"),
        ("MIDDEL",  "PM",         "NB-160 causale keten 13-01-2020 → 02-10-2024"),
        ("MIDDEL",  "PM",         "NB-148 Van der List formaliseren"),
    ]

    lines = [f"# TODO — {TODAY}\n", "## Vaste deadlines + prioriteiten\n",
             "| Prioriteit | Deadline | Actie |", "|-----------|---------|-------|"]
    for prio, dl, item in fixed_todos:
        lines.append(f"| {prio} | {dl} | {item} |")

    lines.append("\n## Openstaand uit dossierbestanden\n")
    for todo in index.get("todos", []):
        lines.append(f"- [ ] {todo}")

    path.write_text('\n'.join(lines), encoding='utf-8')
    return path

def generate_daily_index_md(index):
    """Write daily markdown index."""
    path = REPORTS / f"INDEX_{TODAY}.md"
    entries = list(index["entries"].values())

    lines = [f"# FORENSISCHE INDEX — {TODAY}",
             f"Bestanden geanalyseerd: {len(entries)} | Bijgewerkt: {index.get('last_updated',TODAY)}\n",
             "| Bestand | Bewijs | NB's | Spoor | Actoren | Datum analyse |",
             "|---------|--------|------|-------|---------|---------------|"]
    for e in sorted(entries, key=lambda x: x.get("bewijs_weight",""), reverse=True):
        nb = ", ".join(e["nb_refs"][:5]) + ("…" if len(e["nb_refs"]) > 5 else "")
        actors = "; ".join(e["actors"][:2]) + ("…" if len(e["actors"]) > 2 else "")
        fname = Path(e["file"]).name
        lines.append(f"| {fname} | {e['bewijs_weight']} | {nb} | {e['spoor']} | {actors} | {e['analyzed']} |")

    lines += ["\n## Causale verbanden\n",
              "| Van | Naar | Verband |", "|-----|------|---------|"]
    for fr, to, desc in index.get("causal_map", []):
        lines.append(f"| {fr} | {to} | {desc} |")

    path.write_text('\n'.join(lines), encoding='utf-8')
    return path

# ── Main ───────────────────────────────────────────────────────────────────

def run():
    print(f"[{TODAY}] Forensische pipeline start")

    # Scan
    findings = scan_directory(EXTRACTED)
    findings += scan_directory(ROOT / "forensic")
    print(f"  Bestanden gescand: {len(findings)}")

    # Index
    index = load_index()
    new, updated = update_index(index, findings)
    save_index(index)
    print(f"  Nieuw: {new} | Bijgewerkt: {updated} | Totaal: {len(index['entries'])}")

    # Reports
    todo_path = generate_daily_todo(index)
    index_path = generate_daily_index_md(index)

    # Diepte-analyse bij patroondetectie
    depth_path = run_depth_analysis(findings, index)
    if depth_path:
        print(f"  Diepte: {depth_path}")

    # Excel (separate module)
    try:
        from forensic.excel_report import generate_excel
        xl_path = generate_excel(index, TODAY)
        print(f"  Excel: {xl_path}")
    except Exception as e:
        print(f"  Excel overgeslagen: {e}")

    print(f"  TODO:  {todo_path}")
    print(f"  Index: {index_path}")
    print(f"[{TODAY}] Pipeline klaar")

if __name__ == "__main__":
    run()
