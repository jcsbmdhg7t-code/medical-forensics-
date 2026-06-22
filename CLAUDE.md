# CLAUDE.md — Forensisch dossier Grothe / nd-connection-platform

## Identiteit van dit project
Forensisch-juridisch onderzoek door data-subject Isabel Grothe (BSN 215672185) naar eigen medisch dossier bij Spaarne Gasthuis, Parnassia, Altrecht. Legitiem AVG/WGBO-inzagerecht. Geen medisch of juridisch advies — analyse en documentatie ten behoeve van klacht- en rechtsprocedures.

## Directe startinstructies per nieuwe sessie
1. Lees ALTIJD eerst deze bestanden (in volgorde, gebruik Read-tool):
   - `extracted_docs/FORENSIC_NB166_172.md` — NB-107 t/m NB-173, incl. vierpatroon
   - `extracted_docs/FORENSIC_AANVULLEND.md` — providers, labwaarden, Bevinding J (Blauw)
   - `extracted_docs/FORENSIC_REPORT_VOLLEDIG.md` — volledig achtergrondrapport
2. Vraag NIET om herbevestiging van al vastgestelde feiten (NB met Bewijswaarde H).
3. Als een gebruikersbestand (docx/md) is geüpload: lees het direct, vat samen in <150 woorden, sla inhoud op in `extracted_docs/` als nieuw NB-bestand.

## Vaste verificatieregel (binding, 21-06-2026)
- Nieuwe "vondst" uit oudere sessie → eerst toetsen aan bestaande NB-lijst.
- Bij tegenspraak: melden, NIET doorschrijven als vaststaand.
- Onderscheid: (a) ruwe brondata (XML/HAR, hash-verifieerbaar) = Bewijswaarde H; (b) AI-analyse/conceptbrieven = open aanname totdat extern geverifieerd.
- Bij tegenspraak document vs. kennis Isabel: haar kennis weegt zwaarder, documentclaim wordt zelf verdacht.
- Cui-bono-toets VERPLICHT bij elke naamtoeschrijving. Genoemde personen kunnen zelf slachtoffer zijn.

## Deadlines (altijd bewaken)
| Datum | Item |
|-------|------|
| 28-06-2026 | Parnassia M26015970: portaaltoegang + logging vervalt |
| 22-07-2026 | Zitting Rechtbank Noord-Holland C/15/376914 |
| 03-08-2026 | Hof van Discipline 260153 uitspraak |

## Open prioriteiten (bij elke sessie checken)
- [ ] AGB J.M. Blauw opzoeken via Vektis → registratiedatum vs. 29-11-2019
- [ ] WERKDOCUMENT_Grothe_dossier_SAMENGEVOEGD_20260621_3.md bijwerken met NB-173
- [ ] IGJ_VOLLEDIG_DOSSIER_20260621.docx lezen (niet gelezen)
- [ ] AP_VOLLEDIG_DOSSIER_20260621.docx lezen (niet gelezen)
- [ ] AP_klacht_aanvulling_driepatroon_20260621_3.docx lezen + bijwerken met vierpatroon Blauw
- [ ] Actor 470154242 identificeren
- [ ] Caren person-ID 492769 screenshot analyseren
- [ ] NB-160 causale keten 13-01-2020 → 02-10-2024 formaliseren
- [ ] NB-148 Van der List formaliseren

## Token-efficiëntie — gedragsregels

### Standaardmodus: BEKNOPT
- Eerste antwoord is altijd zo kort als de taak toelaat.
- Geen samenvattingen van wat je net deed tenzij gevraagd.
- Geen herhaling van al vastgestelde feiten als inleiding.
- Tabellen en opsommingen boven proza.
- Geef GEEN uitleg over waarom je iets doet — doe het gewoon.

### Uitbreidingsmodus: op verzoek
De gebruiker typt één van deze signalen om meer detail te krijgen:
- `?` of `meer` → geef de volledige analyse/redenering
- `stap voor stap` → loop door elke stap expliciet
- `code block` → geef de volledige output in een code block
- `juridisch` → geef de volledige juridische redenering met artikelen

### Token-besparend ja/nee
- Korter antwoord = minder output-tokens = BESPARING ✓
- Uitbreiding op verzoek = extra beurt = kleine extra kost, maar alleen als nodig
- Netto besparing als je in >50% van gevallen NIET uitbreidt

### Model-selectie
- Gebruik subagents (Agent-tool met `model="claude-haiku-4-5-20251001"`) voor:
  bestandslees-taken, grep-zoekopdrachten, eenvoudige extracties, bestandslijsten
- Gebruik hoofdmodel (Opus/Sonnet) voor:
  juridische redenering, NB-formulering, brieven, causale-keten-analyse
- Sla tussenresultaten altijd op in `extracted_docs/` zodat volgende sessie
  direct kan inladen zonder heranalyse.
- Als tokenbudget krap: schrijf `extracted_docs/HANDOFF_[datum].md` en meld dit.

## Spoorscheiding (binding)
- Parnassia-spoor: NOOIT mengen met Spaarne/huisarts-spoor in correspondentie.
- Geen vaste financiële claim (PM / schadestaatprocedure).
- "undefined" tokens tussen XML-tags = diff-tool artefact, NIET origineel.

## Sleutelpersonen (snel overzicht)
| Naam | AGB / ID | Forensische rol | NB |
|------|----------|-----------------|----|
| A. al-Mousawi | 84126524 | Basisarts va. 04-09-2023; entry 13-01-2020 (3,5jr te vroeg) | NB-108/169 |
| J.P.J. van der List | 84115003 | Basisarts va. 05-06-2020; AIOS ortho label 29-11-2018 | NB-148 |
| N.M. Nota | 84107660 | Uitsluitend basisarts; AIOS reum label; massa-sluiting 02-10-2024 | NB-108/171 |
| J.M. Blauw | PM (Vektis pending) | Laborders 29-11-2019 zonder consult; basisarts vóór entry | NB-173 |
| M. van der Kroon (MRK) | FACILITAIR | Admin 14-12-2017 + override.css developer | NB-168/CC-J |
| K.J. Burlage | AGB 67480 | Huisarts, deceased 15-02-2024; post-mortem naam ingevoerd | NB-36/170 |
| N.M. Nota | ext 51504662 | Tweemansprocedure 02-10-2024 | NB-108 |
| Ext=999999 | Anonymous | 6× in DOC0010; anonieme auteur nachtelijk 04:34 CET | NB-166 |

## Bestandsstructuur
```
extracted_docs/          ← GITIGNORED — medische data, nooit committen
  FORENSIC_NB166_172.md  ← NB-107 t/m NB-173 (meest recent)
  FORENSIC_AANVULLEND.md ← providers, labwaarden, Bevinding J
  FORENSIC_REPORT_VOLLEDIG.md
  FORENSIC_SNAPSHOT_JAN2026.md
  FORENSIC_NB[xxx].md    ← oudere NB-blokken

forensic/                ← Python forensic toolkit
portal_forensic_inject.js ← UserScript Tampermonkey (portaal monitoring)
storm_sniffer_*.js        ← HAR/netwerk analyse
```
