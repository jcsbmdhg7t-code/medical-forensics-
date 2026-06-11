# FORENSISCH RAPPORT – MEDISCHE CODES & DOCUMENTEXTRACTIE
**Aangemaakt:** 2026-06-11  
**Bronbestanden:** 5 geüploade bestanden  
**Status:** Geanonimiseerd – persoonsgegevens verwijderd

---

## 1. GEÏDENTIFICEERDE BESTANDEN

| Bestandshash (prefix) | Bronbestand | Inhoud |
|---|---|---|
| 73f47b6c | Proxyman HAR audit/grep export | Netwerk audit log (.har captures) |
| f67e691d | GEVONDEN_VERBORGEN_DATA.txt | Binaire PNG screenshot data (XMP metadata) |
| 6972e665 | .zip (allergies/medications/problems JSON) | Gecomprimeerde API ruwe data |
| 792a832e | GEVONDEN_VERBORGEN_DATA_3.txt | Binaire PNG screenshot data (IDAT chunks) |
| 760583ed | GEVONDEN_VERBORGEN_DATA.txt | **HL7 CDA XML – Patiëntsamenvatting (data-2.xml)** |

---

## 2. GEËXTRAHEERD ORIGINEEL DOCUMENT: HL7 CDA Patiëntsamenvatting

**Bron:** `data-2.xml`  
**Hash bron:** 2db739ecd3c16f2697dd4fc0061ab6f29fefb59d031d57bd22d2d5ed3c5d024e  
**Standaard:** HL7 CDA R2 / IPS (International Patient Summary)  
**Aangemaakt door:** Epic versie 10.8, Spaarne Gasthuis  
**Documentdatum:** 17-10-2024 14:19:02 +0200  
**LOINC documenttype:** 60591-5 (Patient Summary Document)  
**Zorginstelling:** Spaarne Gasthuis, Hoofddorp / Haarlem

---

## 3. ALLERGIE

| Veld | Waarde |
|---|---|
| Stof | **Amoxicilline/Clavulaanzuur** |
| Status | Actief |
| Ernst | Licht (Mild) |
| Vastgelegd | 29-11-2018 |
| Reactie | Gelaat iets zwellen, geen benauddheid of zwellen hals |

### Codes – Allergie
| Codesysteem | Code | Omschrijving |
|---|---|---|
| G-standaard SNK | **23167** | Amoxicilline/Clavulaanzuur (stofnaam) |
| G-standaard SNK | **31232** | Vertaling stofnaam |
| SNOMED CT | **255604002** | Mild (ernst) |
| SNOMED CT | **246112005** | Severity (ernst observatie) |
| LOINC | **48767-8** | Annotation comment |
| LOINC | **33999-4** | Status |
| HL7 ActStatus | **active** | Actief |

---

## 4. MEDICATIE (actief)

| Veld | Waarde |
|---|---|
| Middel | **DEXAMFETAMINE (FNA) 5MG CAPSULE** |
| Dosering | 7,5 mg oraal, 5× per dag |
| Startdatum | 04-12-2017 |
| Status | Actief |

> Dexamfetamine is een centraal stimulerend middel (amfetamine), gebruik bij o.a. ADHD. Totale dagdosering: 37,5 mg.

### Codes – Medicatie
| Codesysteem | Code | Omschrijving |
|---|---|---|
| G-Standaard ZI | **15263665** | DEXAMFETAMINE (FNA) 5MG CAPSULE |
| G-Standaard HPK | **1855522** | Handelsverpakking |
| G-Standaard PRK | **82589** | Prescriptie referentiecode |
| G-Standaard GPK | **126713** | Generiek product |
| SNOMED CT | **16076005** | Medicatieafspraak (prescription) |
| NCI Thesaurus | **9** | Route: Oraal |
| G-Standaard eenheid | **229** | Milligram (mg) |

---

## 5. ACTIEVE PROBLEMEN

### Myalgie
| Veld | Waarde |
|---|---|
| Diagnose | **Myalgie** (spierpijn) |
| Vastgelegd | 02-10-2024 |
| Status | Actief |
| Specialisme | Reumatologie |

| Codesysteem | Code | Omschrijving |
|---|---|---|
| SNOMED CT | **68962001** | Myalgia |
| ICD-10 | **M79.19** | Myalgie, niet gespecificeerd |
| DHD Thesaurus | **0000008714** | Myalgie |

---

## 6. GESLOTEN PROBLEMEN (historisch)

### A – Neusdruppelmisbruik
| Periode | Codesysteem | Code | Omschrijving |
|---|---|---|---|
| 04-12-2017 t/m 02-10-2024 | SNOMED CT | **741000146107** | Neusdruppelmisbruik |
| | ICD-10 | **F19.1** | Schadelijk gebruik psychoactieve stoffen (overig) |
| | DHD Thesaurus | **0000005722** | Neusdruppelmisbruik |

> ICD-10 F19.1: klinisch toegepast voor xylometazoline-afhankelijkheid (neusdruppelverslaving).

### B – Paronychia van Vinger
| Periode | Codesysteem | Code | Omschrijving |
|---|---|---|---|
| 28-11-2018 t/m 02-10-2024 | SNOMED CT | **444646006** | Paronychia van vinger |
| | ICD-10 | **L03.0** | Cellulitis van vinger (flegmoon) |
| | DHD Thesaurus | **0000038111** | Paronychia van vinger |

### C – Vermoeidheid
| Periode | Codesysteem | Code | Omschrijving |
|---|---|---|---|
| 13-11-2019 t/m 02-10-2024 | SNOMED CT | **84229001** | Vermoeidheid (fatigue) |
| | ICD-10 | **R53** | Malaise en vermoeidheid |
| | DHD Thesaurus | **0000011510** | Vermoeidheid |

### D – Casus pro diagnosi
| Periode | Codesysteem | Code | Omschrijving |
|---|---|---|---|
| 13-01-2020 t/m 02-10-2024 | SNOMED CT | **41021000146105** | Casus pro diagnosi |
| | ICD-10 | **R69** | Onbekende/niet nader omschreven oorzaken van ziekte |
| | DHD Thesaurus | **0000058478** | Casus pro diagnosi |

---

## 7. SOCIALE ANAMNESE

| Categorie | Bevinding | Codes |
|---|---|---|
| Tabak | Voormalig roker (sigaretten) | – |
| Alcohol | Nooit (0 eenheden/week) | – |
| Drugs | Ja – sporadisch | LOINC **42831-8**, SNOMED **228366006** + **361055000** |

---

## 8. CONTACTEN (afgelopen 3 maanden v.a. documentdatum)

| Datum | Type | Afdeling |
|---|---|---|
| 15-10-2024 | Telefonisch consult | Polikliniek Reumatologie, Haarlem |
| 02-10-2024 | Ondersteunende verrichting | Afdeling Radiologie, Haarlem |
| 02-10-2024 | Nieuwe Patiënt | Polikliniek Reumatologie, Haarlem |

**Specialisme codes:** VEKTIS `0324` (Arts i.o. Reumatologie) / Epic `99` (Reumatologie)

---

## 9. AUDIT LOG – NETWERKTOEGANG (HAR bestand)

**Proxytool:** Proxyman v3.17.0 (MITM proxy)  
**Capture datum:** 03-03-2026  
**Grep filter toegepast:** `audit|inzage|access|log|raadpleging`

### Bezochte systemen tijdens capture
| Domein | Tijdstip | Systeem |
|---|---|---|
| `auth.mijnspaarnegasthuis.nl` | 03-03-2026 11:50 | MijnSpaarne Gasthuis SSO (A-Select) |
| `apigateway.pharmeon.nl` | 03-03-2026 12:08 | Pharmeon medicijnen API |
| `www.mijnspaarnegasthuis.nl` | 03-03-2026 11:58 | Patiëntenportaal Spaarne Gasthuis |
| `www.mijngezondheid.net` | 03-03-2026 17:11 | MijnGezondheid.net portaal |
| `www.gezondheidsmeter.nl` | 03-02-2026 18:19 | Gezondheidsmeter portaal |
| `ocsp.digicert.com` | 03-03-2026 18:29 | Certificaatverificatie |

**Authenticatiemethode:** A-Select SSO protocol (request=login1, rid-tokens aanwezig)

---

## 10. SCREENSHOTS (binaire PNG bestanden)

| Datum screenshot | Afmetingen | Bestandshash (prefix) |
|---|---|---|
| 11-05-2026 04:03 | 1802×1882 px | 5d660b9b |
| 06-01-2026 23:37 | n.v.t. | 1ce73dcd |
| 11-01-2026 22:31 | 2880×1800 px | 8ec89b4d |

> Beeldinhoud niet leesbaar zonder OCR (binaire PNG/IDAT data).

---

## 11. VOLLEDIGE CODE-TABEL

| Categorie | Code | Systeem | NL Omschrijving |
|---|---|---|---|
| Document | 60591-5 | LOINC | Patiëntsamenvatting |
| Allergie stof | 23167 | G-std SNK | Amoxicilline/Clavulaanzuur |
| Allergie ernst | 255604002 | SNOMED CT | Mild |
| Medicatie product | 15263665 | G-std ZI | Dexamfetamine 5mg capsule |
| Medicatie generiek | 126713 | G-std GPK | Dexamfetamine generiek |
| Diagnose actief | M79.19 | ICD-10 | Myalgie |
| Diagnose actief | 68962001 | SNOMED CT | Myalgie |
| Diagnose gesloten | F19.1 | ICD-10 | Neusdruppelmisbruik |
| Diagnose gesloten | 741000146107 | SNOMED CT | Neusdruppelmisbruik |
| Diagnose gesloten | L03.0 | ICD-10 | Paronychia vinger |
| Diagnose gesloten | 444646006 | SNOMED CT | Paronychia vinger |
| Diagnose gesloten | R53 | ICD-10 | Vermoeidheid |
| Diagnose gesloten | 84229001 | SNOMED CT | Vermoeidheid |
| Diagnose gesloten | R69 | ICD-10 | Casus pro diagnosi |
| Diagnose gesloten | 41021000146105 | SNOMED CT | Casus pro diagnosi |
| Sociaal | 42831-8 | LOINC | Drug abuse |
| Sociaal | 361055000 | SNOMED CT | Drugsgebruik (bevinding) |

---

*Rapport geanonimiseerd – persoonsidentificerende gegevens (naam, BSN, adres, telefoon) niet opgenomen.*
