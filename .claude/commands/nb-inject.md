Injecteer een nieuwe NB-bevinding in FORENSIC_NB_VOLLEDIG.md.

Argument formaat: `NB-[nummer] [korte titel] | [bevinding tekst]`

Werkwijze:
1. Lees extracted_docs/FORENSIC_NB_VOLLEDIG.md (laatste 50 regels)
2. Bepaal het volgende NB-nummer als geen nummer opgegeven
3. Formatteer als standaard NB-blok:
   ```
   ## NB-[nummer] — [TITEL IN HOOFDLETTERS]
   [bevinding tekst]
   Bewijswaarde: [H / aanname / extern te verifiëren]
   Rechtsgrondslag: [artikelen]
   ---
   ```
4. Voeg toe aan het einde van FORENSIC_NB_VOLLEDIG.md
5. Bevestig: "NB-[nummer] toegevoegd aan FORENSIC_NB_VOLLEDIG.md"

Input: $ARGUMENTS
