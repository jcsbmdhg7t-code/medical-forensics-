Voer een Drive-audit uit voor het forensisch dossier Grothe:

```bash
cd /home/user/nd-connection-platform
python3 forensic/drive_audit.py $ARGUMENTS
```

Standaard genereert dit `extracted_docs/DRIVE_AUDIT_$(date).md` met alle bestanden gemarkeerd als NIET_GEZIEN / GENOEMD / GEANALYSEERD.

Met `--download-small` worden previews van top-50 kleine niet-geziene bestanden ook gedownload.

Als GOOGLE_ACCESS_TOKEN niet gezet is, geef de instructie:
"Stel een access token in via OAuth Playground (https://developers.google.com/oauthplayground) — scope: drive.readonly. Daarna: export GOOGLE_ACCESS_TOKEN=ya29... en run /drive-audit opnieuw"

Rapporteer na uitvoer: aantal NIET_GEZIEN, aantal bloedwaarde-bestanden, aantal tekst-prefix bestanden, en de top-5 prioriteit-files.
