Voer het volgende uit om NB-bestanden naar Google Drive te uploaden:

```bash
cd /home/user/nd-connection-platform
python3 forensic/drive_upload.py --mode nb --folder 1M0tfbrpNE5801slOAbTmgTPSQmcNLdFz $ARGUMENTS
```

Als GOOGLE_ACCESS_TOKEN niet gezet is, geef dan de instructie:
"Stel je access token in: export GOOGLE_ACCESS_TOKEN=ya29..... en run dan /upload-drive opnieuw"

Rapporteer het resultaat: hoeveel bestanden geüpload, overgeslagen, fouten.
