# Ducky Support – Cloudflare Backend

Dateien:
- `index.html`: GitHub-Pages-Webseite
- `worker.js`: Cloudflare Worker API
- `schema.sql`: D1-Datenbanktabellen

## Noch vor dem Test

1. Cloudflare D1-Datenbank erstellen und `schema.sql` ausführen.
2. Worker `worker.js` deployen und eine D1-Bindung mit dem Variablennamen `DB` hinzufügen.
3. Im Worker unter **Settings → Variables and Secrets** ein Secret `ADMIN_PASSWORD` anlegen. Ein langes, einzigartiges Passwort verwenden. Nicht in GitHub oder in `index.html` speichern.
4. In `index.html` die Zeile `const API_BASE = ...` durch die echte `https://...workers.dev`-Adresse ersetzen.
5. `index.html` zu GitHub pushen/committen.

Die Worker-API verwendet D1 für Accounts, Nachrichten, Sessions und Bestellungen. Passwörter werden mit PBKDF2 gehasht. Admin-Zugangsdaten liegen nur als Cloudflare Secret vor.

Hinweis: Die Website ist erst vollständig verbunden, wenn Worker und D1 angelegt, konfiguriert und deployed wurden. GitHub Pages hostet nur die HTML-Datei.
