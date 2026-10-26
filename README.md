# PDF DRM Server

Ein selbst gehosteter Server, der PDFs verschlüsselt speichert, Zugriffe über
Lizenzen steuert und Dokumente nur als personalisierte, wasserzeichenbehaftete
Seitenbilder an einen Web-Viewer ausliefert.

## Funktionen

| Bereich | Umsetzung |
|---|---|
| **Verschlüsselung at rest** | AES-256-GCM, eigener Schlüssel (DEK) pro Dokument, gewrappt mit einem Master-Key (Envelope Encryption). Manipulierte Dateien werden erkannt. Der Master-Key lässt sich rotieren. |
| **Kein PDF beim Client** | Seiten werden serverseitig mit PDFium gerendert. Der Browser bekommt nur WebP-Bilder ohne Textebene und ohne Original-PDF. |
| **Wasserzeichen** | Gekacheltes diagonales Wasserzeichen und eine Fußzeile mit E-Mail (oder eigenem Text), Lizenz-ID und Zeitstempel, eingebrannt in jedes Bild. |
| **Lizenzen** | Gültigkeitszeitraum, max. Geräte, max. Öffnungen, Druck- und Download-Recht, eigener Wasserzeichentext. |
| **Sofortiger Widerruf** | Jeder Seitenabruf prüft Lizenz, Benutzerstatus und Gerätefreigabe erneut. Ein Widerruf, eine Benutzersperre oder ein entferntes Gerät wirkt sofort, auch in offenen Sitzungen. |
| **Geräte-Bindung** | Lizenzen zählen Geräte, der Admin kann einzelne Geräte wieder freigeben. |
| **Anti-Scraping** | Kurzlebige View-Tokens (JWT) pro Sitzung, Rate-Limit für Seitenabrufe, `no-store`-Caching, strikte CSP. |
| **Offline-Export** (optional) | Gerastertes PDF mit Wasserzeichen, AES-256-verschlüsselt, mit Rechte-Flags (Drucken ja/nein) und Lizenz-ID in den Metadaten. |
| **Audit-Log** | Logins, Fehlversuche, Öffnungen, jede angesehene Seite, Downloads und Admin-Aktionen. |
| **Login-Schutz** | scrypt-Passworthashes und eine Kontosperre nach wiederholten Fehlversuchen. |

## Schnellstart

```bash
pip install -e .            # oder: pip install -e '.[dev]' für Tests
export PDFDRM_DATA_DIR=./data

pdfdrm user-add leser@example.com --name "Max Leser"
pdfdrm doc-add handbuch.pdf --title "Handbuch 2026"
pdfdrm grant <USER_ID> <DOC_ID> --until 30d --max-devices 2 --max-opens 50 --print
pdfdrm serve --host 0.0.0.0 --port 8000
```

Danach unter `http://localhost:8000/` anmelden und das Dokument öffnen.
Die interaktive API-Doku liegt unter `/docs`.

Mit Docker:

```bash
docker build -t pdfdrm .
docker run -p 8000:8000 -v pdfdrm-data:/data \
  -e PDFDRM_MASTER_KEY=$(openssl rand -base64 32) \
  -e PDFDRM_ADMIN_API_KEY=$(openssl rand -hex 32) \
  -e PDFDRM_JWT_SECRET=$(openssl rand -hex 32) pdfdrm
```

> **Wichtig:** Ohne `PDFDRM_MASTER_KEY` erzeugt der Server beim ersten Start
> `data/master.key`. Ohne diesen Schlüssel sind alle Dokumente unwiederbringlich
> verloren. Den Schlüssel deshalb **getrennt von den Daten** sichern, in
> Produktion per Secret-Manager bzw. Umgebungsvariable setzen und den Server
> nur hinter HTTPS betreiben.

## CLI

| Befehl | Zweck |
|---|---|
| `pdfdrm serve [--host --port]` | Server starten |
| `pdfdrm admin-key` | Admin-API-Schlüssel anzeigen |
| `pdfdrm user-add EMAIL [--name --password]` | Benutzer anlegen |
| `pdfdrm user-list` / `user-disable ID` | Benutzer auflisten oder sperren |
| `pdfdrm doc-add DATEI [--title]` | PDF verschlüsselt importieren |
| `pdfdrm doc-list` / `doc-delete ID` | Dokumente verwalten |
| `pdfdrm grant USER DOC [--from --until --max-devices --max-opens --print --download --watermark]` | Lizenz vergeben (`--until` als ISO-Datum oder z. B. `30d`, `12h`) |
| `pdfdrm revoke LIZENZ` | Lizenz widerrufen |
| `pdfdrm license-list [--user --document]` | Lizenzen anzeigen |
| `pdfdrm audit [--limit]` | Audit-Log |
| `pdfdrm rotate-master-key` | Master-Key rotieren |

## HTTP-API

Admin-Endpunkte erwarten den Header `X-Admin-Key`.

| Methode & Pfad | Beschreibung |
|---|---|
| `POST /api/admin/users` | Benutzer anlegen `{email, password, name}` |
| `GET /api/admin/users`, `PATCH /api/admin/users/{id}` | Auflisten, sperren/entsperren, Passwort setzen |
| `POST /api/admin/documents` | PDF hochladen (multipart: `file`, `title`) |
| `GET /api/admin/documents`, `DELETE /api/admin/documents/{id}` | Dokumente verwalten |
| `POST /api/admin/licenses` | Lizenz vergeben |
| `GET/PATCH /api/admin/licenses/{id}` | Lizenz ansehen/ändern |
| `POST /api/admin/licenses/{id}/revoke` | Widerrufen |
| `DELETE /api/admin/licenses/{id}/devices/{device}` | Gerät freigeben |
| `GET /api/admin/audit` | Audit-Log |

Für Leser:

| Methode & Pfad | Beschreibung |
|---|---|
| `POST /api/auth/login` | `{email, password}` → Access-Token |
| `GET /api/library` | Lizenzierte Dokumente |
| `POST /api/documents/{id}/open` | `{device_id}` → prüft die Lizenz, bindet das Gerät, zählt die Öffnung und liefert ein View-Token |
| `GET /api/view/pages/{n}?scale=1.5` | Seite als WebP mit Wasserzeichen (View-Token) |
| `POST /api/view/refresh` | View-Token verlängern (nur bei weiterhin gültiger Lizenz) |
| `POST /api/view/download` | Geschütztes Offline-PDF (nur mit Download-Recht) |

## Konfiguration

| Variable | Standard | Bedeutung |
|---|---|---|
| `PDFDRM_DATA_DIR` | `./data` | Datenbank, verschlüsselte Dokumente, ggf. Schlüsseldateien |
| `PDFDRM_MASTER_KEY` | Datei `master.key` | 32 Byte, base64 |
| `PDFDRM_JWT_SECRET` | Datei `jwt.key` | Signaturschlüssel für Tokens |
| `PDFDRM_ADMIN_API_KEY` | Datei `admin_api.key` | Admin-Zugang |
| `PDFDRM_ACCESS_TOKEN_TTL` | `3600` | Gültigkeit des Login-Tokens (s) |
| `PDFDRM_VIEW_SESSION_TTL` | `1800` | Gültigkeit eines View-Tokens (s) |
| `PDFDRM_MAX_PAGES_PER_MINUTE` | `60` | Rate-Limit pro Lesesitzung |
| `PDFDRM_MAX_RENDER_SCALE` | `3.0` | Maximale Render-Auflösung |
| `PDFDRM_WATERMARK_OPACITY` | `60` | Deckkraft des Wasserzeichens (0–255) |
| `PDFDRM_LOGIN_MAX_FAILURES` / `PDFDRM_LOGIN_LOCKOUT_SECONDS` | `5` / `300` | Login-Sperre |

## Was DRM leisten kann – und was nicht

Kein DRM-System kann verhindern, dass jemand abfotografiert oder abschreibt,
was auf seinem Bildschirm zu sehen ist. Das Ziel ist, das Kopieren
aufwendig zu machen und Weitergaben **nachverfolgbar** zu machen:

- **Wirksam:** Das Original-PDF verlässt den Server nie. Es gibt keine
  Textebene zum Kopieren. Der Zugriff ist an Lizenz, Zeit und Gerät gebunden und
  sofort widerrufbar. Jede Seite trägt die Identität des Lesers, und jeder
  Abruf landet im Audit-Log.
- **Nur Hürden:** Die Sperren im Browser (Rechtsklick, Strg+S/P, Druck-CSS,
  Unschärfe beim Tab-Wechsel) und die Geräte-ID im `localStorage` lassen sich
  umgehen. Die PDF-Rechte-Flags beim Offline-Export werden von
  Standard-Readern respektiert, sind kryptografisch aber nicht erzwingbar.
  Das eingebrannte Wasserzeichen bleibt die eigentliche Absicherung.
- **Betrieb:** Das Rate-Limit liegt im Speicher und gilt pro Prozess. Bei
  mehreren Instanzen muss es auf einen gemeinsamen Speicher wie Redis
  umgestellt werden. Die SQLite-Datenbank ist für eine Instanz ausgelegt.

## Tests

```bash
pip install -e '.[dev]'
pytest
```

Verwendete Bibliotheken: FastAPI, pypdfium2 (Apache-2.0/BSD), pypdf (BSD),
Pillow (HPND), cryptography (Apache-2.0/BSD) und PyJWT (MIT). Es gibt keine
AGPL-Abhängigkeiten.
