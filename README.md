# LinkShield AI 3.0: a second opinion on anything you are sent

Paste, share or forward a suspicious message, link, screenshot, voice note or file. LinkShield opens links in a sandbox, inspects files without running them, fact-checks the claims, and gives one plain answer about what to do, in the person's language.

The wireframes this build follows are in [`docs/wireframes/`](docs/wireframes/).

## How a check runs

```text
Input (text, link, screenshot, voice note, file)
   -> Extract        Gemini reads it: transcript, claims, links, pressure tactics
   -> three branches, side by side
        Claims       Gemini + Google Search research each claim, then judge it from the sources only
        Links        sandbox browser visit, redirects, forms, screenshot  -> fixed rules + Google Web Risk
        Files        sandbox download, real type, macros, scripts, links inside -> fixed rules + VirusTotal lookup
   -> Summary        Gemini writes one headline and next steps; it is told the verdict and cannot change it
   -> Response       report cards, download flag, spoken verdict, saved history
```

Three rules hold everywhere:

1. **Gemini never decides a link or file verdict.** Fixed rules, Web Risk and antivirus lookups do, so the same input always gets the same answer.
2. **Untrusted content is only handled in the sandbox worker**, a separate service with no cloud credentials. Files are read as bytes, never opened or run.
3. **Anything that could not be checked is never shown as low risk.** It is reported as unverified, with the reason.

## What is not claimed

This is static triage plus lookups, not an antivirus and not a malware-detonation service. A clean result means no known danger signs were found. LinkShield cannot read private chats: it only sees what a person pastes, shares or forwards to it. Programs and installers never get a green flag.

## Quick start (local demo)

Requires Docker Desktop.

```bash
cp .env.example .env      # change SANDBOX_TOKEN to a long random value
docker compose up --build
# open http://localhost:8080
```

Two services start: the API on `localhost:8080` and the sandbox worker, which is not published to the host. With `DISABLE_GOOGLE=1` (the default) links and files are fully checked, the summary is written by fixed rules in English, and screenshots, voice notes and claims are reported as not read. Each optional service switches on with its own setting:

| Setting | Switches on |
|---|---|
| `GOOGLE_CLOUD_PROJECT` + `DISABLE_GOOGLE=0` (with ADC) | Gemini extraction, claim fact-checks, the written summary, Web Risk, spoken verdicts |
| `VIRUSTOTAL_API_KEY` | Known-malware lookup by file fingerprint (the file is never sent) |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_BOT_USERNAME`, `TELEGRAM_WEBHOOK_SECRET` | Telegram bot |
| `WHATSAPP_TOKEN`, `WHATSAPP_APP_SECRET`, `WHATSAPP_VERIFY_TOKEN`, `WHATSAPP_DISPLAY_NUMBER` | WhatsApp bot (Meta Cloud API, needs a business account) |
| `AUTH_REQUIRED=1` + Firebase settings | Google and guest sign-in |
| `ENABLE_FIRESTORE=1` | Saved history, preferences and a rate limit shared by all servers |

Tests: `pip install -r requirements-dev.txt && python -m pytest -q tests`.

## API

Every route under `/api` needs an identity: a Firebase ID token when `AUTH_REQUIRED=1`, otherwise a random `X-Linkshield-Session` UUID (demo only). Checks are limited to 15 per person per ten minutes.

| Method | Route | Purpose |
|---|---|---|
| POST | `/api/v1/checks` | **The main endpoint.** Multipart form: `text`, `language`, `file`, `recording`. Returns one report with `summary`, `claims`, `links`, `uploads`, `tactics` |
| GET / DELETE | `/api/v1/scans`, `/api/v1/scans/{id}` | History: list, open, delete |
| GET / PUT | `/api/v1/me` | Remembered preferences (language) |
| POST | `/api/v1/tts` | Read a verdict aloud (Google Text-to-Speech) |
| GET | `/api/v1/trends` | Anonymous counts of the most-checked claims |
| GET | `/api/v1/capabilities` | Which integrations are switched on |
| POST | `/api/v1/bots/telegram`, `/api/v1/bots/whatsapp` | Bot webhooks (verified by secret header / signed body) |
| POST | `/share` | Android share target (handled in the browser by `sw.js`) |
| POST | `/api/v1/scans`, `/api/v1/files` | Single link / single file checks, kept for older clients |
| POST | `/api/check`, `/api/tts`; GET `/api/trends` | Original endpoints, kept for older clients, now behind the same identity check and limits |

```bash
curl -s http://localhost:8080/api/v1/checks \
  -H 'X-Linkshield-Session: a38e8dad-d196-4fda-8c43-9be5eecb080f' \
  -F 'text=Your SBI account is blocked. Update KYC: https://sbi-kyc-update.example.com/verify' \
  -F 'file=@invoice.pdf'
```

`score` is a heuristic triage score, not a probability. Levels: `critical`, `high`, `caution`, `low`, `unverified`. A check takes the worst level among its parts.

## Ways in

- **Web app**: one box for text, links, files, screenshots (paste or drop) and recorded voice notes.
- **Share to LinkShield**: the app is installable; on Android it then appears in the share sheet of WhatsApp, Gmail and the gallery. Needs HTTPS.
- **Telegram bot**: forward a message or file; a forwarded file is checked without the person downloading it (20 MB Bot API limit).
- **WhatsApp bot**: forward a message to the business number.

## Deployment

`./deploy.sh YOUR_PROJECT_ID us-central1 [-var ...]` builds both images and deploys two Cloud Run services: the API and a private sandbox worker with its own identity that holds no roles. See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) and read [`docs/SECURITY.md`](docs/SECURITY.md) first. The Terraform has not been applied to a real project from this repository; review a `terraform plan` before the first apply.

## Repository layout

```text
app/
  main.py                  app shell, share target, original endpoints
  bots.py                  Telegram and WhatsApp webhooks
  pipeline.py              Gemini extract / research / judge for claims
  insights.py              anonymous claim trends (BigQuery or memory)
  security/
    engine.py              the unified check: extract -> claims, links, files -> summary
    orchestrator.py        one link or one file: sandbox, rules, lookups, links inside files
    signals.py             every scoring rule, in one place
    providers.py           Web Risk, VirusTotal, Gemini explanation and summary
    api.py                 routes, rate limits, preferences, speech
    guard.py               URL validation and private-address rejection
    sandbox_client.py      authenticated calls to the worker
    identity.py            Firebase token check / demo session
    storage.py             history, preferences, private screenshots
    telemetry.py           anonymous scan events
  static/                  web app, manifest, service worker
sandbox/
  worker.py                browser visits and file downloads
  filescan.py              static file inspection
terraform/main.tf          Cloud Run x2, Secret Manager, BigQuery, Pub/Sub, Storage, IAM
tests/                     automated tests
docs/                      wireframes, architecture, deployment, security
```

## License

See `LICENSE`.
