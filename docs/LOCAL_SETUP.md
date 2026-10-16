# Local setup

Quickest: `cp .env.example .env && docker compose up --build`, then open `http://localhost:8080`. By default, `DISABLE_GOOGLE=1` means no live Google calls. The browser sandbox is available when the worker container starts successfully. To test without Docker: create a venv, `pip install -r requirements-dev.txt`, then `DISABLE_GOOGLE=1 uvicorn app.main:app --reload --port 8080`. This runs without the browser worker and reports it as unavailable. Run tests with `python -m pytest -q tests`.

A Firebase ID token is required only with `AUTH_REQUIRED=1`; the demo frontend uses an anonymous, browser-local random session UUID (not production authentication). Google ADC is required to use cloud integrations; run `gcloud auth application-default login`, set `GOOGLE_CLOUD_PROJECT`, and unset `DISABLE_GOOGLE`. Claim checking is part of the main check box and needs Gemini.
