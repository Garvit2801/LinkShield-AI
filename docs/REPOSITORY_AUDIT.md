# Audit of supplied LinkShield-AI.zip

The uploaded repository (before these changes) contained:

- `app/main.py`: FastAPI HTTP server, legacy multimedia `/api/check`, `/api/tts`, `/api/trends`, in-memory throttling
- `app/pipeline.py`: Gemini multimodal transcription/claim extraction, Google Search grounded verification, answer localization
- `app/links.py`: Regex URL extraction, suspicious-domain checks, Web Risk, static HTTP HTML extraction, Gemini risk judgement
- `app/insights.py`: BigQuery/in-memory misinformation event logs and trends
- `app/static/index.html`: a single-page legacy claim checker interface
- `terraform/main.tf`, `deploy.sh`, `Dockerfile`: deployment to Cloud Run and BigQuery
- `evals/claims.jsonl` and `run_eval.py`: benchmark for misinformation verdicts
- `docs/ARCHITECTURE.md`, `LOCAL_SETUP.md`, `ROADMAP.md`: past architecture/plans

## Issues and gaps

1. **No actual sandbox.** Original source comments explicitly say no JavaScript execution and no sandbox.
2. **Sensitive URL fetch in API.** Original static fetch used DNS check followed by a separate HTTP resolution, leaving a DNS-rebinding race. New primary API does no URL fetch; the legacy direct fetch was disabled.
3. **No scan history / authentication.** Now added Firestore user scope and optional Firebase; local-only demo mode is not secure authentication.
4. **URL verdict centered on Gemini judgment.** New security classifier uses fixed evidence-driven rules; Gemini explains without overriding the risk label.
5. **No persisted evidence.** New optional private GCS screenshot store with one-day lifecycle; screenshot omitted from Firestore scan records.
6. **In-process cache and rate limit.** New demo still has instance-local throttling. A distributed gateway quota store is still required for production.
7. **Misleading lack-of-evidence interpretation.** An unavailable sandbox or reputation lookup is now shown explicitly. Clean reputation lookup is not proof of safety.

## Retained original functions

`GET /legacy`, `POST /api/check`, `POST /api/tts`, `GET /api/trends`; claim extraction/evaluation code remains for further adaptation. Static page fetching in the old pipeline is intentionally disabled as a security precaution. Legacy feature behavior may therefore differ for URLs.
