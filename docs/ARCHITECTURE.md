# Architecture (current state)

One FastAPI process serves both the API and the UI (`app/static/index.html`).

| File | Role |
|---|---|
| `app/main.py` | Routes: `GET /`, `GET /healthz`, `POST /api/check` (multipart: text, url, language, image, audio; 8 MB limit), `POST /api/tts`, `GET /api/trends`. In-memory per-IP rate limit (20 per 10 min). |
| `app/pipeline.py` | `extract()` (Gemini multimodal: transcript, language, up to 3 claims, tactics) -> `research()` (Gemini + Google Search grounding, up to 5 sources) -> `judge()` (verdict, confidence, explanation in the user's language). In-memory claim cache. `check()` orchestrates and runs link analysis in parallel. |
| `app/links.py` | URL extraction, heuristics (shorteners, punycode, lookalike brands...), SSRF-safe fetch, Web Risk lookup, Gemini link judge. |
| `app/insights.py` | Claim log (BigQuery or memory) and global trends. No user ids. |
| `terraform/`, `deploy.sh`, `Dockerfile` | Cloud Run, Artifact Registry, BigQuery, IAM. Service is public today. |
| `evals/` | Accuracy eval over `claims.jsonl`. |

## Response shape of `/api/check`
`{input_language, output_language, transcript, tactics[], claims[{claim_id, claim, verdict, confidence, verdict_label, explanation, sources[{title,url}], grounded, cached}], links[{url, final_url, risk, score, reasons, explanation, advice, flags, web_risk}], latency_ms}`

## Known gaps
- No auth or per-user data.
- Cache and rate limit live in instance memory (not shared on Cloud Run).
- Sources lack publisher, date and stance; no overall summary or next-step actions.
- UI is one vanilla HTML file.

# Target design

## Auth (Firebase Authentication)
- Providers: Google, email, phone OTP.
- Browser signs in with the Firebase JS SDK and sends `Authorization: Bearer <ID token>`.
- `app/auth.py`: FastAPI dependency `current_user` that verifies the token with `firebase-admin` (`auth.verify_id_token`) and returns `{uid, email}`; 401 otherwise.
- Local dev escape hatch: `AUTH_DISABLED=1` makes uid `local-dev`.
- Protect `/api/check`, `/api/tts`, history routes. Rate-limit by `uid`. Keep `/healthz` and anonymised `/api/trends` open.

## History (Firestore)
- Path: `users/{uid}/checks/{checkId}`; doc = `{id, ts, preview (<=200 chars), result}`.
- `app/store.py` with `save`, `list_checks`, `get`, `delete`, `delete_all`. Use Firestore when `FIRESTORE=1`, in-memory fallback locally.
- Never store uploaded images or audio. Access only through the backend service account.
- Routes: `GET /api/me`, `GET /api/history`, `GET /api/history/{id}`, `DELETE /api/history/{id}`, `DELETE /api/history`.
- Add `result["id"]` to the `/api/check` response after saving.
- Optional: Firestore TTL policy for retention.

## Summary and actions (post-scan)
Add `summary` to the check result, built in `app/summary.py` (deterministic, no extra model call):
- `level`: `danger` (dangerous link, or false claim plus manipulation tactics), `warning` (suspicious link or false/misleading claim), `unclear` (unverifiable claims), `safe`.
- `counts`: false, unverifiable, dangerous_links, suspicious_links.
- `actions[]`, each `{type, text, url?}`; types: `dont_click`, `dont_share`, `warn_others`, `report_cybercrime` (cybercrime.gov.in / 1930), `report_sender`, `check_official`, `verify_source`, `safe_to_ignore`.
- UI localises by `type`; `text` is the English fallback.
- Later option: Gemini-written, language-specific action text constrained to the same type allowlist.

## Source tracing ("found online")
- In `research()`, keep only URLs from `grounding_metadata.grounding_chunks` (never model-invented).
- Per source add publisher (domain), date if available, and stance: supports / contradicts / neutral.
- Add `origin`: earliest known source or fact-check article if found, else null (UI says "no origin found").
- For links: grounded search on the domain/URL for reports and mentions; show alongside Web Risk.
- Keep the rule: no sources means confidence capped at 0.4 and a warning.

## Frontend (React + Vite + TS + Tailwind + shadcn/ui)
- New `web/` folder; build output goes to `app/static/`; FastAPI serves it with an SPA fallback.
- Screens: Login, Check (text, screenshot, voice, language), Result (summary card, claim cards, link cards, actions), History, Trends, Settings (language, delete my data, sign out).
- shadcn components: Card, Badge, Button, Tabs, Dialog, Sheet, Skeleton, Sonner/Toast, Progress, Select, Textarea, Alert.
- Move strings to i18n files (EN/HI first, then the other 9 languages). Keep dark mode, a11y, mobile first.
- Dev: `npm run dev` with Vite proxy to `uvicorn --reload` on 8080. Keep node_modules outside OneDrive or accept slow sync (prefer moving the repo out of OneDrive).

## Deploy changes
- Multi-stage Dockerfile: node build, then python image with ffmpeg.
- Terraform: Firestore database, `roles/datastore.user` for the runtime service account, Identity Platform/Firebase config, authorized domains, budget alert, max instances.
- New deps: `firebase-admin`, `google-cloud-firestore`.
- Update README privacy text (it currently says no user ids and nothing stored).
