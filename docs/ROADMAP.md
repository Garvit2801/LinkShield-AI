# Roadmap

Decisions: Firebase Auth (Google, email, phone OTP), Firestore history, React + Vite + Tailwind + shadcn/ui served by FastAPI. Design details are in [ARCHITECTURE.md](./ARCHITECTURE.md).

## Phase 0: run locally
Follow [LOCAL_SETUP.md](./LOCAL_SETUP.md). Verify one text claim and one link end to end.

## Phase 1: backend auth and history
- [ ] `app/auth.py` token verification dependency
- [ ] `app/store.py` Firestore history with in-memory fallback
- [ ] Protect `/api/check` and `/api/tts`; rate-limit by uid
- [ ] History routes and `/api/me`; return check `id`

## Phase 2: summary, actions, sources
- [ ] `app/summary.py` and `summary` in the check result
- [ ] Source stance, publisher, date, claim origin (grounding data only)
- [ ] Online mentions for links
- [ ] Eval cases for summary schema and language

## Phase 3: frontend
- [ ] Scaffold `web/` (Vite, React, TS, Tailwind, shadcn, firebase SDK)
- [ ] Login, Check, Result, History, Trends, Settings
- [ ] i18n (EN/HI first), dark mode, a11y, mobile

## Phase 4: deploy
- [ ] Multi-stage Dockerfile
- [ ] Terraform: Firestore, IAM, auth config, budget alert
- [ ] Deploy and smoke test (sign in, check, history persists, delete data)

## Phase 5: hardening
- [ ] Shared cache and rate limit
- [ ] Tests: auth, store (emulator), pipeline schema, SSRF regression
- [ ] README privacy update

## Open questions
- Guest mode with a small quota, or login required (default: required)?
- History retention period?
- Firestore region (default: same as Cloud Run)?
