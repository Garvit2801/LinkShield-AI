# LinkShield AI: your personal scam and misinformation investigator for WhatsApp forwards

Two checks in one place: **link investigation** (phishing, fake KYC, malware: Web Risk, redirect tracing, Gemini analysis) and **misinformation checking** (claims verified against live sources). Answers come in the user's own language.

Paste a forward, link, screenshot or voice note (Hindi, English and 9 other Indian languages). LinkShield AI extracts the
checkable claims, verifies each against live web sources, and answers in the user's language, with audio, sources,
the pressure tactics used in the message, and a one-tap "share the debunk back" button.

## Pipeline
```
text / URL / screenshot / voice note
  -> Gemini multimodal (Vertex AI): transcript, language, claims, manipulation tactics   [JSON schema]
  -> per claim, in parallel: Gemini + Google Search grounding -> research notes + sources
  -> Gemini judge (evidence-only, calibrated confidence) -> verdict + explanation in user's language [JSON schema]
  -> in parallel, every link in the message (also short links without https://):
       redirect trace (SSRF-checked per hop, pages fetched statically, never executed)
       + Google Cloud Web Risk lookup + lookalike/TLD/shortener heuristics + Gemini landing-page judgement
       -> risk score, reasons and advice in the user's language (a Web Risk hit always forces "dangerous")
  -> Cloud Text-to-Speech (listen) | BigQuery (claim log -> trends) | claim-hash cache
```
Guardrails: verdicts come only from retrieved evidence; no sources means confidence is capped and the UI warns;
message content is treated as data (prompt-injection-safe); SSRF guard on links; per-IP rate limit; uploads are never stored.

## Run locally
```bash
pip install -r requirements.txt          # ffmpeg must be installed for voice notes
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT=<project> GOOGLE_CLOUD_LOCATION=us-central1
uvicorn app.main:app --reload            # http://localhost:8080 with --port 8080
python -m evals.run_eval                 # accuracy on evals/claims.jsonl
```

## Deploy
Quick first deploy (do this early): 
```bash
gcloud run deploy linkshield --source . --region us-central1 --allow-unauthenticated \
  --set-env-vars GOOGLE_CLOUD_PROJECT=<project>,GOOGLE_CLOUD_LOCATION=us-central1
# grant the runtime service account roles/aiplatform.user
```
Full infra (Cloud Run, BigQuery, IAM, Artifact Registry): `./deploy.sh <project-id>`

## Link checker setup
Enable the API once: `gcloud services enable webrisk.googleapis.com` (Terraform does this). The runtime service account
needs no extra role beyond API access; check Web Risk quota and pricing for your project. Links are never opened in a browser
or sandbox, so JavaScript-only phishing pages are judged from redirects, Web Risk, heuristics and static page text.

## Limits
Verdicts are AI-assisted and can be wrong; always read the sources. Shortened links are not followed.
