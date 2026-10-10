# Run locally (Windows, Git Bash)

The repo is in OneDrive, so keep the virtualenv outside it.

```bash
python -m venv /c/venvs/linkshield
source /c/venvs/linkshield/Scripts/activate
pip install -r requirements.txt

gcloud auth login
gcloud config set project YOUR_PROJECT_ID
gcloud services enable aiplatform.googleapis.com texttospeech.googleapis.com webrisk.googleapis.com
gcloud auth application-default login

export GOOGLE_CLOUD_PROJECT=YOUR_PROJECT_ID
export GOOGLE_CLOUD_LOCATION=us-central1
uvicorn app.main:app --reload --port 8080
```

Open http://localhost:8080. Frontend and backend are one process.

## Notes
- Voice notes need `ffmpeg` on PATH.
- If `gcloud` says `failed to locate pyvenv.cfg`, deactivate any broken venv and open a fresh terminal.
- Once auth is added: `export AUTH_DISABLED=1` for local runs without Firebase.
- Eval: `python evals/run_eval.py`.
