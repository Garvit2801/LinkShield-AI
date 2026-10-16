"""LinkShield AI HTTP service: the unified check API, chat bots, the share target and the web app."""
import logging
import os
from pathlib import Path
from urllib.parse import urlencode

from fastapi import BackgroundTasks, Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from .bots import router as bots_router
from .chat import router as chat_router
from .security.api import Speech, limit, router as security_router, speak
from .security.identity import current_user

log = logging.getLogger("linkshield")
app = FastAPI(title="LinkShield AI", version="3.0.0", docs_url="/docs")
app.include_router(security_router)
app.include_router(bots_router)
app.include_router(chat_router)
STATIC = Path(__file__).parent / "static"
MAX_BYTES = 8 * 1024 * 1024
app.mount("/assets", StaticFiles(directory=STATIC / "assets"), name="assets")


@app.get("/healthz")
def healthz():
    return {"ok": True, "version": "3.0.0"}


@app.get("/")
def login():
    """Sign in with Google, or carry on as a guest. Someone already signed in goes straight to the app."""
    return FileResponse(STATIC / "login.html", headers={"Cache-Control": "no-cache"})


@app.get("/app")
def checker():
    return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})


@app.get("/api/config")
def api_config():
    """What the sign-in page needs (the same names as the original GitHub version)."""
    from .security.identity import google_client_id
    return {"authRequired": os.getenv("AUTH_REQUIRED", "0") == "1", "googleClientId": google_client_id()}


@app.get("/legacy")
def legacy():
    """The old fact-checker page. Claim checking now lives in the main check box."""
    return RedirectResponse("/app#scan", 308)


@app.get("/manifest.webmanifest")
def manifest():
    return FileResponse(STATIC / "manifest.webmanifest", media_type="application/manifest+json")


@app.get("/sw.js")
def service_worker():
    # Served from the root so its scope covers the whole app, including the /share target.
    return FileResponse(STATIC / "sw.js", media_type="text/javascript", headers={"Cache-Control": "no-cache"})


@app.post("/share")
async def share_fallback(request: Request):
    """Android share target. The service worker normally handles this in the browser so files never
    need a second upload; this fallback carries shared text across when the worker is not active yet."""
    try:
        async with request.form(max_files=1, max_fields=6) as form:
            text = " ".join(str(form.get(k) or "") for k in ("title", "text", "url") if isinstance(form.get(k), str)).strip()
    except Exception:
        text = ""
    return RedirectResponse("/app?" + urlencode({"text": text[:3000]}) + "#scan", 303)


@app.get("/share")
def share_get(title: str = "", text: str = "", url: str = ""):
    return RedirectResponse("/app?" + urlencode({"text": " ".join(x for x in (title, text, url) if x)[:3000]}) + "#scan", 303)


@app.post("/api/check")
async def legacy_check(bg: BackgroundTasks, text: str = Form(""), url: str = Form(""),
                       language: str = Form(""), image: UploadFile | None = File(None),
                       audio: UploadFile | None = File(None), uid: str = Depends(current_user)):
    """The original claim-check API, kept for older clients. New clients use POST /api/v1/checks."""
    await limit(uid)
    from . import insights, pipeline
    img = aud = None
    if image:
        data = await image.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES or not (image.content_type or "").startswith("image/"):
            raise HTTPException(413, "Image must be a supported image under 8 MB.")
        img = (data, image.content_type)
    if audio:
        aud = await audio.read(MAX_BYTES + 1)
        if len(aud) > MAX_BYTES or not (audio.content_type or "").startswith("audio/"):
            raise HTTPException(413, "Audio must be a supported audio file under 8 MB.")
    try:
        result = await pipeline.check(text=text, url=url, lang=language.strip().lower()[:2], image=img, audio=aud)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    except Exception:
        log.exception("legacy checker failed")
        raise HTTPException(502, "Fact checking unavailable. Verify Vertex AI configuration.") from None
    bg.add_task(insights.log_claims, result["claims"], result["output_language"])
    return result


@app.post("/api/tts")
async def api_tts(req: Speech, uid: str = Depends(current_user)):
    return await speak(req, uid)


@app.get("/api/trends")
async def api_trends(uid: str = Depends(current_user)):
    await limit(uid, "read")
    from . import insights
    return insights.trends()
