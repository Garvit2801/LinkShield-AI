import asyncio, collections, logging, time
from pathlib import Path

from fastapi import BackgroundTasks, Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel

from . import auth, insights, pipeline, store

log = logging.getLogger("linkshield")
app = FastAPI(title="LinkShield AI")
STATIC = Path(__file__).parent / "static"
MAX_BYTES = 8 * 1024 * 1024
LOCALES = {"hi": "hi-IN", "en": "en-IN", "bn": "bn-IN", "ta": "ta-IN", "te": "te-IN", "mr": "mr-IN",
           "gu": "gu-IN", "kn": "kn-IN", "ml": "ml-IN", "pa": "pa-IN", "ur": "ur-IN"}
_hits: dict = collections.defaultdict(collections.deque)
_tts = None


def limited(ip: str, limit: int = 20, window: int = 600) -> bool:
    now, q = time.time(), _hits[ip]
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= limit:
        return True
    q.append(now)
    return False


def synth(text: str, lang: str) -> bytes:
    global _tts
    from google.cloud import texttospeech as tts
    _tts = _tts or tts.TextToSpeechClient()
    r = _tts.synthesize_speech(
        input=tts.SynthesisInput(text=text[:900]),
        voice=tts.VoiceSelectionParams(language_code=LOCALES.get(lang, "en-IN")),
        audio_config=tts.AudioConfig(audio_encoding=tts.AudioEncoding.MP3),
    )
    return r.audio_content


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/config")
def api_config():
    return {"authRequired": auth.required(), "googleClientId": auth.client_id()}


@app.get("/api/me")
def api_me(user: dict | None = Depends(auth.current_user)):
    if not user:
        raise HTTPException(401, "Not signed in.")
    return user


@app.post("/api/check")
async def api_check(request: Request, bg: BackgroundTasks, text: str = Form(""), url: str = Form(""),
                    language: str = Form(""), image: UploadFile | None = File(None),
                    audio: UploadFile | None = File(None), user: dict | None = Depends(auth.current_user)):
    ip = (request.headers.get("x-forwarded-for") or (request.client.host if request.client else "?")).split(",")[0].strip()
    if limited(f"uid:{user['uid']}" if user else ip):
        raise HTTPException(429, "Too many checks. Try again in a few minutes.")
    img = aud = None
    if image:
        data = await image.read()
        if len(data) > MAX_BYTES:
            raise HTTPException(413, "Image is too large (max 8 MB).")
        img = (data, image.content_type or "image/png")
    if audio:
        aud = await audio.read()
        if len(aud) > MAX_BYTES:
            raise HTTPException(413, "Audio is too large (max 8 MB).")
    try:
        result = await pipeline.check(text=text, url=url, lang=language.strip().lower()[:2], image=img, audio=aud)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception:
        log.exception("check failed")
        raise HTTPException(502, "The checker is busy. Please try again.")
    bg.add_task(insights.log_claims, result["claims"], result["output_language"])
    if user:
        preview = text or url or result.get("transcript", "")
        result["id"] = await asyncio.to_thread(store.save, user["uid"], result, preview)
    return result


@app.get("/api/history")
async def api_history(user: dict | None = Depends(auth.current_user)):
    if not user:
        raise HTTPException(401, "Sign in to see your history.")
    return {"items": await asyncio.to_thread(store.list_items, user["uid"])}


@app.get("/api/history/{cid}")
async def api_history_item(cid: str, user: dict | None = Depends(auth.current_user)):
    if not user:
        raise HTTPException(401, "Sign in to see your history.")
    item = await asyncio.to_thread(store.get, user["uid"], cid)
    if not item:
        raise HTTPException(404, "Not found.")
    return item


@app.delete("/api/history/{cid}")
async def api_history_delete(cid: str, user: dict | None = Depends(auth.current_user)):
    if not user:
        raise HTTPException(401, "Sign in first.")
    await asyncio.to_thread(store.delete, user["uid"], cid)
    return {"ok": True}


@app.delete("/api/history")
async def api_history_clear(user: dict | None = Depends(auth.current_user)):
    if not user:
        raise HTTPException(401, "Sign in first.")
    await asyncio.to_thread(store.delete_all, user["uid"])
    return {"ok": True}


class TTSReq(BaseModel):
    text: str
    language: str = "en"


@app.post("/api/tts")
async def api_tts(req: TTSReq):
    try:
        audio = await asyncio.to_thread(synth, req.text, req.language)
    except Exception:
        log.exception("tts failed")
        raise HTTPException(502, "Audio is unavailable right now.")
    return Response(audio, media_type="audio/mpeg")


@app.get("/api/trends")
async def api_trends():
    return await asyncio.to_thread(insights.trends)
