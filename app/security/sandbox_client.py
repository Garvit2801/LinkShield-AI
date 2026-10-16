"""Client for a SEPARATE, opt-in sandbox worker. Never executes downloaded payloads."""
import asyncio
import os
from urllib.parse import quote

import httpx

NOT_CONFIGURED = {"status": "not_configured", "evidence": {}, "error": "Sandbox worker is not configured"}


def _worker() -> tuple[str, str]:
    return os.getenv("SANDBOX_URL", "").rstrip("/"), os.getenv("SANDBOX_TOKEN", "")


def _identity_token(audience: str) -> str:
    from google.auth.transport.requests import Request
    from google.oauth2 import id_token
    return id_token.fetch_id_token(Request(), audience)


async def _headers(secret: str) -> dict:
    """The worker's own bearer token, plus a Google identity token when the worker is a private Cloud Run service."""
    headers = {"Authorization": f"Bearer {secret}"}
    audience = os.getenv("SANDBOX_AUDIENCE", "")
    if audience:
        # Cloud Run checks this header first, so Authorization stays free for the worker's token.
        headers["X-Serverless-Authorization"] = f"Bearer {await asyncio.to_thread(_identity_token, audience)}"
    return headers


async def investigate(url: str) -> dict:
    worker_url, secret = _worker()
    if not worker_url or not secret:
        return dict(NOT_CONFIGURED)
    try:
        # Worker endpoint is trusted infrastructure, never derived from user input.
        # The timeout covers a page visit plus fetching and inspecting any file it leads to.
        async with httpx.AsyncClient(timeout=80, follow_redirects=False) as client:
            response = await client.post(f"{worker_url}/investigate", json={"url": url},
                                         headers=await _headers(secret))
            response.raise_for_status()
            obj = response.json()
            if obj.get("status") not in ("completed", "blocked", "error"):
                raise ValueError("Invalid sandbox response")
            return obj
    except Exception:
        return {"status": "error", "evidence": {}, "error": "Sandbox worker did not complete the scan"}


async def inspect_upload(data: bytes, name: str, content_type: str = "") -> dict:
    """Hand an uploaded file to the worker so untrusted bytes are parsed there, not in the API process."""
    worker_url, secret = _worker()
    if not worker_url or not secret:
        return dict(NOT_CONFIGURED)
    try:
        async with httpx.AsyncClient(timeout=60, follow_redirects=False) as client:
            response = await client.post(f"{worker_url}/scan-file", content=data, headers={
                **await _headers(secret), "Content-Type": "application/octet-stream",
                "X-File-Name": quote(name[:200]), "X-File-Type": content_type[:80].encode("ascii", "ignore").decode()})
            response.raise_for_status()
            obj = response.json()
            if obj.get("status") != "completed" or not isinstance(obj.get("file"), dict):
                raise ValueError("Invalid sandbox response")
            return obj
    except Exception:
        return {"status": "error", "evidence": {}, "error": "Sandbox worker did not complete the file inspection"}
