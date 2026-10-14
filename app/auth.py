"""Firebase ID-token auth. Anonymous use stays allowed unless AUTH_REQUIRED=1."""
import os

from fastapi import HTTPException, Request
from google.auth.transport import requests as g_requests
from google.oauth2 import id_token

_transport = g_requests.Request()


def required() -> bool:
    return os.environ.get("AUTH_REQUIRED", "0") == "1"


def project_id() -> str:
    return os.environ.get("FIREBASE_PROJECT_ID") or os.environ.get("GOOGLE_CLOUD_PROJECT", "")


def verify(token: str) -> dict:
    claims = id_token.verify_firebase_token(token, _transport, audience=project_id())
    if not claims or not claims.get("sub"):
        raise ValueError("invalid token")
    return {"uid": claims["sub"], "email": claims.get("email"), "name": claims.get("name"),
            "phone": claims.get("phone_number"), "picture": claims.get("picture")}


def current_user(request: Request) -> dict | None:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        if required():
            raise HTTPException(401, "Sign in to continue.")
        return None
    try:
        return verify(header[7:].strip())
    except Exception:
        # A bad token is rejected even when auth is optional, so expired sessions are noticed.
        raise HTTPException(401, "Your session is invalid or expired. Please sign in again.")
