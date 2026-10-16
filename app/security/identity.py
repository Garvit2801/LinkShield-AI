"""Who is calling: a Google account (Sign in with Google), a Firebase user, or a guest with a random session key.

A request that carries a sign-in token is always verified, even when guests are allowed, so an expired
session is noticed instead of silently becoming a guest. Without a token, guests are allowed unless
AUTH_REQUIRED=1.
"""
import hashlib
import os
import re
from functools import lru_cache

from fastapi import Header, HTTPException


def google_client_id() -> str:
    return os.getenv("GOOGLE_CLIENT_ID", "")


@lru_cache(maxsize=1)
def _transport():
    from google.auth.transport import requests as g_requests
    return g_requests.Request()  # caches Google's signing keys between requests


def _google(token: str) -> dict:
    from google.oauth2 import id_token
    claims = id_token.verify_oauth2_token(token, _transport(), audience=google_client_id())
    if not claims.get("sub") or not claims.get("email_verified", False):
        raise ValueError("unverified account")
    return {"uid": "g-" + claims["sub"], "email": claims.get("email"), "name": claims.get("name"), "picture": claims.get("picture")}


def _firebase(token: str) -> dict:
    from firebase_admin import auth, get_app, initialize_app
    try:
        get_app()
    except ValueError:
        initialize_app()
    decoded = auth.verify_id_token(token)
    return {"uid": str(decoded["uid"]), "email": decoded.get("email"), "name": decoded.get("name"), "picture": decoded.get("picture")}


def account(authorization: str | None = Header(None), x_linkshield_session: str | None = Header(None)) -> dict:
    """The caller as {uid, email, name, picture, guest}."""
    if authorization and authorization.startswith("Bearer "):
        token = authorization.removeprefix("Bearer ").strip()
        try:
            return {**(_google(token) if google_client_id() else _firebase(token)), "guest": False}
        except Exception:
            raise HTTPException(401, "Your sign-in has expired. Please sign in again.") from None
    if os.getenv("AUTH_REQUIRED", "0") == "1":
        raise HTTPException(401, "Sign in to continue.")
    # A guest: not authentication, only a key that keeps one browser's history apart from another's.
    if not x_linkshield_session or not re.fullmatch(r"[a-f0-9-]{36}", x_linkshield_session.lower()):
        raise HTTPException(400, "A random X-Linkshield-Session UUID is required for guests.")
    return {"uid": "demo-" + hashlib.sha256(x_linkshield_session.encode()).hexdigest()[:32], "email": None, "name": None, "picture": None, "guest": True}


def current_user(authorization: str | None = Header(None), x_linkshield_session: str | None = Header(None)) -> str:
    return account(authorization, x_linkshield_session)["uid"]
