from fastapi.testclient import TestClient

from app import auth, main

client = TestClient(main.app)
USER = {"uid": "u1", "email": "a@b.c", "name": None, "phone": None, "picture": None}


def fake_verify(token):
    if token == "good":
        return USER
    raise ValueError("bad")


def test_me_requires_login(monkeypatch):
    monkeypatch.setattr(auth, "verify", fake_verify)
    monkeypatch.setattr(auth, "client_id", lambda: "cid")
    assert client.get("/api/me").status_code == 401
    assert client.get("/api/me", headers={"Authorization": "Bearer good"}).json()["uid"] == "u1"


def test_bad_token_rejected_even_when_optional(monkeypatch):
    monkeypatch.setattr(auth, "verify", fake_verify)
    monkeypatch.setattr(auth, "client_id", lambda: "cid")
    r = client.post("/api/check", data={"text": "hi"}, headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401


def test_required_blocks_anonymous(monkeypatch):
    monkeypatch.setenv("AUTH_REQUIRED", "1")
    assert client.post("/api/check", data={"text": "hi"}).status_code == 401


def test_anonymous_allowed_by_default(monkeypatch):
    monkeypatch.delenv("AUTH_REQUIRED", raising=False)
    assert client.get("/healthz").status_code == 200
    assert client.get("/api/config").json()["authRequired"] is False
