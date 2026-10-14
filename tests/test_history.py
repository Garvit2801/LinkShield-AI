from fastapi.testclient import TestClient

from app import auth, main, pipeline

client = TestClient(main.app)


def users(token):
    if token in ("a", "b"):
        return {"uid": "user-" + token, "email": token + "@x.y", "name": None, "picture": None}
    raise ValueError("bad")


async def fake_check(**kw):
    return {"input_language": "en", "output_language": "en", "transcript": "", "tactics": [],
            "claims": [{"claim_id": "k1", "claim": "c", "verdict": "false", "verdict_label": "False", "confidence": .9,
                        "explanation": "e", "sources": [], "grounded": False}],
            "links": [], "summary": {"level": "warning", "counts": {}, "actions": []}, "latency_ms": 1}


def H(t):
    return {"Authorization": "Bearer " + t}


def test_history_is_per_user(monkeypatch):
    monkeypatch.setattr(auth, "verify", users)
    monkeypatch.setattr(auth, "client_id", lambda: "cid")
    monkeypatch.setattr(pipeline, "check", fake_check)
    r = client.post("/api/check", data={"text": "hello"}, headers=H("a"))
    assert r.status_code == 200 and r.json()["id"]
    cid = r.json()["id"]
    assert len(client.get("/api/history", headers=H("a")).json()["items"]) >= 1
    assert client.get("/api/history", headers=H("b")).json()["items"] == []
    assert client.get(f"/api/history/{cid}", headers=H("b")).status_code == 404
    assert client.delete(f"/api/history/{cid}", headers=H("a")).status_code == 200
    assert client.get(f"/api/history/{cid}", headers=H("a")).status_code == 404


def test_anonymous_check_not_saved(monkeypatch):
    monkeypatch.setattr(pipeline, "check", fake_check)
    r = client.post("/api/check", data={"text": "hello"})
    assert r.status_code == 200 and "id" not in r.json()
    assert client.get("/api/history").status_code == 401
