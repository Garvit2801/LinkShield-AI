"""Per-user check history. In-memory locally; Firestore when ENABLE_FIRESTORE=1.

Only claim text, verdicts, sources and the summary are stored. Uploaded media never is.
"""
import collections, os, time, uuid

MAX_ITEMS = 50
_mem: dict = collections.defaultdict(dict)
_fs = None


def _firestore():
    global _fs
    if _fs is None:
        from google.cloud import firestore
        _fs = firestore.Client()
    return _fs


def _enabled() -> bool:
    return os.environ.get("ENABLE_FIRESTORE", "0") == "1"


def _coll(uid: str):
    return _firestore().collection("users").document(uid).collection("checks")


def _record(result: dict, preview: str) -> dict:
    return {
        "created_at": time.time(),
        "preview": preview[:200],
        "output_language": result.get("output_language"),
        "summary": result.get("summary"),
        "claims": [{k: c.get(k) for k in ("claim", "verdict", "verdict_label", "confidence", "explanation", "sources", "trace", "grounded")}
                   for c in result.get("claims", [])],
        "links": [{k: l.get(k) for k in ("url", "final_url", "risk", "score", "explanation", "advice", "reasons")}
                  for l in result.get("links", [])],
        "tactics": result.get("tactics", []),
    }


def save(uid: str, result: dict, preview: str) -> str:
    rec, cid = _record(result, preview), uuid.uuid4().hex[:16]
    if _enabled():
        _coll(uid).document(cid).set(rec)
    else:
        _mem[uid][cid] = rec
        for old in sorted(_mem[uid], key=lambda k: _mem[uid][k]["created_at"])[:-MAX_ITEMS]:
            del _mem[uid][old]
    return cid


def list_items(uid: str) -> list:
    if _enabled():
        docs = _coll(uid).order_by("created_at", direction="DESCENDING").limit(MAX_ITEMS).stream()
        items = [{"id": d.id, **d.to_dict()} for d in docs]
    else:
        items = sorted(({"id": k, **v} for k, v in _mem[uid].items()), key=lambda r: -r["created_at"])
    return items


def get(uid: str, cid: str) -> dict | None:
    if _enabled():
        d = _coll(uid).document(cid).get()
        return {"id": d.id, **d.to_dict()} if d.exists else None
    rec = _mem[uid].get(cid)
    return {"id": cid, **rec} if rec else None


def delete(uid: str, cid: str) -> None:
    if _enabled():
        _coll(uid).document(cid).delete()
    else:
        _mem[uid].pop(cid, None)


def delete_all(uid: str) -> None:
    if _enabled():
        for d in _coll(uid).stream():
            d.reference.delete()
    else:
        _mem.pop(uid, None)
