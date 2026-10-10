"""Claim logging + trends. BigQuery when BQ_TABLE is set, in-memory fallback otherwise. No user ids are stored."""
import collections, os
from datetime import datetime, timezone

BQ_TABLE = os.getenv("BQ_TABLE")
_mem: list = []
_bq = None


def _client():
    global _bq
    if _bq is None:
        from google.cloud import bigquery
        _bq = bigquery.Client()
    return _bq


def log_claims(claims: list, lang: str):
    rows = [{
        "ts": datetime.now(timezone.utc).isoformat(), "claim_id": c["claim_id"], "claim": c["claim"][:500],
        "language": lang, "verdict": c["verdict"], "confidence": c["confidence"], "grounded": c["grounded"],
    } for c in claims]
    _mem.extend(rows)
    if BQ_TABLE and rows:
        try:
            errs = _client().insert_rows_json(BQ_TABLE, rows)
            if errs:
                print("bq insert errors:", errs)
        except Exception as e:
            print("bq log failed:", e)


def _from_memory() -> dict:
    top = collections.Counter(r["claim_id"] for r in _mem).most_common(5)
    by_id = {r["claim_id"]: r for r in _mem}
    return {
        "source": "memory", "total": len(_mem),
        "top_claims": [{"claim": by_id[i]["claim"], "checks": n, "verdict": by_id[i]["verdict"]} for i, n in top],
        "verdicts": dict(collections.Counter(r["verdict"] for r in _mem)),
        "languages": dict(collections.Counter(r["language"] for r in _mem)),
    }


def trends() -> dict:
    if not BQ_TABLE:
        return _from_memory()
    try:
        c = _client()
        win = f"FROM `{BQ_TABLE}` WHERE ts > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)"
        top = c.query(f"SELECT ANY_VALUE(claim) claim, COUNT(*) checks, ANY_VALUE(verdict) verdict {win} "
                      "GROUP BY claim_id ORDER BY checks DESC LIMIT 5").result()
        ver = c.query(f"SELECT verdict k, COUNT(*) n {win} GROUP BY k").result()
        lng = c.query(f"SELECT language k, COUNT(*) n {win} GROUP BY k").result()
        v = {r.k: r.n for r in ver}
        return {
            "source": "bigquery", "total": sum(v.values()),
            "top_claims": [{"claim": r.claim, "checks": r.checks, "verdict": r.verdict} for r in top],
            "verdicts": v, "languages": {r.k: r.n for r in lng},
        }
    except Exception as e:
        print("bq trends failed:", e)
        return _from_memory()
