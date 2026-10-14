"""Source tracing: classify grounded sources and summarise who has checked a claim."""
from urllib.parse import urlparse

FACT_CHECKERS = {
    "boomlive.in", "altnews.in", "vishvasnews.com", "factly.in", "newschecker.in", "factcheck.pib.gov.in",
    "factcheck.afp.com", "reuters.com", "snopes.com", "factchecker.in", "dfrac.org", "logically.ai",
    "politifact.com", "fullfact.org", "factcheck.org", "pesacheck.org", "africacheck.org", "leadstories.com",
    "misbar.com", "factcrescendo.com", "teyit.org", "newsmeter.in", "thip.media", "digiteye.in",
}
OFFICIAL_SUFFIXES = (".gov.in", ".nic.in", ".gov", ".edu.in", ".ac.in")
OFFICIAL_HOSTS = {"who.int", "un.org", "unicef.org", "rbi.org.in"}
STANCES = ("supports", "contradicts", "neutral")


def host_of(source: dict) -> str:
    host = (source.get("domain") or "").lower()
    if not host:
        title = (source.get("title") or "").lower()
        host = title if "." in title and " " not in title else urlparse(source.get("url", "")).netloc.lower()
    return host.removeprefix("www.")


def _matches(host: str, domains) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def classify(host: str) -> str:
    if _matches(host, FACT_CHECKERS):
        return "factcheck"
    if host.endswith(OFFICIAL_SUFFIXES) or _matches(host, OFFICIAL_HOSTS):
        return "official"
    return "news" if host else "other"


def enrich(sources: list, notes: list | None) -> list:
    """Attach publisher, kind, stance and date to each source. `notes` are 1-based judge annotations."""
    by_index = {}
    for n in notes or []:
        i = getattr(n, "index", None)
        if isinstance(i, int) and 1 <= i <= len(sources):
            by_index[i - 1] = n
    out = []
    for i, s in enumerate(sources):
        host = host_of(s)
        n = by_index.get(i)
        stance = getattr(n, "stance", "neutral")
        out.append({**s, "publisher": host or s.get("title", ""), "kind": classify(host),
                    "stance": stance if stance in STANCES else "neutral",
                    "published": (getattr(n, "published", None) or None)})
    order = {"factcheck": 0, "official": 1, "news": 2, "other": 3}
    return sorted(out, key=lambda s: order.get(s["kind"], 3))


def build(sources: list, origin: str | None) -> dict:
    fc = [s for s in sources if s["kind"] == "factcheck"]
    return {
        "fact_checked": bool(fc),
        "fact_checkers": sorted({s["publisher"] for s in fc}),
        "official_sources": sorted({s["publisher"] for s in sources if s["kind"] == "official"}),
        "supporting": sum(s["stance"] == "supports" for s in sources),
        "contradicting": sum(s["stance"] == "contradicts" for s in sources),
        "origin": (origin or "").strip() or None,
    }
