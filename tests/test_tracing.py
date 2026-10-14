from types import SimpleNamespace as N

from app import summary, tracing


def test_classify_domains():
    assert tracing.classify("boomlive.in") == "factcheck"
    assert tracing.classify("hindi.boomlive.in") == "factcheck"
    assert tracing.classify("factcheck.pib.gov.in") == "factcheck"
    assert tracing.classify("pib.gov.in") == "official"
    assert tracing.classify("who.int") == "official"
    assert tracing.classify("thehindu.com") == "news"
    assert tracing.classify("") == "other"
    assert tracing.classify("pesacheck.org") == "factcheck"
    assert tracing.classify("notboomlive.in") == "news"


def test_host_from_domain_or_title():
    assert tracing.host_of({"domain": "www.AltNews.in"}) == "altnews.in"
    assert tracing.host_of({"title": "boomlive.in", "url": "https://x/redirect"}) == "boomlive.in"
    assert tracing.host_of({"title": "Some headline text", "url": "https://www.thehindu.com/a"}) == "thehindu.com"


def test_enrich_orders_and_validates_notes():
    sources = [{"title": "a", "url": "u1", "domain": "thehindu.com"},
               {"title": "b", "url": "u2", "domain": "boomlive.in"},
               {"title": "c", "url": "u3", "domain": "who.int"}]
    notes = [N(index=2, stance="contradicts", published="2024-03-01"), N(index=9, stance="supports", published=None),
             N(index=1, stance="bogus", published="")]
    out = tracing.enrich(sources, notes)
    assert [s["kind"] for s in out] == ["factcheck", "official", "news"]
    assert out[0]["stance"] == "contradicts" and out[0]["published"] == "2024-03-01"
    assert out[1]["stance"] == "neutral"
    assert out[2]["stance"] == "neutral" and out[2]["published"] is None


def test_build_trace():
    out = tracing.enrich([{"title": "b", "url": "u", "domain": "boomlive.in"}], [N(index=1, stance="contradicts", published=None)])
    t = tracing.build(out, "  Started on a Telegram channel in 2023. ")
    assert t == {"fact_checked": True, "fact_checkers": ["boomlive.in"], "official_sources": [],
                 "supporting": 0, "contradicting": 1, "origin": "Started on a Telegram channel in 2023."}
    assert tracing.build([], None)["origin"] is None


def test_summary_suggests_reading_fact_check():
    claim = {"verdict": "false", "trace": {"fact_checked": True}}
    assert "read_fact_check" in [a["type"] for a in summary.build([claim], [], [])["actions"]]
    assert "read_fact_check" not in [a["type"] for a in summary.build([{"verdict": "false"}], [], [])["actions"]]
