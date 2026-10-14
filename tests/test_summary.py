from app import summary


def types(s):
    return [a["type"] for a in s["actions"]]


def test_dangerous_link_is_danger():
    s = summary.build([], [{"risk": "dangerous", "url": "http://x.biz"}], ["urgency"])
    assert s["level"] == "danger"
    assert types(s)[:2] == ["dont_click", "report_cybercrime"]
    assert "check_official" in types(s)


def test_false_claim_is_warning():
    s = summary.build([{"verdict": "false"}], [], [])
    assert s["level"] == "warning"
    assert {"dont_share", "warn_others"} <= set(types(s))


def test_true_claim_is_safe():
    s = summary.build([{"verdict": "true"}], [{"risk": "safe"}], [])
    assert s["level"] == "safe" and types(s) == ["safe_to_ignore"]


def test_nothing_found_is_unclear():
    assert summary.build([], [], [])["level"] == "unclear"


def test_unverifiable_suggests_verify():
    s = summary.build([{"verdict": "unverifiable"}], [], [])
    assert s["level"] == "unclear" and "verify_source" in types(s)
