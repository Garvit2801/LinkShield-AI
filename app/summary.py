"""Deterministic post-scan summary and recommended actions. The UI localises by `type`."""

LEVELS = ("danger", "warning", "unclear", "safe")


def build(claims: list, links: list, tactics: list) -> dict:
    bad_links = [l for l in links if l.get("risk") == "dangerous"]
    sus_links = [l for l in links if l.get("risk") == "suspicious"]
    false_c = [c for c in claims if c.get("verdict") == "false"]
    mislead_c = [c for c in claims if c.get("verdict") == "misleading"]
    unver_c = [c for c in claims if c.get("verdict") == "unverifiable"]
    true_c = [c for c in claims if c.get("verdict") == "true"]
    pressure = bool(tactics)

    if bad_links:
        level = "danger"
    elif false_c or sus_links or (mislead_c and pressure):
        level = "warning"
    elif mislead_c or unver_c or pressure:
        level = "unclear"
    elif claims or links:
        level = "safe"
    else:
        level = "unclear"

    actions = []

    def add(type_, priority, **extra):
        actions.append({"type": type_, "priority": priority, **extra})

    if bad_links or sus_links:
        add("dont_click", 1, urls=[l.get("final_url") or l.get("url") for l in bad_links + sus_links])
    if bad_links:
        add("report_cybercrime", 2, helpline="1930", url="https://cybercrime.gov.in")
        add("report_sender", 3)
    if false_c or mislead_c or bad_links:
        add("dont_share", 2)
        add("warn_others", 4)
    if unver_c or mislead_c:
        add("verify_source", 3)
    if pressure and (bad_links or sus_links or false_c):
        add("check_official", 3)
    if level == "safe":
        add("safe_to_ignore", 5)
    actions.sort(key=lambda a: a["priority"])

    return {
        "level": level,
        "counts": {"false": len(false_c), "misleading": len(mislead_c), "unverifiable": len(unver_c),
                   "true": len(true_c), "dangerous_links": len(bad_links), "suspicious_links": len(sus_links)},
        "actions": actions,
    }
