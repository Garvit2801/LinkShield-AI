"""Agent pipeline: normalize -> reputation -> isolated browser / file inspection -> evidence -> deterministic risk -> Gemini."""
import asyncio
import hashlib
import os
import re
import time
import uuid
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from .guard import normalize_url
from . import behaviour
from . import piracy
from .signals import inspect_url, inspect_page, inspect_files, inspect_reputation, inspect_embedded, classify
from .providers import google_web_risk, gemini_explain, default_narrative, virustotal
from .sandbox_client import investigate, inspect_upload

DISCLAIMER = ("A low-risk result is not a guarantee of safety. Files are inspected without being opened or run, "
              "and this is not an antivirus scan.")
# Link endings that mean the person expects a file rather than a web page.
FILE_LINK = re.compile(r"\.(pdf|docx?|docm|xlsx?|xlsm|pptx?|pptm|rtf|od[tsp]|jpe?g|png|gif|webp|bmp|heic|svg|mp4|mov|mkv|avi|wmv|webm|3gp|mp3|wav|m4a|"
                       r"zip|rar|7z|gz|iso|img|apk|exe|msi|dmg|pkg|jar|bat|cmd|ps1|vbs|scr|lnk)$", re.I)
FILE_FIELDS = ("name", "extension", "type", "kind", "declared_type", "size", "bytes_checked", "sha256", "complete",
               "verdict", "score", "findings", "checks", "notes", "source_url", "links")
# Addresses that appear in document metadata and templates rather than as something a person would tap.
BORING_HOSTS = ("w3.org", "adobe.com", "purl.org", "microsoft.com", "openxmlformats.org", "xmlsoap.org", "apple.com", "iptc.org")
MAX_EMBEDDED_LINKS = 3


class ScanInput(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    message: str = Field(default="", max_length=4000)
    language: str = Field(default="en", pattern=r"^(en|hi|bn|ta|te|mr|gu|kn|ml|pa|ur)$")
    sandbox: bool = True


def public_files(raw) -> list[dict]:
    return [{k: item[k] for k in FILE_FIELDS if k in item} for item in (raw or []) if isinstance(item, dict)][:3]


def pick_links(urls: list[str]) -> list[str]:
    """Choose which links written inside a file to follow: valid, one per website, a few at most."""
    picked, hosts = [], set()
    for raw in urls:
        try:
            url = normalize_url(raw)
        except ValueError:
            continue
        host = urlsplit(url).hostname or ""
        if host in hosts or any(host == b or host.endswith("." + b) for b in BORING_HOSTS):
            continue
        hosts.add(host)
        picked.append(url)
        if len(picked) == MAX_EMBEDDED_LINKS:
            break
    return picked


async def follow_link(url: str) -> dict | None:
    try:
        sub = await scan(ScanInput(url=url), depth=1, explain=False)
    except Exception:
        return None
    return {"url": sub["url"], "domain": sub["domain"], "level": sub["level"], "score": sub["score"], "target": sub["target"],
            "headline": sub["narrative"]["headline"], "reasons": [s["label"] for s in sub["signals"][:3]]}


async def enrich(files: list[dict], follow: bool) -> tuple[list[dict], list[str]]:
    """Add what the sandbox cannot know: whether antivirus engines know the file, and where the links inside it lead.

    Returns the extra (signals, threats). The API process does these lookups because the sandbox holds no keys.
    """
    async def one(item: dict):
        urls = item.pop("links", None) or []
        item["links_found"] = len(urls)
        picks = pick_links(urls) if follow else []
        results = await asyncio.gather(virustotal(item.get("sha256")), *[follow_link(u) for u in picks])
        item["reputation"] = results[0]
        item["embedded_links"] = [r for r in results[1:] if r]
    await asyncio.gather(*[one(item) for item in files])
    signals, threats = inspect_reputation(files)
    signals += inspect_embedded(files)
    for item in files:
        rep, links = item["reputation"], item["embedded_links"]
        extra = sum(s["weight"] for s in inspect_reputation([item])[0] + inspect_embedded([item]))
        total = int(item.get("score") or 0) + extra
        if extra and total >= 30:
            item["verdict"] = "dangerous" if total >= 65 else "suspicious"
        if rep.get("checked"):
            bad = rep.get("malicious", 0)
            item.setdefault("checks", []).append(
                {"label": f"{bad} antivirus engines identify this file as malicious" if bad else
                 "No antivirus engine flags this file" if rep.get("known") else "Not in the known-malware database", "ok": not bad})
            if not rep.get("known"):
                item.setdefault("notes", []).append("Antivirus engines have never seen this exact file. That is normal for personal documents and photos, and also for brand-new malware.")
        if links:
            risky = [l for l in links if l["level"] in ("critical", "high", "caution")]
            item.setdefault("checks", []).append(
                {"label": f"{len(risky)} of the links inside lead{'s' if len(risky) == 1 else ''} somewhere risky" if risky else f"The {len(links)} link{'s' if len(links) != 1 else ''} checked inside lead nowhere risky", "ok": not risky})
    return signals, threats


def file_step(files: list[dict]) -> dict:
    first = files[0]
    outcome = {"clean": "no danger signs found", "suspicious": "warning signs found", "dangerous": "danger signs found",
               "unknown": "could only be partly checked"}.get(first.get("verdict"), "checked")
    return {"id": "file", "title": "Inspect the file in the sandbox", "status": "completed" if all(f.get("complete") for f in files) else "partial",
            "detail": f"{first.get('name', 'File')}: {first.get('type', 'file')}, {outcome}. The file was read, never opened or run."
            + (" Antivirus engines were asked whether they know it." if (first.get("reputation") or {}).get("checked") else "")
            + (f" {len(first['embedded_links'])} link{'s' if len(first['embedded_links']) != 1 else ''} inside it were traced." if first.get("embedded_links") else "")}


async def scan(payload: ScanInput, depth: int = 0, explain: bool = True) -> dict:
    """Investigate one link. depth > 0 means the link was found inside a file, so links inside its own files are not followed."""
    started = time.perf_counter()
    url = normalize_url(payload.url)
    host = urlsplit(url).hostname or ""
    steps = [{"id": "normalize", "title": "Validate link", "status": "completed", "detail": "Only public HTTP(S) addresses are accepted."}]
    wr_task = asyncio.create_task(google_web_risk(url))
    browser_task = asyncio.create_task(investigate(url)) if payload.sandbox else None
    wr = await wr_task
    steps.append({"id": "reputation", "title": "Google Web Risk lookup", "status": "completed" if wr["checked"] else "unavailable",
                  "detail": "Checked published threat intelligence." if wr["checked"] else wr.get("error", "Not checked")})
    browser = await browser_task if browser_task else {"status": "skipped", "evidence": {}, "error": "Sandbox not requested"}
    page = browser.get("evidence") or {}
    sandbox_status = browser.get("status", "error")
    files = public_files(browser.get("files"))
    target = "file" if browser.get("target") == "file" and files else "page"
    if target == "file":
        steps.append({"id": "sandbox", "title": "Sandbox download", "status": sandbox_status,
                      "detail": "This link leads straight to a file, so the sandbox downloaded it instead of your device."})
    else:
        steps.append({"id": "sandbox", "title": "Browser sandbox investigation", "status": sandbox_status,
                      "detail": "Observed a live page inside the browser worker; downloads were not executed." if sandbox_status == "completed" else browser.get("error", "Not completed")})
    final_url = page.get("final_url", url)
    # A site can refuse the sandbox (bot checks, sign-in walls). What was seen then is not the real page or file.
    refused = int(page.get("http_status") or 0) >= 400
    file_expected = bool(files) or (sandbox_status == "completed" and bool(FILE_LINK.search(urlsplit(final_url).path) or FILE_LINK.search(urlsplit(url).path)))
    file_error = None
    extra_signals, file_threats = await enrich(files, follow=depth == 0)
    if refused:
        steps[-1].update(status="partial", detail=f"The site refused the sandbox (HTTP {page['http_status']}), so the real content was not seen.")
    if files:
        steps.append(file_step(files))
    elif file_expected:
        file_error = "This link points to a file, but the sandbox could not download it" + (f" ({browser['file_error'].lower()})" if browser.get("file_error") else "") + ". It has not been checked."
        steps.append({"id": "file", "title": "Inspect the file in the sandbox", "status": "error", "detail": file_error})
    signals = inspect_url(url, payload.message)
    # Indicators for redirects are independent of initial link indicators.
    if final_url != url:
        try:
            final_url = normalize_url(final_url)
            seen = {s["code"] for s in signals}
            for signal in inspect_url(final_url):
                if signal["code"] not in seen:
                    signals.append(signal)
        except ValueError:
            final_url = url
    if sandbox_status == "completed" and target == "page":
        signals += inspect_page(page)
    seen = {s["code"] for s in signals}
    signals += [s for s in piracy.inspect(url, page if sandbox_status == "completed" else None) if s["code"] not in seen]
    signals += inspect_files(files) + extra_signals
    wr_final = {"checked": False, "threats": []}
    if final_url != url:
        wr_final = await google_web_risk(final_url)
    threats = sorted(set(wr["threats"] + wr_final.get("threats", [])))
    checked = wr["checked"] and (final_url == url or wr_final["checked"])
    # A file that could only be partly read must never be reported as low risk.
    inspected = sandbox_status if all(f.get("complete") for f in files) and not refused and not file_error else "partial"
    all_threats = sorted(set(threats + file_threats))
    level, score = classify(signals, all_threats, inspected, checked)
    steps.append({"id": "evidence", "title": "Correlate threat evidence", "status": "completed", "detail": f"{len(signals)} technical indicators; {len(threats)} Web Risk classifications."})
    narrative = await gemini_explain(level, signals, all_threats, {**page, "file_not_checked": file_error}, payload.language, files) if explain else None
    if not narrative:
        narrative = default_narrative(level, signals, all_threats, inspected, files, checked)
        if file_error and level == "unverified":
            narrative.update(headline="This file could not be checked", explanation=file_error,
                             recommendations=["Do not download it unless you were expecting it and trust the sender.",
                                              "If you do download it, add the file here to check it before opening."])
    steps.append({"id": "explain", "title": "Explain findings", "status": "completed" if narrative["generated_by"] == "gemini_vertex_ai" else "rules_fallback",
                  "detail": "Gemini on Vertex AI" if narrative["generated_by"] == "gemini_vertex_ai" else "Evidence-based local explanation"})
    # Avoid retaining content from potentially malicious sites in scan history.
    public_page = {k: page.get(k) for k in ("title", "final_url", "redirects", "password_inputs", "payment_inputs", "downloads", "generated_downloads", "cross_domain_forms", "blocked_requests", "http_status", "screenshot_base64") if k in page}
    if page.get("behaviour"):
        public_page["behaviour"] = {k: page["behaviour"].get(k) for k in ("requests", "hosts", "permissions", "exfil_hosts", "dialogs", "popups")}
        public_page["tests"] = behaviour.checks(page["behaviour"])
    return {
        "id": str(uuid.uuid4()), "url": url, "domain": host, "url_hash": hashlib.sha256(url.encode()).hexdigest(),
        "status": "completed", "target": target, "file_expected": file_expected, "file_error": file_error, "level": level, "score": score, "score_kind": "heuristic_triage_not_probability",
        "message_context_provided": bool(payload.message), "language": payload.language,
        "web_risk": {"checked": checked, "threats": threats, "error": None if checked else "Lookup incomplete or unavailable"},
        "threats": all_threats,
        "sandbox": {"status": sandbox_status, "error": browser.get("error"), "evidence": public_page},
        "files": files, "signals": signals, "narrative": narrative, "steps": steps,
        "elapsed_ms": int((time.perf_counter()-started)*1000),
        "disclaimer": DISCLAIMER
    }


async def scan_upload(data: bytes, name: str, content_type: str = "", language: str = "en", explain: bool = True) -> dict:
    """Inspect a file the user already has. The bytes go to the sandbox worker and are not stored."""
    started = time.perf_counter()
    steps = [{"id": "normalize", "title": "Receive file", "status": "completed", "detail": "The file was sent to the sandbox. It is not saved."}]
    result = await inspect_upload(data, name, content_type)
    sandbox_status = result.get("status", "error")
    files = public_files([result.get("file")])
    if files:
        steps.append(file_step(files))
    else:
        steps.append({"id": "file", "title": "Inspect the file in the sandbox", "status": sandbox_status, "detail": result.get("error", "Not completed")})
    extra_signals, threats = await enrich(files, follow=True)
    if files:
        steps[-1] = file_step(files)
    signals = inspect_files(files) + extra_signals
    inspected = sandbox_status if files and all(f.get("complete") for f in files) else "partial"
    level, score = classify(signals, threats, inspected, False)
    steps.append({"id": "evidence", "title": "Correlate threat evidence", "status": "completed", "detail": f"{len(signals)} technical indicators."})
    narrative = await gemini_explain(level, signals, threats, {}, language, files) if explain else None
    if not narrative:
        narrative = default_narrative(level, signals, threats, sandbox_status, files)
        if not files:
            narrative["headline"] = "This file could not be checked"
            narrative["explanation"] = "File inspection needs the sandbox worker, which did not complete. Nothing is known about this file."
            narrative["recommendations"] = ["Do not open it unless you were expecting it and trust the sender.", "Try the check again in a moment."]
    steps.append({"id": "explain", "title": "Explain findings", "status": "completed" if narrative["generated_by"] == "gemini_vertex_ai" else "rules_fallback",
                  "detail": "Gemini on Vertex AI" if narrative["generated_by"] == "gemini_vertex_ai" else "Evidence-based local explanation"})
    shown = files[0]["name"] if files else (name or "uploaded file")[:120]
    return {
        "id": str(uuid.uuid4()), "url": "", "domain": shown, "url_hash": hashlib.sha256(data).hexdigest(),
        "status": "completed", "target": "upload", "level": level, "score": score, "score_kind": "heuristic_triage_not_probability",
        "message_context_provided": False, "language": language,
        "web_risk": {"checked": False, "threats": [], "error": "Not applicable to an uploaded file"}, "threats": threats,
        "sandbox": {"status": sandbox_status, "error": result.get("error"), "evidence": {}},
        "files": files, "signals": signals, "narrative": narrative, "steps": steps,
        "elapsed_ms": int((time.perf_counter()-started)*1000),
        "disclaimer": DISCLAIMER
    }
