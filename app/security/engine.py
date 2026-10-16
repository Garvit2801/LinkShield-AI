"""One check for anything a person was sent: a message, links, a screenshot, a voice note or a file.

Extract -> three branches (claims, links, files) -> summary. Link and file verdicts come from fixed rules
and threat lookups only. Gemini reads the input, fact-checks claims and writes the summary; it never
decides or changes a link or file verdict.
"""
import asyncio
import hashlib
import io
import os
import re
import time
import uuid
import zipfile

from .orchestrator import DISCLAIMER, ScanInput, scan, scan_upload
from .guard import normalize_url
from .providers import gemini_summary
from .signals import classify, detect_tactics, inspect_message

MAX_LINKS = 3
MAX_CHAT_LINKS = 5  # a chat export can hold hundreds; the most recent ones are checked
PART_DEADLINE = 90  # seconds one link or file may take before the check goes on without it
# A line of a WhatsApp chat export, e.g. "12/03/24, 9:41 pm - Name: text" or "[12/03/2024, 21:41:05] Name: text".
CHAT_LINE = re.compile(r"^\[?\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4},?\s+\d{1,2}[:.]\d{2}", re.M)
MAX_CLAIMS = 3
MAX_MEDIA_BYTES = 8 * 1024 * 1024
SUPPORTED = {"hi", "en", "bn", "ta", "te", "mr", "gu", "kn", "ml", "pa", "ur"}
RANK = {"low": 0, "unverified": 1, "caution": 2, "high": 3, "critical": 4}
SCORE_FLOOR = {"low": 0, "unverified": 0, "caution": 30, "high": 65, "critical": 98}
CLAIM_LEVEL = {"false": "caution", "misleading": "caution", "unverifiable": "unverified", "true": "low"}
URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"'`]+"
    r"|(?<![@\w.])(?:[a-z0-9-]+\.)+(?:com|in|org|net|co|io|info|biz|xyz|top|app|site|online|live|club|shop|link|click|me|ly|gov|edu|"
    r"bank|sbi|icu|cfd|sbs|zip|mov|monster|page|dev)\b(?:/[^\s<>\"'`]*)?", re.I)
IMAGE_MAGIC = ((b"\xff\xd8\xff", "image/jpeg"), (b"\x89PNG\r\n\x1a\n", "image/png"), (b"GIF8", "image/gif"))
AUDIO_EXT = ("ogg", "oga", "opus", "mp3", "m4a", "wav", "aac", "amr", "flac", "weba")
NO_AI = "needs Gemini, which is not connected on this server"


def gemini_on() -> bool:
    return bool(os.getenv("GOOGLE_CLOUD_PROJECT")) and os.getenv("DISABLE_GOOGLE", "0") != "1"


def find_urls(text: str, limit: int = MAX_LINKS) -> list[str]:
    found = []
    for raw in URL_RE.findall(text or ""):
        try:
            url = normalize_url(raw.rstrip(".,;:!?)]}>।”’\"'"))
        except ValueError:
            continue
        if url not in found:
            found.append(url)
    return found[:limit]


def chat_export(data: bytes, name: str) -> str | None:
    """The text of an exported chat (WhatsApp "Export chat", as .txt or .zip), or None if this is not one."""
    text = None
    if data[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                chats = [i for i in z.infolist() if i.filename.lower().endswith(".txt") and i.file_size <= 5_000_000]
                if chats:
                    with z.open(max(chats, key=lambda i: i.file_size)) as f:
                        text = f.read(5_000_000).decode("utf-8", "replace")
        except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError):
            return None
    elif name.lower().endswith(".txt") or not name:
        text = data[:5_000_000].decode("utf-8", "replace")
    if not text or len(CHAT_LINE.findall(text[:20000])) < 3:
        return None
    return text


def media_kind(data: bytes, name: str, content_type: str, recording: bool = False) -> tuple[str, str] | None:
    """('image'|'audio', mime type) when Gemini can read the attachment as a screenshot or a voice note."""
    for magic, mime in IMAGE_MAGIC:
        if data.startswith(magic):
            return "image", mime
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image", "image/webp"
    declared = (content_type or "").split(";")[0].strip().lower()
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if recording or declared.startswith("audio/") or ext in AUDIO_EXT or data[:4] in (b"OggS", b"fLaC") or data[:3] == b"ID3" or \
            (data[:4] == b"RIFF" and data[8:12] == b"WAVE") or data[:5] == b"#!AMR":
        return "audio", declared or "audio/ogg"
    return None


async def gemini_extract(text: str, image: tuple[bytes, str] | None, audio: bytes | None) -> dict:
    """Read the message, screenshot or voice note: transcript, language, checkable claims and pressure tactics."""
    from google.genai import types
    from .. import pipeline
    parts = []
    if text:
        parts.append(types.Part.from_text(text="Message text:\n" + text))
    if image:
        parts.append(types.Part.from_bytes(data=image[0], mime_type=image[1]))
    if audio:
        parts.append(types.Part.from_bytes(data=await pipeline.to_wav(audio), mime_type="audio/wav"))
    out = await pipeline.extract(parts)
    return {"transcript": out.transcript or text, "input_language": out.input_language, "claims": list(out.claims), "tactics": list(out.tactics),
            "scam_patterns": [p.model_dump() for p in out.scam_patterns]}


# Gemini knows many more scam types than fixed rules do, but it only ever adds risk, never removes it, and each pattern must quote
# the message. Its total is capped, so on its own it can reach "caution" but never "high"; rules and the sandbox decide the rest.
PATTERN_WEIGHT = {"high": 30, "medium": 18, "low": 8}
PATTERN_CAP = 35


def pattern_signals(patterns: list, transcript: str) -> list[dict]:
    seen = " ".join((transcript or "").lower().split())
    out, total = [], 0
    for p in sorted(patterns or [], key=lambda p: -PATTERN_WEIGHT.get(p.get("severity"), 0)):
        quote = " ".join(str(p.get("quote", "")).lower().split()).strip(" .\"'“”")
        name = str(p.get("name", "")).strip()[:60]
        weight = min(PATTERN_WEIGHT.get(p.get("severity"), 0), PATTERN_CAP - total)
        if len(quote) < 6 or quote not in seen or not name or weight <= 0:
            continue  # not grounded in the message itself
        total += weight
        out.append({"code": "gemini_pattern", "label": f"Matches a known scam: {name}", "weight": weight,
                    "detail": f"Gemini recognised this pattern from the words \u201c{str(p['quote']).strip()[:120]}\u201d.", "source": "gemini_patterns"})
    return out


async def gemini_claim(claim: str, language: str) -> dict:
    """Research one claim with Google Search grounding, then judge it from the research notes only."""
    from .. import pipeline
    return await pipeline.check_claim(claim, language)


def defang(url: str) -> str:
    return re.sub(r"^https?://", "", url or "", flags=re.I).replace(".", "[.]")[:120]


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def default_summary(level: str, links: list, uploads: list, claims: list, message_signals: list, notes: list) -> dict:
    """The summary when Gemini is not available: built from the fixed verdicts, in English."""
    def worst(items):
        return max(items, key=lambda r: (RANK[r["level"]], r["score"]), default=None)
    bad_link, bad_file = worst(links), worst(uploads)
    false_claims = [c for c in claims if c["verdict"] in ("false", "misleading")]
    link_led = bad_link and RANK[bad_link["level"]] == RANK[level]
    file_led = bad_file and RANK[bad_file["level"]] == RANK[level]
    if level in ("critical", "high"):
        headline = "Do not open this file" if file_led and not link_led else "Do not open this link" if link_led else "This message looks like a scam"
    elif level == "caution":
        headline = ("Be careful with this link" if link_led else "Be careful with this file" if file_led else
                    "This message shows scam warning signs" if message_signals else
                    "This message contains a false claim" if any(c["verdict"] == "false" for c in claims) else "This message contains a misleading claim")
    elif level == "unverified":
        headline = "Part of this could not be checked" if links or uploads or claims else "Nothing here could be checked"
    else:
        headline = "No warning signs found"
    said = []
    for r in links[:MAX_LINKS]:
        why = ", ".join(s["label"].lower() for s in r["signals"][:2])
        if why or r["level"] != "low":
            said.append(f"The link to {defang(r['domain'])} is rated {r['level'].replace('unverified', 'unverified because too little could be checked')}"
                        + (f": {why}." if why else "."))
        else:
            said.append(f"{defang(r['domain'])}: {r['narrative']['explanation']}")
    for r in uploads:
        why = ", ".join(s["label"].lower() for s in r["signals"][:2])
        said.append(f"{r['domain']}: {r['narrative']['headline'].lower()}" + (f" ({why})." if why else "."))
    if claims:
        counts = {v: sum(1 for c in claims if c["verdict"] == v) for v in ("false", "misleading", "true", "unverifiable")}
        said.append(f"{_plural(len(claims), 'claim')} checked against sources: " + ", ".join(f"{n} {v}" for v, n in counts.items() if n) + ".")
    if message_signals:
        said.append("The wording itself is a warning sign: " + ", ".join(s["label"].lower() for s in message_signals[:3]) + ".")
    said += notes
    steps = []
    lead = sorted((r for r in (bad_link, bad_file) if r and r["level"] != "low"), key=lambda r: -RANK[r["level"]])
    for i, r in enumerate(lead):
        steps += r["narrative"]["recommendations"][:1 if i else 3]
    if not lead and bad_file:
        steps += bad_file["narrative"]["recommendations"][:2]
    if any(s["code"] == "secret_request" for s in message_signals):
        steps.insert(0, "Never share an OTP, PIN, CVV or password with anyone who contacts you, whoever they say they are.")
    if false_claims:
        steps.append("Do not forward this message. If someone sent it to you in good faith, tell them it is not accurate.")
    if not steps:
        steps = (["Check with the sender through a phone call or another app before acting on it.",
                  "Do not pay, install anything or share codes because a message told you to."] if level != "low" else
                 ["Nothing suspicious was found, but stay alert if you are later asked for money, codes or passwords."])
    seen = []
    for step in steps:
        if step not in seen:
            seen.append(step)
    return {"headline": headline, "explanation": " ".join(said) or "There was no link, file or checkable claim in what you sent.",
            "next_steps": seen[:4], "generated_by": "rules"}


async def check(text: str = "", language: str = "", attachment: tuple[bytes, str, str] | None = None, recording: bool = False) -> dict:
    """attachment is (bytes, file name, declared content type). recording marks a voice note recorded in the app."""
    started = time.perf_counter()
    text = (text or "").strip()[:6000]
    if not text and not attachment:
        raise ValueError("Add a message, a link, a screenshot, a voice note or a file.")
    ai = gemini_on()
    chat = chat_export(attachment[0], attachment[1]) if attachment and not recording else None
    chat_urls = []
    if chat:
        # An exported chat is read as a conversation: its newest links are traced and its latest messages read.
        newest_first = list(reversed(URL_RE.findall(chat)))
        chat_urls = find_urls(" ".join(newest_first[:60]), MAX_CHAT_LINKS)
        all_links = len(set(URL_RE.findall(chat)))
        text = (text + "\n" if text else "") + chat[-5000:]
        attachment = None
        chat_note = (f"Chat export: the {_plural(len(chat_urls), 'most recent link')} of {all_links} and the latest messages were checked."
                     if all_links > len(chat_urls) else "Chat export: every link and the latest messages were checked.")
    media = media_kind(attachment[0], attachment[1], attachment[2], recording) if attachment else None
    readable = media if media and len(attachment[0]) <= MAX_MEDIA_BYTES else None
    notes, steps, unread = ([chat_note] if chat else []), [], False

    # 1. Extract: what does the message say, and what in it can be checked?
    read = {"transcript": text, "input_language": "", "claims": [], "tactics": detect_tactics(text), "scam_patterns": []}
    lone_link = bool(text) and not re.search(r"\s", text) and not readable
    if ai and (text or readable) and not lone_link:
        try:
            read = await gemini_extract(text, (attachment[0], readable[1]) if readable and readable[0] == "image" else None,
                                        attachment[0] if readable and readable[0] == "audio" else None)
            read["tactics"] = list(dict.fromkeys(read["tactics"] + detect_tactics(read["transcript"])))
            steps.append({"id": "extract", "title": "Read what you sent", "status": "completed",
                          "detail": f"Gemini read the {'screenshot' if readable and readable[0] == 'image' else 'voice note' if readable else 'message'} and found {_plural(len(read['claims']), 'checkable claim')}."})
        except Exception:
            steps.append({"id": "extract", "title": "Read what you sent", "status": "error", "detail": "Gemini could not read this input, so only links and files were checked."})
            notes.append("The message could not be read by Gemini, so any claims in it were not fact-checked.")
            unread = bool(readable)
    else:
        if readable:
            what = "The screenshot" if readable[0] == "image" else "The voice note"
            notes.append(f"{what} could not be read: that {NO_AI}.")
            unread = True
        elif len(text.split()) >= 6 and not ai:
            notes.append(f"Claims in the message were not fact-checked: that {NO_AI}.")
        steps.append({"id": "extract", "title": "Read what you sent", "status": "unavailable" if readable else "rules_fallback",
                      "detail": f"Reading screenshots and voice notes {NO_AI}." if readable else "Links were pulled out of the text and its wording was checked against known scam patterns."})
    transcript = (read["transcript"] or text)[:6000]
    out_lang = language if language in SUPPORTED else read["input_language"] if read["input_language"] in SUPPORTED else "en"
    urls = chat_urls or find_urls(text + " " + transcript)
    inspect_attachment = bool(attachment) and not recording

    # 2. Three branches, side by side.
    async def branch(coros):
        # A slow sandbox visit is left out (and reported as partly checked) rather than holding up the whole answer.
        return [r for r in await asyncio.gather(*(asyncio.wait_for(c, PART_DEADLINE) for c in coros), return_exceptions=True) if isinstance(r, dict)]
    claims, links, uploads = await asyncio.gather(
        branch([gemini_claim(c, out_lang) for c in read["claims"][:MAX_CLAIMS]] if ai else []),
        branch([scan(ScanInput(url=u, message=transcript[:4000], language=out_lang), explain=False) for u in urls]),
        branch([scan_upload(attachment[0], attachment[1], attachment[2], out_lang, explain=False)] if inspect_attachment else []))
    if urls:
        steps.append({"id": "links", "title": "Trace links in the sandbox", "status": "completed" if len(links) == len(urls) else "partial",
                      "detail": f"{_plural(len(links), 'link')} traced: " + ", ".join(f"{defang(r['domain'])} ({r['level']})" for r in links) + "."})
    if inspect_attachment:
        done = bool(uploads) and bool(uploads[0]["files"])
        steps.append({"id": "files", "title": "Inspect the file in the sandbox", "status": "completed" if done else "error",
                      "detail": f"{uploads[0]['domain']}: {uploads[0]['narrative']['headline'].lower()}." if uploads else "The file could not be inspected."})
    if read["claims"]:
        failed = len(read["claims"][:MAX_CLAIMS]) - len(claims)
        steps.append({"id": "claims", "title": "Check claims against sources", "status": "completed" if not failed else "partial",
                      "detail": f"{_plural(len(claims), 'claim')} researched with Google Search and judged from the sources found."})
        if failed:
            notes.append(f"{_plural(failed, 'claim')} could not be fact-checked this time.")

    # 3. Overall level: the worst fixed verdict among the parts. Nothing judged means unverified, never low.
    message_signals = inspect_message(transcript) + pattern_signals(read.get("scam_patterns"), transcript)
    if links:  # each link already counted the message's scam wording
        message_signals = [s for s in message_signals if s["code"] != "social_pressure"]
    message_level, message_score = classify(message_signals, [], "completed", False)
    levels = [r["level"] for r in links + uploads] + [CLAIM_LEVEL[c["verdict"]] for c in claims]
    if message_level != "low":
        levels.append(message_level)
    level = max(levels, key=RANK.get) if levels else "unverified"
    if unread and level == "low":  # what the screenshot or voice note says was never seen
        level = "unverified"
    score = max([r["score"] for r in links + uploads] + [message_score])
    # A level set by a claim verdict alone still gets a score inside that level's band, so the two never disagree.
    score = max(score, SCORE_FLOOR[level])

    # 4. Summary: explains the verdicts above and cannot change them.
    evidence = {
        "links": [{"website": defang(r["domain"]), "level": r["level"], "leads_to_file": bool(r["files"]), "reasons": [s["label"] for s in r["signals"][:5]]} for r in links],
        "files": [{"name": r["domain"], "level": r["level"], "type": (r["files"] or [{}])[0].get("type"), "reasons": [s["label"] for s in r["signals"][:5]]} for r in uploads],
        "claims": [{"claim": c["claim"], "verdict": c["verdict"], "explanation": c["explanation"], "sources": len(c["sources"])} for c in claims],
        "message_warning_signs": [s["label"] for s in message_signals], "pressure_tactics": read["tactics"], "not_checked": notes}
    summary = await gemini_summary(level, evidence, out_lang) or default_summary(level, links, uploads, claims, message_signals, notes)
    steps.append({"id": "summary", "title": "Write the summary", "status": "completed" if summary["generated_by"] == "gemini_vertex_ai" else "rules_fallback",
                  "detail": "Gemini on Vertex AI explained the verdicts." if summary["generated_by"] == "gemini_vertex_ai" else "Built from the verdicts by fixed rules."})
    # Fixed follow-up actions (report, read the fact-check, ...) the page turns into buttons.
    from .. import summary as actions
    risk = {"critical": "dangerous", "high": "dangerous", "caution": "suspicious"}
    summary["actions"] = actions.build(claims, [{"risk": risk.get(r["level"], "safe"), "url": r.get("url")} for r in links + uploads], read["tactics"])["actions"]

    label = (links[0]["domain"] if links else uploads[0]["domain"] if uploads else
             transcript[:70] if transcript else "Voice note" if media and media[0] == "audio" else attachment[1][:70] if attachment else "Message")
    return {
        "id": str(uuid.uuid4()), "kind": "check", "status": "completed", "label": label, "level": level, "score": score,
        "score_kind": "heuristic_triage_not_probability", "language": out_lang, "input_language": read["input_language"],
        "input": {"text": bool(text), "attachment": {"name": attachment[1][:200], "size": len(attachment[0]),
                                                     "read_as": readable[0] if readable else None} if attachment else None, "recording": recording},
        "transcript": transcript[:1500] if (readable or len(transcript) > 80) else "", "tactics": read["tactics"],
        "message_signals": message_signals, "claims": claims, "links": links, "uploads": uploads, "notes": notes,
        "summary": summary, "steps": steps, "ai": ai,
        "url_hash": hashlib.sha256((text + "|".join(urls)).encode() + (hashlib.sha256(attachment[0]).digest() if attachment else b"")).hexdigest(),
        "elapsed_ms": int((time.perf_counter() - started) * 1000), "disclaimer": DISCLAIMER,
    }
