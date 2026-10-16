"""What a page or an HTML/SVG attachment did while the sandbox watched it, turned into scored findings.

Shared by the API (links) and the sandbox worker (attachments), so both score behaviour the same way.
The sandbox fast-forwards page timers by several minutes, so code that waits before acting still shows itself.
"""
import re

# Services phishing kits post stolen details to instead of running their own server.
EXFIL_HOSTS = ("api.telegram.org", "discord.com", "discordapp.com", "hooks.slack.com", "script.google.com", "formspree.io",
               "getform.io", "formsubmit.co", "submit-form.com", "webhook.site", "ngrok", "workers.dev", "pipedream.net",
               "requestbin", "000webhostapp.com", "api.emailjs.com")
MINER = re.compile(r"coinhive|coin-hive|cryptonight|webminer|minero\.cc|xmrig|cryptoloot", re.I)
# What a "fix it by pasting this" page puts on the clipboard (the ClickFix trick).
COMMAND = re.compile(r"powershell|mshta|cmd(\.exe)?\s*/c|curl\s|wget\s|bash\s|iex\b|invoke-|rundll32|regsvr32|certutil|\bWin\s*\+\s*R\b", re.I)

TESTS = [  # (key, what the report calls the test)
    ("delayed", "Waited 5 minutes for delayed actions"),
    ("downloads", "Watched for automatic downloads"),
    ("clipboard", "Watched the clipboard"),
    ("keystrokes", "Typed fake details without submitting"),
    ("permissions", "Watched for permission prompts"),
    ("lockin", "Watched for full-screen and back-button traps"),
    ("popups", "Watched for pop-ups and dialogs"),
    ("exfil", "Watched where data is sent"),
]


def is_exfil(host: str) -> bool:
    host = (host or "").lower()
    return any(h in host for h in EXFIL_HOSTS)


def findings(b: dict) -> list[dict]:
    """b is the 'behaviour' block the sandbox returns. Returns findings with code, label, weight and detail."""
    out = []

    def add(code, label, weight, detail):
        out.append({"code": code, "label": label, "weight": weight, "detail": detail})

    if not b:
        return out
    if any(COMMAND.search(c or "") for c in b.get("clipboard") or []):
        add("clipboard_command", "Puts a command on your clipboard", 70,
            "The page copied a computer command for you to paste into Run or a terminal. This 'fix it yourself' trick installs malware.")
    if b.get("keystroke_leak"):
        add("keystroke_leak", "Sends what you type before you submit", 60,
            "Fake details typed into the page were sent off at once, without pressing any button. Real login pages do not do this.")
    if b.get("exfil_hosts") and (b.get("password_inputs") or b.get("keystroke_leak")):
        add("exfil_service", "Sends data to a chat or webhook service", 35,
            f"The page talks to {', '.join(b['exfil_hosts'][:2])}, a service scam kits use to collect stolen details.")
    if b.get("fullscreen") or (b.get("back_trap") and b.get("dialogs", 0) >= 2):
        add("lock_in", "Tries to trap you on the page", 35,
            "It goes full screen, blocks the back button or keeps showing alerts, as fake virus and tech-support pages do.")
    elif b.get("back_trap"):
        add("back_trap", "Blocks the back button", 15, "The page rewrites browser history so pressing Back keeps you on it.")
    perms = sorted(set(b.get("permissions") or []))
    sensitive = [p for p in perms if p in ("camera", "microphone", "location", "saved logins")]
    if sensitive:
        add("permission_ask", f"Asks for your {' and '.join(sensitive)}", 20,
            "The page asked for access without you doing anything. Do not allow it unless you trust the site.")
    elif "notifications" in perms:
        add("notification_ask", "Asks to send you notifications", 10,
            "Scam sites use notification permission to keep pushing fake alerts after you leave.")
    if b.get("delayed_redirect"):
        add("delayed_redirect", "Switches to another site after a delay", 20,
            "After waiting, the page sent the browser to a different website, a trick for hiding the real destination from quick checks.")
    if b.get("late_downloads"):
        add("late_download", "Starts a download after a delay", 40, "A download began only after the page had been open for a while.")
    if b.get("miner"):
        add("miner", "Uses your device to mine cryptocurrency", 40, "The page loads known crypto-mining code.")
    if b.get("popups", 0) >= 2 or b.get("dialogs", 0) >= 3:
        add("popups", "Opens pop-ups or alert boxes", 10, "The page kept opening new windows or alert boxes.")
    return out


def checks(b: dict) -> list[dict]:
    """Which behaviour tests ran and whether each came out clean, for the report."""
    if not b:
        return []
    bad = {f["code"] for f in findings(b)}
    trouble = {
        "delayed": {"delayed_redirect", "late_download"}, "downloads": {"late_download"}, "clipboard": {"clipboard_command"},
        "keystrokes": {"keystroke_leak"}, "permissions": {"permission_ask", "notification_ask"}, "lockin": {"lock_in", "back_trap"},
        "popups": {"popups"}, "exfil": {"exfil_service"},
    }
    ran = set(b.get("tests") or [])
    return [{"label": label, "ok": not (trouble[key] & bad)} for key, label in TESTS if key in ran]
