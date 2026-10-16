"""Deterministic, explainable threat indicators; scores are triage rankings, not probabilities."""
import ipaddress
import re
from urllib.parse import urlsplit, unquote

from . import behaviour

# Brand word -> the registered domains that brand really uses. A host is official when it equals one or sits under it.
BRANDS = {
    "sbi": ("sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com", "sbilife.co.in", "sbimf.com", "sbigeneral.in",
            "sbisecurities.in", "sbiyono.sbi", "sbi"),
    "hdfc": ("hdfcbank.com", "hdfc.com", "hdfclife.com", "hdfcergo.com", "hdfcsec.com", "hdfcfund.com", "hdfcsky.com"),
    "icici": ("icicibank.com", "icicidirect.com", "iciciprulife.com", "icicilombard.com", "icicipruamc.com", "icicihfc.com"),
    "axis": ("axisbank.com", "axismf.com", "axisdirect.in", "axismaxlife.com", "axiscapital.co.in", "axisfinance.in"),
    "paytm": ("paytm.com", "paytm.in", "paytmbank.com", "paytmmoney.com", "paytminsider.com", "paytmpayments.com"),
    "phonepe": ("phonepe.com",),
    "googlepay": ("pay.google.com", "google.com"),
    "amazon": ("amazon.in", "amazon.com", "amazonaws.com", "amazonpay.in", "amazon.jobs", "amazon.science", "amazon.dev",
               "aboutamazon.com", "aboutamazon.in", "media-amazon.com", "ssl-images-amazon.com"),
    "flipkart": ("flipkart.com", "flipkart.net", "flixcart.com"),
    "whatsapp": ("whatsapp.com", "whatsapp.net", "wa.me"),
    "indiapost": ("indiapost.gov.in",), "uidai": ("uidai.gov.in",),
    "epfo": ("epfindia.gov.in",), "irctc": ("irctc.co.in", "irctc.com", "irctctourism.com"),
}
# Registries that only hand out names to verified organisations (Indian government, RBI-regulated banks and lenders).
RESTRICTED_SUFFIXES = (".gov.in", ".nic.in", ".bank.in", ".fin.in", ".gov", ".mil")
AMAZON_REGIONAL = re.compile(r"(^|\.)amazon\.(co\.[a-z]{2}|com\.[a-z]{2}|[a-z]{2})$")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy", "tiny.cc"}
SUSP_TLDS = {"zip", "mov", "top", "click", "icu", "cfd", "sbs", "monster"}
# \b does not work around Devanagari vowel signs, so Indian-language terms are matched without word boundaries.
SCAM_TERMS = re.compile(
    r"\b(kyc|otp|verify your account|account (?:is |has been |will be )?(?:blocked|suspended|frozen)|prize|lottery|urgent(?:ly)?|upi pin|cvv|"
    r"free gift|refund|suspended|delivery fee|customs fee|processing fee|electricity (?:bill|connection)|pan card|aadhaar|"
    r"turant|khata band|inaam|jeeta)\b"
    r"|केवाईसी|ओटीपी|पैन कार्ड|आधार|खाता (?:बंद|ब्लॉक)|ब्लॉक|तुरंत|लॉटरी|इनाम|बिजली (?:बिल|कनेक्शन)"
    r"|কেওয়াইসি|ওটিপি|লটারি|கேஒய்சி|ஓடிபி|కేవైసీ|ఓటీపీ|केवायसी|કેવાયસી|ઓટીપી", re.I)
SECRET_REQUEST = re.compile(
    r"\b(?:share|send|tell|give|enter|provide|confirm|forward|batao|bhejo|bata)\b[^.!?\n]{0,60}\b(?:otp|one[- ]time (?:password|code)|upi pin|mpin|atm pin|cvv|password|verification code|card number)\b"
    r"|(?:ओटीपी|पिन|पासवर्ड|सीवीवी)[^।.!?\n]{0,40}(?:बताएं|बताइए|बताओ|भेजें|भेजो|शेयर|साझा)"
    r"|(?:बताएं|बताओ|भेजें|भेजो|शेयर)[^।.!?\n]{0,40}(?:ओटीपी|पिन|पासवर्ड|सीवीवी)", re.I)
REMOTE_APP = re.compile(r"\b(anydesk|teamviewer|quicksupport|rustdesk|airdroid|screen ?share|remote access app)\b|\.apk\b", re.I)
MONEY_REQUEST = re.compile(
    r"\b(?:pay|send|transfer|deposit)\b[^.!?\n]{0,50}(?:₹|rs\.?|inr|rupees|fee|charge|amount)|\b(?:registration|processing|customs|security|clearance) (?:fee|charge|deposit)\b"
    r"|(?:शुल्क|फीस) (?:जमा|भेजें|भरें)", re.I)
TACTICS = {
    "urgency": re.compile(r"\b(urgent(?:ly)?|immediately|right now|within \d+ ?(?:hours?|hrs?|minutes?|mins?|days?)|last chance|expires? (?:today|soon)|act now|turant|abhi|jaldi)\b|तुरंत|अभी|जल्दी|आज ही|অবিলম্বে|உடனடியாக|వెంటనే", re.I),
    "fear": re.compile(r"\b(blocked|suspended|frozen|deactivated|disconnected|legal action|arrest(?:ed)?|penalty|fir|terminated|khata band)\b|बंद|ब्लॉक|गिरफ्तार|जुर्माना|कानूनी कार्रवाई", re.I),
    "fake_authority": re.compile(r"\b(rbi|reserve bank|income tax|customs|police|cbi|trai|uidai|government|govt|ministry|bank manager|customer care)\b|सरकार|पुलिस|आयकर|रिज़र्व बैंक", re.I),
    "forward_chain": re.compile(r"\b(forward (?:this|to)|share (?:this )?with (?:everyone|all|\d+)|send (?:this )?to (?:all|\d+)|sabko bhejo|pass it on)\b|फॉरवर्ड|सबको भेजें|सभी को भेजें|शेयर करें", re.I),
    "miracle_cure": re.compile(r"\b(cures?|miracle|guaranteed (?:cure|treatment)|doctors (?:hate|don't want)|100% (?:cure|effective)|home remedy)\b|इलाज|चमत्कार|रामबाण", re.I),
    "emotional_bait": re.compile(r"\b(congratulations|you (?:have )?won|winner|prize|lottery|free (?:gift|recharge|phone|laptop)|lucky draw|cashback of)\b|बधाई|जीत|इनाम|लॉटरी|मुफ्त", re.I),
}


def official_host(host: str, brand: str) -> bool:
    """True when the host belongs to the brand, or to a registry that scammers cannot register names under."""
    if host.endswith(RESTRICTED_SUFFIXES):
        return True
    if brand == "amazon" and AMAZON_REGIONAL.search(host):
        return True
    return any(host == d or host.endswith("." + d) for d in BRANDS[brand])


def inspect_url(url: str, message: str = "") -> list[dict]:
    p = urlsplit(url)
    host = p.hostname or ""
    flags = []
    def add(code, label, weight, detail):
        flags.append({"code": code, "label": label, "weight": weight, "detail": detail, "source": "local_rules"})
    if p.scheme == "http":
        add("http_only", "Unencrypted HTTP connection", 10, "The link does not use HTTPS. HTTPS alone does not prove legitimacy.")
    if host.startswith("xn--") or ".xn--" in host:
        add("punycode", "Internationalized domain encoding", 16, "Encoded characters may hide a lookalike domain.")
    if host in SHORTENERS:
        add("shortener", "Shortened destination", 16, "A short link hides the final destination until investigated.")
    if host.split(".")[-1] in SUSP_TLDS:
        add("uncommon_tld", "Higher-risk domain extension", 13, "This extension merits closer inspection but is not proof of fraud.")
    if host.count("-") >= 3:
        add("hyphens", "Unusual domain structure", 8, "Multiple hyphens can be associated with impersonation.")
    if len(host) > 55:
        add("long_domain", "Very long domain", 8, "Long domains may obscure their owner.")
    if "@" in unquote(p.path + "?" + p.query):
        add("encoded_at", "Obfuscated link characters", 8, "The URL contains a character that can be used to confuse recipients.")
    try:
        ipaddress.ip_address(host)
        add("ip_host", "Direct IP address", 24, "The destination uses an IP address rather than a named domain.")
    except ValueError:
        pass
    words = re.split(r"[.\-_]", host)
    for brand in BRANDS:
        named = brand in words or (len(brand) >= 4 and any(w.startswith(brand) for w in words)) or (len(brand) >= 5 and brand in host)
        if named and not official_host(host, brand):
            add("impersonation", "Possible brand impersonation", 44, f"The domain references {brand.upper()} but is not one of its listed official domains.")
            break
    if SCAM_TERMS.search(message[:4000]):
        add("social_pressure", "Sensitive or urgent message", 14, "The accompanying message uses common scam themes. Context is not proof of fraud.")
    return flags


def inspect_message(text: str) -> list[dict]:
    """Warning signs in the wording itself, for messages that carry no link or file to judge."""
    text = (text or "")[:6000]
    flags = []
    def add(code, label, weight, detail):
        flags.append({"code": code, "label": label, "weight": weight, "detail": detail, "source": "message_rules"})
    if SECRET_REQUEST.search(text):
        add("secret_request", "Asks you to share a secret code", 40, "The message asks for an OTP, PIN, CVV or password. No bank, courier or government office ever needs these from you.")
    if REMOTE_APP.search(text):
        add("remote_app", "Asks you to install an app", 30, "Screen-sharing and unknown apps let a stranger control your phone and read your OTPs.")
    if MONEY_REQUEST.search(text):
        add("money_request", "Asks for a payment", 16, "Small advance fees for prizes, parcels, jobs or refunds are a common fraud pattern.")
    if SCAM_TERMS.search(text):
        add("social_pressure", "Sensitive or urgent message", 14, "The message uses common scam themes. Wording alone is not proof of fraud.")
    return flags


def detect_tactics(text: str) -> list[str]:
    """Pressure tactics spotted by fixed word lists; used when Gemini is not available."""
    text = (text or "")[:6000]
    return [name for name, pattern in TACTICS.items() if pattern.search(text)]


def inspect_page(page: dict) -> list[dict]:
    flags = []
    def add(code, label, weight, detail):
        flags.append({"code":code, "label":label,"weight":weight,"detail":detail,"source":"sandbox"})
    if page.get("password_inputs", 0):
        add("password_form", "Password entry form found", 22, "The page requests a password; verify who operates the domain.")
    if page.get("payment_inputs", 0):
        add("payment_form", "Payment information requested", 23, "The page appears to request payment or card information.")
    if page.get("downloads", 0):
        add("download_attempt", "Automatic download attempted", 38, "A download was triggered during browser inspection; the file was not executed.")
    if page.get("generated_downloads", 0):
        add("smuggled_download", "Page built a file inside the browser", 55, "The page assembled a download with script instead of linking to a file, a trick for slipping malware past scanners. That file could not be inspected.")
    if page.get("redirects", 0) >= 3:
        add("redirects", "Several redirects", 12, "The browser navigated across multiple addresses.")
    if page.get("cross_domain_forms", 0):
        add("offsite_form", "Form submits to another domain", 28, "A form sends data to a different domain, which warrants investigation.")
    if page.get("blocked_requests", 0) >= 3:
        # Ordinary pages often call a few addresses that no longer resolve, so only a pattern counts, and only a little.
        add("blocked_navigation", "Tried to reach blocked addresses", 8, "Several requests went to private or unresolvable addresses and were blocked.")
    for f in behaviour.findings(page.get("behaviour") or {}):
        add(f["code"], f["label"], f["weight"], f["detail"])
    return flags


def inspect_files(files: list[dict]) -> list[dict]:
    """Turn the sandbox's static file findings into scored signals."""
    flags = []
    for item in files:
        for finding in item.get("findings") or []:
            flags.append({"code": str(finding.get("code", "file_finding"))[:40], "label": str(finding.get("label", "File finding"))[:120],
                          "weight": max(0, min(100, int(finding.get("weight", 0)))), "detail": str(finding.get("detail", ""))[:600],
                          "source": "file_scan"})
    return flags


def inspect_reputation(files: list[dict]) -> tuple[list[dict], list[str]]:
    """Score what antivirus engines already know about each file's fingerprint. Returns (signals, threats)."""
    flags, threats = [], []
    for item in files:
        rep = item.get("reputation") or {}
        bad = int(rep.get("malicious") or 0)
        if bad >= 3:
            threats.append("KNOWN_MALWARE")
            flags.append({"code": "known_malware", "label": "Known malware", "weight": 98, "source": "file_reputation",
                          "detail": f"{bad} of {rep.get('engines', 0)} antivirus engines on VirusTotal already identify this exact file as malicious."})
        elif bad or int(rep.get("suspicious") or 0) >= 2:
            flags.append({"code": "flagged_by_engines", "label": "Flagged by some antivirus engines", "weight": 35, "source": "file_reputation",
                          "detail": f"{bad} antivirus engine{'s' if bad != 1 else ''} on VirusTotal mark this exact file as malicious. A few flags can be false alarms, so treat it with care."})
    return flags, sorted(set(threats))


def inspect_embedded(files: list[dict]) -> list[dict]:
    """Score the links written inside a file by the verdict each one earned from the link checks."""
    flags = []
    for item in files:
        worst = max((link for link in item.get("embedded_links") or []), key=lambda link: link.get("score", 0), default=None)
        if not worst:
            continue
        if worst.get("level") in ("critical", "high"):
            flags.append({"code": "dangerous_link_inside", "label": "A link inside this file is dangerous", "weight": 70, "source": "embedded_link",
                          "detail": f"The file contains a link to {worst.get('domain', 'a website')} that the link checks rate as {worst['level']} risk. Do not tap links inside this file."})
        elif worst.get("level") == "caution":
            flags.append({"code": "risky_link_inside", "label": "A link inside this file shows warning signs", "weight": 30, "source": "embedded_link",
                          "detail": f"The file contains a link to {worst.get('domain', 'a website')} that shows warning signs."})
    return flags


def classify(flags: list[dict], threats: list[str], sandbox_status: str, webrisk_checked: bool) -> tuple[str, int]:
    if threats:
        return "critical", 98
    score = min(90, sum(int(f["weight"]) for f in flags))
    if score >= 65:
        return "high", score
    if score >= 30:
        return "caution", score
    if sandbox_status != "completed":
        return "unverified", score
    return "low", score
