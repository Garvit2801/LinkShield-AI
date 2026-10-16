"""Pirated movie, TV and music sites. Not phishing, but a real risk: they live on malvertising (fake download
buttons, pop-unders, scareware), hop between domains to dodge takedowns, and are illegal to use in India.

Two independent signs, either is enough:
- the domain carries the name of a well-known piracy brand, or
- the page itself reads like a piracy index: release tags, quality tags and "full movie download" wording
  together. One or two of these appear on ordinary film news and review pages, so several kinds are required.
"""
import re
from urllib.parse import urlsplit

# Name stems used by long-running piracy brands and their endless mirrors (9xflix.esq, 9xflix.fi, ...).
BRANDS = (
    "9xflix", "9xmovies", "9kmovies", "filmyzilla", "filmywap", "afilmywap", "filmy4wap", "filmyhit", "filmyfly", "filmymeet",
    "tamilrockers", "tamilblasters", "tamilyogi", "tamilmv", "isaimini", "moviesda", "kuttymovies", "movierulz", "ibomma",
    "khatrimaza", "worldfree4u", "bolly4u", "hdhub4u", "vegamovies", "katmoviehd", "mkvcinemas", "moviesflix", "extramovies",
    "skymovieshd", "mp4moviez", "jalshamoviez", "pagalmovies", "sdmoviespoint", "moviesmod", "moviesverse", "rdxhd", "7starhd",
    "pikahd", "okjatt", "123mkv", "123movies", "gomovies", "fmovies", "putlocker", "soap2day", "solarmovie", "primewire",
    "yesmovies", "lookmovie", "thepiratebay", "piratebay", "1337x", "limetorrents", "torrentgalaxy", "kickasstorrents",
    "yts", "yify", "rarbg", "mlwbd", "mkvmoviespoint", "downloadhub", "bollyflix", "dotmovies", "hdmovies4u", "uwatchfree",
)
SHORT = {b for b in BRANDS if len(b) <= 5}  # matched only as a whole name, never inside another word

MARKERS = {
    "quality": re.compile(r"\b(480p|720p|1080p|2160p|4k\s*hdr)\b", re.I),
    "release": re.compile(r"\b(hdrip|web-?dl|webrip|bluray|brrip|bdrip|dvdscr|camrip|hdcam|hdts|predvd|hdtc|s-?print|x264|x265|hevc)\b", re.I),
    "download": re.compile(r"(full\s+movie\s+(free\s+)?download|download\s+(full\s+)?(hd\s+)?movies?|movies?\s+download|free\s+download|"
                           r"watch\s+online\s+free|direct\s+download\s+links?|g-?drive\s+links?|torrent|magnet:)", re.I),
    "dubbed": re.compile(r"\b(dual\s+audio|hindi\s+dubbed|org\.?\s*audio|esubs?|multi\s+audio)\b", re.I),
    "size": re.compile(r"\b\d{3,4}\s?mb\b|\b\d(\.\d)?\s?gb\b", re.I),
}
# Real streaming and ticketing services talk about movies too; they are never treated as piracy.
OFFICIAL = ("netflix.com", "primevideo.com", "amazon.in", "amazon.com", "hotstar.com", "jiocinema.com", "zee5.com", "sonyliv.com",
            "mxplayer.in", "youtube.com", "erosnow.com", "sunnxt.com", "aha.video", "hoichoi.tv", "bookmyshow.com", "imdb.com",
            "apple.com", "spotify.com", "gaana.com", "jiosaavn.com", "wikipedia.org")


def _host(url: str) -> str:
    return (urlsplit(url or "").hostname or "").lower().removeprefix("www.")


def _official(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in OFFICIAL)


def brand_of(host: str) -> str | None:
    labels = host.split(".")[:-1] or [host]  # leave out the extension: 9xflix.esq -> ["9xflix"]
    for label in labels:
        for brand in BRANDS:
            if (label == brand or label.startswith(brand + "-") or re.fullmatch(rf"{brand}\d*", label)) if brand in SHORT else brand in label:
                return brand
    return None


def markers(text: str) -> list[str]:
    return [name for name, rx in MARKERS.items() if rx.search(text or "")]


def inspect(url: str, page: dict | None = None) -> list[dict]:
    """Signals for a link (and, when the sandbox saw it, its page)."""
    page = page or {}
    final = page.get("final_url") or url
    hosts = [_host(url), _host(final)]
    if any(_official(h) for h in hosts):
        return []
    brand = next(filter(None, (brand_of(h) for h in hosts)), None) or brand_of(re.sub(r"[^a-z0-9.]", "", (page.get("title") or "").lower().split(" ")[0]))
    found = markers(f"{page.get('title', '')}\n{page.get('page_text', '')}")
    if not brand and len(found) < 3:
        return []
    why = f"The site carries the name of {brand}, a well-known piracy brand" if brand else f"The page lists films the way piracy sites do ({', '.join(found[:3])} tags and download wording)"
    flags = [{"code": "piracy_site", "label": "Pirated movies and shows", "weight": 35, "source": "local_rules",
              "detail": f"{why}. These sites are illegal to use in India and make money from aggressive ads: fake download buttons, "
                        "pop-ups and pages that push malware, scam apps or fake virus warnings. Use an official streaming service instead."}]
    hopped = hosts[0] and hosts[1] and hosts[0] != hosts[1] and hosts[0].split(".")[0] == hosts[1].split(".")[0]
    many_hosts = int((page.get("behaviour") or {}).get("hosts") or 0) >= 25
    if hopped or many_hosts:
        flags.append({"code": "piracy_mirror", "label": "Hops between addresses and ad networks", "weight": 8, "source": "local_rules",
                      "detail": ("It moved from " + hosts[0] + " to " + hosts[1] + ", the way piracy sites dodge takedowns. " if hopped else "")
                                + (f"It loaded content from {page['behaviour']['hosts']} different websites, mostly ad networks." if many_hosts else "")})
    return flags
