"""Static file inspection for the sandbox worker.

SECURITY CONTRACT: files are only ever read as bytes. Nothing here opens, renders, extracts to disk
or runs a file. This is structural triage (real type, disguises, macros, scripts, hidden payloads).
It is NOT an antivirus: there is no malware signature database and no behavioural detonation.
"""
import hashlib
import io
import re
import zipfile
import zlib

# id -> (plain-language label, kind)
TYPES = {
    "pe": ("Windows program", "program"), "elf": ("Linux program", "program"), "macho": ("macOS program", "program"),
    "javaclass": ("Java program", "program"), "dex": ("Android program code", "program"), "shell": ("Script", "program"),
    "code": ("Source code", "code"),
    "lnk": ("Windows shortcut", "program"), "apk": ("Android app (APK)", "program"), "jar": ("Java app (JAR)", "program"),
    "msi": ("Windows installer", "program"), "chm": ("Windows help file", "program"),
    "pdf": ("PDF document", "document"), "ooxml": ("Office document", "document"), "ole": ("Older Office document", "document"),
    "odf": ("OpenDocument file", "document"), "rtf": ("Rich Text document", "document"), "onenote": ("OneNote notebook", "document"),
    "jpeg": ("JPEG image", "image"), "png": ("PNG image", "image"), "gif": ("GIF image", "image"), "webp": ("WebP image", "image"),
    "bmp": ("BMP image", "image"), "tiff": ("TIFF image", "image"), "ico": ("Icon image", "image"), "heif": ("HEIC/AVIF image", "image"),
    "svg": ("SVG image", "image"),
    "mp4": ("MP4/MOV video", "video"), "mkv": ("MKV/WebM video", "video"), "avi": ("AVI video", "video"), "asf": ("Windows Media file", "video"),
    "flv": ("Flash video", "video"), "mpeg": ("MPEG video", "video"),
    "mp3": ("MP3 audio", "audio"), "wav": ("WAV audio", "audio"), "flac": ("FLAC audio", "audio"), "ogg": ("Ogg media", "audio"),
    "m4a": ("M4A audio", "audio"), "aac": ("AAC audio", "audio"),
    "zip": ("ZIP archive", "archive"), "rar": ("RAR archive", "archive"), "7z": ("7-Zip archive", "archive"), "gzip": ("Gzip archive", "archive"),
    "bzip2": ("Bzip2 archive", "archive"), "xz": ("XZ archive", "archive"), "cab": ("Cabinet archive", "archive"), "iso": ("Disk image", "archive"),
    "html": ("Web page (HTML)", "web"), "xml": ("XML text", "text"), "text": ("Plain text", "text"),
    "unknown": ("Unrecognised data", "unknown"), "empty": ("Empty file", "unknown"),
}

_EXT_GROUPS = {
    "image": "jpg jpeg jpe jfif png gif webp bmp tif tiff ico heic heif avif svg",
    "video": "mp4 m4v mov 3gp mkv webm avi wmv asf flv mpg mpeg ts ogv",
    "audio": "mp3 wav flac ogg oga opus m4a aac wma amr",
    "document": "pdf doc docx docm dot dotx dotm xls xlsx xlsm xlsb xlt xltx xltm ppt pptx pptm pps ppsx ppsm pot potx rtf odt ods odp one",
    "archive": "zip rar 7z gz tgz bz2 xz tar cab iso img vhd vhdx",
    "text": "txt csv log md json xml yml yaml",
    "web": "html htm xhtml mht mhtml shtml",
    # Source code is plain text: nothing happens unless someone deliberately runs it.
    "code": "py pyw ipynb rb pl pm php sh bash zsh fish go java kt kts c h cpp cc hpp cs rs swift lua dart scala r sql jsx tsx mjs cjs",
}
# Files that run as soon as they are double-clicked.
SCRIPT_EXT = set("bat cmd ps1 psm1 vbs vbe js jse wsf wsh hta scr pif com lnk reg cpl scf command chm url desktop".split())
MOBILE_EXT = set("apk apks xapk aab ipa".split())
INSTALLER_EXT = set("exe msi msp dll sys dmg pkg deb rpm appimage jar app run".split())
DISK_EXT = set("iso img vhd vhdx".split())
PROGRAM_EXT = SCRIPT_EXT | MOBILE_EXT | INSTALLER_EXT
EXT_KIND = {ext: kind for kind, exts in _EXT_GROUPS.items() for ext in exts.split()}
EXT_KIND.update({ext: "program" for ext in PROGRAM_EXT})
# Endings used as bait in names like "invoice.pdf.exe". Libraries (.dll) are excluded: nobody double-clicks them.
LURE_EXT = set(" ".join(_EXT_GROUPS[k] for k in ("image", "video", "audio", "document")).split()) | {"txt", "zip", "rar"}
MACRO_EXT = set("docm dotm xlsm xltm xlsb pptm ppsm".split())
OPAQUE_ARCHIVES = {"rar", "7z", "gzip", "bzip2", "xz", "cab"}

# Windows script-host and screensaver files: almost never sent for an honest reason, unlike a .bat or .ps1 a colleague might share.
LURE_SCRIPT_EXT = set("vbs vbe jse wsf wsh hta scr pif cpl scf".split())
PROGRAM_ADVICE = {
    "mobile": (70, "This is an app installer. Apps sent through chats or links skip the official store's checks and are a common "
                   "way to steal banking OTPs. Install apps only from the official app store."),
    "script": (45, "This kind of file runs commands as soon as it is double-clicked. Open it only if you were expecting it from someone you trust."),
    "installer": (50, "This is a program, not a document or picture. Programs can take full control of a device. Only run software "
                      "you went looking for yourself, from the maker's official website."),
}
TYPE_FAMILY = {"apk": "mobile", "dex": "mobile", "shell": "script", "lnk": "script", "chm": "script"}

_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069\u200e\u200f]")
_DOS_STUB = b"This program cannot be run in DOS mode"
_EICAR = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
_SCRIPT_MARKS = re.compile(rb"<\?php|<script|powershell|cmd\.exe|WScript\.Shell", re.I)
_MEDIA_KINDS = {"video", "audio"}
_WEB_ADDRESS = re.compile(rb"https?://[A-Za-z0-9.\-]{4,120}(?:/[\x21\x23-\x3b\x3d\x3f-\x7e]{0,300})?")


def clean_name(raw: str) -> tuple[str, bool]:
    """Return a displayable base name and whether it carried text-direction control characters."""
    raw = (raw or "").replace("\\", "/").split("/")[-1]
    hidden = bool(_BIDI.search(raw))
    name = "".join(ch for ch in _BIDI.sub("", raw) if ch.isprintable()).strip()[:120]
    return name, hidden


def extension(name: str) -> str:
    return name.rsplit(".", 1)[-1].strip().lower() if "." in name else ""


def double_extension(name: str) -> bool:
    parts = name.lower().split(".")
    padded = re.search(r"\s{3,}\.\w+$", name) is not None
    return (len(parts) >= 3 and parts[-1] in PROGRAM_EXT - {"dll", "sys"} and parts[-2].strip() in LURE_EXT) or padded


def sniff(data: bytes) -> str:
    """Identify a file from its leading bytes, never from its name."""
    if not data:
        return "empty"
    h = data[:16]
    if h.startswith(b"MZ"): return "pe"
    if h.startswith(b"\x7fELF"): return "elf"
    if h[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"): return "macho"
    if h[:4] == b"\xca\xfe\xba\xbe":  # shared by macOS universal binaries and Java classes
        return "macho" if int.from_bytes(data[4:8], "big") < 20 else "javaclass"
    if h.startswith(b"dex\n"): return "dex"
    if h.startswith(b"#!"): return "shell"
    if h.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"): return "lnk"
    if h.startswith(b"ITSF"): return "chm"
    if b"%PDF-" in data[:1024]: return "pdf"
    if h[:4] in (b"PK\x03\x04", b"PK\x05\x06"): return "zip"
    if h.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"): return "ole"
    if h.startswith(b"{\\rt"): return "rtf"
    if h.startswith(b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d"): return "onenote"
    if h.startswith(b"\xff\xd8\xff"): return "jpeg"
    if h.startswith(b"\x89PNG\r\n\x1a\n"): return "png"
    if h[:6] in (b"GIF87a", b"GIF89a"): return "gif"
    if h[:4] == b"RIFF":
        return {b"WEBP": "webp", b"AVI ": "avi", b"WAVE": "wav"}.get(data[8:12], "unknown")
    if h[:2] == b"BM" and data[6:10] == b"\x00\x00\x00\x00": return "bmp"
    if h[:4] in (b"II*\x00", b"MM\x00*"): return "tiff"
    if h[:4] == b"\x00\x00\x01\x00": return "ico"
    if data[4:8] == b"ftyp":
        brand = data[8:12]
        if brand in (b"heic", b"heix", b"hevc", b"mif1", b"msf1", b"avif", b"avis"): return "heif"
        return "m4a" if brand.startswith(b"M4A") else "mp4"
    if h[:4] == b"\x1a\x45\xdf\xa3": return "mkv"
    if h[:8] == b"\x30\x26\xb2\x75\x8e\x66\xcf\x11": return "asf"
    if h[:4] == b"FLV\x01": return "flv"
    if h[:4] in (b"\x00\x00\x01\xba", b"\x00\x00\x01\xb3"): return "mpeg"
    if len(data) > 188 and data[0] == 0x47 and data[188] == 0x47: return "mpeg"
    if h[:4] == b"OggS": return "ogg"
    if h[:4] == b"fLaC": return "flac"
    if h[:3] == b"ID3" or (h[0] == 0xFF and h[1] in (0xFB, 0xFA, 0xF3, 0xF2, 0xE3)): return "mp3"
    if h[0] == 0xFF and h[1] in (0xF1, 0xF9): return "aac"
    if h.startswith(b"Rar!\x1a\x07"): return "rar"
    if h.startswith(b"7z\xbc\xaf\x27\x1c"): return "7z"
    if h[:2] == b"\x1f\x8b": return "gzip"
    if h[:3] == b"BZh": return "bzip2"
    if h.startswith(b"\xfd7zXZ\x00"): return "xz"
    if h[:4] == b"MSCF": return "cab"
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001": return "iso"
    return _sniff_text(data[:4096])


def _sniff_text(sample: bytes) -> str:
    if sample[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            sample = sample.decode("utf-16").encode("utf-8")
        except UnicodeError:
            return "unknown"
    low = sample.lstrip(b"\xef\xbb\xbf\r\n\t ").lower()
    if b"\x00" in low:
        return "unknown"
    if b"<svg" in low[:2048]:
        return "svg"
    if low.startswith((b"<!doctype html", b"<html")) or re.search(rb"<(html|head|body|script|form|iframe)[\s>]", low):
        return "html"
    if low.startswith(b"<?xml"):
        return "xml"
    control = sum(1 for b in low if b < 9 or 13 < b < 32)
    return "text" if control * 20 <= max(1, len(low)) else "unknown"


class _Scan:
    def __init__(self, data: bytes, truncated: bool):
        self.data, self.truncated = data, truncated
        self.findings, self.checks, self.notes, self.links = [], [], [], []
        self.complete = not truncated

    def link(self, raw):
        """Remember a web address written inside the file so the link checks can follow it."""
        url = (raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw).strip().replace("&amp;", "&").rstrip(".,;:!?)]}'\"")
        if re.match(r"https?://[^\s/]+\.[^\s/]", url, re.I) and len(url) <= 600 and url not in self.links and len(self.links) < 40:
            self.links.append(url)

    def flag(self, code, label, weight, detail):
        self.findings.append({"code": code, "label": label, "weight": weight, "detail": detail})

    def check(self, label, ok):
        self.checks.append({"label": label, "ok": bool(ok)})

    def test(self, bad, code, label, weight, detail, ok_label):
        """Record a check either way so the report can show what was looked for."""
        if bad:
            self.flag(code, label, weight, detail)
        self.check(label if bad else ok_label, not bad)
        return bool(bad)

    def note(self, text):
        self.notes.append(text)

    def unreadable(self, why):
        self.complete = False
        self.note(why)


def _embedded_program(scan: _Scan, what: str):
    scan.test(_DOS_STUB in scan.data, "embedded_program", "A program is hidden inside this file", 80,
              f"The {what} carries a Windows program inside it. Real {what}s do not need one; this is how malware is smuggled.",
              "No program hidden inside")


def _trailer(scan: _Scan, end: int | None, what: str):
    """Look at bytes after the point where the image officially ends."""
    if scan.truncated or end is None:
        return
    tail = scan.data[end:].strip(b"\x00\r\n\t ")
    if len(tail) < 32:
        scan.check("Nothing attached after the end of the image", True)
        return
    inner = sniff(tail)
    kind = TYPES[inner][1]
    if kind == "program":
        scan.flag("hidden_payload", "A program is attached to the end of this image", 80,
                  f"After the {what} ends, the file continues with a {TYPES[inner][0].lower()}. This is a known way to hide malware in a picture.")
    elif kind == "archive":
        scan.flag("hidden_archive", "An archive is attached to the end of this image", 45,
                  f"After the {what} ends, the file continues with a {TYPES[inner][0].lower()}. Its contents are hidden from a normal image viewer.")
    elif _SCRIPT_MARKS.search(tail[:200_000]):
        scan.flag("hidden_script", "Script code is attached to the end of this image", 45,
                  "Text that looks like program code follows the image data.")
    else:
        if len(tail) > 16_384 and kind not in ("image", "video"):
            scan.note(f"About {len(tail) // 1024} KB of extra data follows the image. Cameras sometimes add this; it was not recognised as a threat.")
        scan.check("Nothing dangerous attached after the end of the image", True)
        return
    scan.check("Something is attached after the end of the image", False)


def _png_end(data: bytes) -> int | None:
    pos = 8
    while pos + 12 <= len(data):
        length = int.from_bytes(data[pos:pos + 4], "big")
        ctype = data[pos + 4:pos + 8]
        pos += 12 + length
        if ctype == b"IEND":
            return pos
    return None


def _image(scan: _Scan, kind_id: str):
    data = scan.data
    _embedded_program(scan, "image")
    if kind_id == "jpeg":
        last = data.rfind(b"\xff\xd9")
        _trailer(scan, last + 2 if last > 0 else None, "JPEG")
    elif kind_id == "png":
        _trailer(scan, _png_end(data), "PNG")
    elif kind_id == "webp":
        size = 8 + int.from_bytes(data[4:8], "little")
        _trailer(scan, size + (size & 1), "WebP image")
    scan.test(re.search(rb"<\?php|<script[\s>]", data[:2_000_000], re.I), "embedded_script", "Script code inside an image", 35,
              "The image contains text that looks like program code. Pictures have no use for it.", "No script code inside")


def _svg(scan: _Scan):
    text = scan.data[:2_000_000]
    reasons = []
    if re.search(rb"<script[\s>]", text, re.I): reasons.append("a script")
    if re.search(rb"\son[a-z]+\s*=", text, re.I): reasons.append("actions that run on load or click")
    if re.search(rb"javascript\s*:", text, re.I): reasons.append("a javascript: link")
    if re.search(rb"<(foreignObject|iframe|embed)[\s>]", text, re.I): reasons.append("an embedded web page")
    scan.test(reasons, "svg_active", "This image can run code", 55,
              "SVG pictures are text files that browsers execute. This one contains " + ", ".join(reasons) + ", which can redirect you or show a fake login.",
              "No scripts or embedded pages")


def _media(scan: _Scan, kind_id: str):
    _embedded_program(scan, "media file")
    if kind_id == "asf":
        marker = b"URLANDEXIT"
        scan.test(marker in scan.data or marker.decode().encode("utf-16-le") in scan.data, "media_script", "Video contains a web command", 50,
                  "This Windows Media file tells the player to open a web address, an old trick for pushing fake codec downloads.",
                  "No commands that open websites")


def _pdf_structure(data: bytes) -> bytes:
    """PDF text outside binary streams, plus the contents of compressed object streams."""
    parts, pos, inflated, objstreams = [], 0, 0, 0
    for m in re.finditer(rb"stream\r?\n", data):
        if m.start() < pos:
            continue
        end = data.find(b"endstream", m.end())
        if end < 0:
            end = len(data)
        parts.append(data[pos:m.start()])
        if b"/ObjStm" in data[max(pos, m.start() - 512):m.start()] and objstreams < 400 and inflated < 24_000_000:
            objstreams += 1
            try:
                out = zlib.decompressobj().decompress(data[m.end():end], 4_000_000)
                inflated += len(out)
                parts.append(out)
            except zlib.error:
                pass
        pos = end + 9
    parts.append(data[pos:])
    # Names may be written with #xx escapes to dodge scanners (/J#61vaScript).
    return re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), b"\n".join(parts))


def _pdf(scan: _Scan):
    body = _pdf_structure(scan.data)
    has = lambda name: re.search(rb"/(?:" + name + rb")(?![A-Za-z0-9])", body) is not None
    auto = has(rb"OpenAction|AA")
    scan.test(has(rb"JavaScript|JS"), "pdf_script", "PDF contains a script", 60 if auto else 45,
              "This PDF carries JavaScript" + (" that is set to run by itself when the file opens" if auto else "") +
              ". Ordinary letters, bills and tickets do not need it.", "No scripts (JavaScript)")
    scan.test(has(rb"Launch"), "pdf_launch", "PDF tries to start another program", 65,
              "The file contains a command that launches a program or file outside the PDF reader.", "No commands that start other programs")
    scan.test(has(rb"EmbeddedFiles?"), "pdf_attachment", "Another file is packed inside this PDF", 30,
              "A second file is embedded in the PDF and was not inspected. Do not open attachments from inside it.", "No files packed inside")
    scan.test(has(rb"SubmitForm"), "pdf_submit", "PDF form sends data to a website", 20,
              "Whatever you type into this PDF can be sent to a web address.", "No forms that send data away")
    if has(rb"Encrypt"):
        scan.flag("pdf_locked", "Password-protected PDF", 10, "Protected PDFs hide part of their contents from scanners, so this one could only be partly checked.")
        scan.unreadable("The PDF is password-protected, so its inner contents could not be read.")
    for found in re.findall(rb"/URI\s*\(((?:[^()\\]|\\.){4,600})\)", body):
        scan.link(re.sub(rb"\\(.)", rb"\1", found))
    for found in re.findall(rb"/URI\s*<([0-9A-Fa-f\s]{8,1200})>", body):
        try:
            scan.link(bytes.fromhex(found.decode().translate({32: None, 10: None, 13: None, 9: None})))
        except ValueError:
            pass
    links = len(scan.links) or len(re.findall(rb"/URI\s*[(<]", body))
    if links:
        scan.note(f"Contains {links} web link{'s' if links != 1 else ''}. Check where a link goes before tapping it.")
    _embedded_program(scan, "PDF")


def _read_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    with zf.open(info) as fh:
        return fh.read(limit)


def _office(scan: _Scan, zf: zipfile.ZipFile, infos: list, ext: str):
    names = [i.filename for i in infos]
    low = [n.lower() for n in names]
    macros = any(n.endswith("vbaproject.bin") or "/macrosheets/" in n for n in low)
    scan.test(macros, "office_macro", "Document contains macros", 55,
              "Macros are small programs inside a document. If you press 'Enable content' they run with your permissions. "
              "This is the most common way documents deliver malware.", "No macros")
    remote = []
    for info in [i for i in infos if i.filename.lower().endswith(".rels")][:80]:
        xml = _read_member(zf, info, 1_000_000)
        for rel in re.findall(rb"<Relationship\b[^>]*>", xml):
            if b'TargetMode="External"' not in rel:
                continue
            kind = re.search(rb'Type="[^"]*/([A-Za-z]+)"', rel)
            target = re.search(rb'Target="([^"]{4,600})"', rel)
            if kind and target and kind.group(1) == b"hyperlink":
                scan.link(target.group(1))
            if kind and kind.group(1) in (b"attachedTemplate", b"oleObject", b"frame", b"subDocument"):
                remote.append(kind.group(1).decode())
    scan.test(remote, "office_remote", "Document loads content from the internet", 60,
              "When opened, this document fetches a template or object from a remote address. Attackers use this to pull in "
              "malicious code that is not in the file itself.", "No remote templates or linked objects")
    packaged = any(("/embeddings/" in n and n.endswith(".bin")) or "/activex/" in n for n in low)
    scan.test(packaged, "office_object", "Document has an embedded object", 30,
              "An embedded object or control is packed inside. Double-clicking such objects can run them.", "No embedded objects or controls")
    dde = False
    for info in infos:
        if info.filename.lower() in ("word/document.xml", "xl/workbook.xml") and not dde:
            dde = re.search(rb"<w:instrText[^>]*>[^<]*DDE|ddeService=", _read_member(zf, info, 8_000_000)) is not None
    scan.test(dde, "office_dde", "Document uses a command link (DDE)", 45,
              "The document contains a field that can start another program when you accept a prompt.", "No command links (DDE)")
    if ext and ext not in MACRO_EXT and macros:
        scan.note("The file name does not use a macro extension, yet macros are present.")


def _archive(scan: _Scan, zf: zipfile.ZipFile, infos: list):
    files = [i for i in infos if not i.is_dir()]
    programs, disguised, doubles, nested, locked, sniffed = [], [], [], 0, 0, 0
    for info in files:
        name, _ = clean_name(info.filename)
        ext = extension(name)
        if info.flag_bits & 1:
            locked += 1
        if ext in PROGRAM_EXT:
            programs.append(name)
            if double_extension(name):
                doubles.append(name)
        if EXT_KIND.get(ext) == "archive":
            nested += 1
        if not info.flag_bits & 1 and sniffed < 60 and EXT_KIND.get(ext) in ("image", "video", "audio", "document", "text"):
            sniffed += 1
            try:
                if TYPES[sniff(_read_member(zf, info, 4096))][1] == "program":
                    disguised.append(name)
            except Exception:
                scan.unreadable("Some files inside the archive could not be read.")
    scan.note(f"Contains {len(files)} file{'s' if len(files) != 1 else ''}" + (": " + ", ".join(clean_name(i.filename)[0] for i in files[:5]) + ("…" if len(files) > 5 else "") if files else "") + ".")
    scan.test(programs, "archive_program", "Archive contains a program", 65 if any(extension(p) in SCRIPT_EXT | MOBILE_EXT for p in programs) else 55,
              "Inside the archive: " + ", ".join(programs[:4]) + ". Zipping a program is a common way to get it past filters.", "No programs inside")
    scan.test(disguised or doubles, "archive_disguised", "A file inside is disguised", 90 if disguised else 60,
              "These files pretend to be something else: " + ", ".join((disguised + doubles)[:4]) + ".", "Files inside are what their names say")
    if scan.test(locked, "archive_locked", "Password-protected archive", 35,
                 "The contents are locked, so they could not be inspected. Scammers send the password in the message precisely so scanners cannot look inside.",
                 "Not password-locked"):
        scan.complete = False
    if nested:
        scan.unreadable(f"Contains {nested} archive{'s' if nested != 1 else ''} inside the archive that {'were' if nested != 1 else 'was'} not opened.")
    packed = sum(i.compress_size for i in files)
    total = sum(i.file_size for i in files)
    scan.test(total > 1_000_000_000 and total > 100 * max(1, packed), "archive_bomb", "Archive expands to an enormous size", 40,
              "The archive unpacks to more than a gigabyte from a tiny file, a trick used to crash scanners and devices.", "Unpacked size is reasonable")


def _zip(scan: _Scan, ext: str) -> str:
    try:
        zf = zipfile.ZipFile(io.BytesIO(scan.data))
        infos = zf.infolist()[:5000]
    except (zipfile.BadZipFile, ValueError, OSError, NotImplementedError):
        scan.unreadable("The archive is damaged or incomplete, so its contents could not be listed.")
        return "zip"
    names = {i.filename for i in infos}
    with zf:
        if "AndroidManifest.xml" in names:
            return "apk"
        if "[Content_Types].xml" in names and any(n.startswith(("word/", "xl/", "ppt/")) for n in names):
            _office(scan, zf, infos, ext)
            return "ooxml"
        if "META-INF/MANIFEST.MF" in names and any(n.endswith(".class") for n in names):
            return "jar"
        if "mimetype" in names and any(n == "content.xml" for n in names):
            scan.test(any(n.startswith("Basic/") or n.startswith("Scripts/") for n in names), "office_macro", "Document contains macros", 55,
                      "Macros are small programs inside a document that run if you allow them.", "No macros")
            return "odf"
        _archive(scan, zf, infos)
    return "zip"


def _ole(scan: _Scan, ext: str) -> str:
    data = scan.data
    wide = lambda s: s.encode("utf-16-le")
    if ext in ("msi", "msp") or (wide("SummaryInformation") in data and not any(wide(x) in data for x in ("WordDocument", "Workbook", "Book", "PowerPoint Document"))
                                and _DOS_STUB in data):
        return "msi"
    scan.test(wide("_VBA_PROJECT") in data, "office_macro", "Document contains macros", 55,
              "Macros are small programs inside a document. If you press 'Enable content' they run with your permissions. "
              "This is the most common way documents deliver malware.", "No macros")
    scan.test(wide("\x01Ole10Native") in data, "office_object", "Document has an embedded object", 30,
              "A packaged file is embedded in the document. Double-clicking it can run it.", "No embedded objects")
    if wide("EncryptedPackage") in data:
        scan.flag("office_locked", "Password-protected document", 25,
                  "The contents are locked, so they could not be inspected. Sending the password alongside the file is a known way to dodge scanners.")
        scan.unreadable("The document is password-protected, so its contents could not be read.")
    _embedded_program(scan, "document")
    for found in _WEB_ADDRESS.findall(data[:6_000_000])[:200]:
        scan.link(found)
    return "ole"


def _rtf(scan: _Scan):
    body = scan.data
    auto = b"\\objupdate" in body
    scan.test(re.search(rb"\\obj(data|emb|ocx|autlink|link)\b", body), "rtf_object", "Document has an embedded object", 65 if auto else 50,
              "This Rich Text file carries an embedded object" + (" that updates itself when the file opens" if auto else "") +
              ". Such objects are a frequent way to exploit document readers.", "No embedded objects")
    for found in re.findall(rb'HYPERLINK\s+"([^"]{4,600})"', body[:6_000_000]):
        scan.link(found)
    _embedded_program(scan, "document")


def _html(scan: _Scan, named_as_web: bool):
    text = scan.data[:3_000_000]
    for found in re.findall(rb'(?:href|action)\s*=\s*["\']?(https?://[^"\'\s>]{4,600})', text, re.I):
        scan.link(found)
    if named_as_web:
        scan.flag("html_file", "A web page sent as a file", 35,
                  "Opening this file shows a page stored on your own device, so the address bar gives no warning. Scammers use this for fake login screens.")
    scan.test(re.search(rb'type\s*=\s*["\']?password', text, re.I), "html_password", "The page asks for a password", 25,
              "The file contains a password box. A real company would send you to its website, not a file.", "Does not ask for a password")
    scrambled = re.search(rb"\b(atob|unescape|eval)\s*\(|fromCharCode|msSaveOrOpenBlob|createObjectURL", text) or re.search(rb"[A-Za-z0-9+/]{3000,}", text)
    scan.test(scrambled, "html_scrambled", "The page hides or builds content with script", 35,
              "Scrambled script inside the file can assemble a download or a fake page after it opens, hiding it from scanners.", "No scrambled script")


CODE_LANG = {"py": "Python", "pyw": "Python", "ipynb": "Python notebook", "rb": "Ruby", "pl": "Perl", "pm": "Perl", "php": "PHP",
             "sh": "shell", "bash": "shell", "zsh": "shell", "fish": "shell", "go": "Go", "java": "Java", "kt": "Kotlin", "kts": "Kotlin",
             "c": "C", "h": "C", "cpp": "C++", "cc": "C++", "hpp": "C++", "cs": "C#", "rs": "Rust", "swift": "Swift", "lua": "Lua",
             "dart": "Dart", "scala": "Scala", "r": "R", "sql": "SQL", "jsx": "JavaScript", "tsx": "TypeScript", "mjs": "JavaScript", "cjs": "JavaScript"}
_FETCH = re.compile(rb"\bcurl\s|\bwget\s|urlopen|urlretrieve|requests\.get|httpx\.get|Invoke-WebRequest|\biwr\s|DownloadString|DownloadFile|"
                    rb"Net\.WebClient|bitsadmin|certutil\s+-urlcache", re.I)
# Running what was just fetched: piping into a shell, exec/eval of it, or launching the saved file. Plain subprocess calls are normal.
_RUN = re.compile(rb"\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\|\s*python|\bexec\s*\(|\beval\s*\(|chmod\s+\+x|Start-Process|\biex\b|"
                  rb"Invoke-Expression|ShellExecute|os\.startfile", re.I)
_UNPACK = re.compile(rb"b64decode|base64|decompress|marshal\.loads|codecs\.decode|fromCharCode|FromBase64String", re.I)
_EXEC = re.compile(rb"\bexec\s*\(|\beval\s*\(|\biex\b|Invoke-Expression|Function\s*\(", re.I)
CODE_BEHAVIOURS = [
    ("code_remote_shell", "Gives someone remote control of the computer", 70,
     "The code connects out and hands a command line to whoever is on the other end. That is how attackers take over machines.",
     "No remote-control connection", re.compile(rb"/dev/tcp/|\bnc(?:at)?\s+[^\n]*-e\s|pty\.spawn|os\.dup2\s*\(", re.I)),
    ("code_steals", "Reads saved passwords, cookies or crypto wallets", 65,
     "It looks for the files where browsers and wallets keep logins. Ordinary programs never need them.",
     "Does not read saved passwords or wallets",
     re.compile(rb"Login Data|logins\.json|key4\.db|wallet\.dat|Local Storage[\\/]+leveldb|Telegram Desktop.{0,20}tdata|\.ssh[\\/]+id_rsa|Keychains", re.I)),
    ("code_keylogger", "Records what you type", 40, "It listens to the keyboard in the background, the way a keylogger does.",
     None, re.compile(rb"pynput\.keyboard|keyboard\.on_press|GetAsyncKeyState|SetWindowsHookEx", re.I)),
    ("code_security_off", "Switches off security protection", 45, "It tries to disable antivirus or the firewall.", None,
     re.compile(rb"DisableRealtimeMonitoring|Add-MpPreference\s+-ExclusionPath|setenforce\s+0|ufw\s+disable|advfirewall\s+set\s+\w+\s+state\s+off", re.I)),
    ("code_wipe", "Deletes files or backups on a large scale", 45, "It contains commands that wipe the disk, the home folder or system backups.", None,
     re.compile(rb"rm\s+-rf\s+(?:/|~|\$HOME)(?:\s|$|\*)|format\s+c:|vssadmin\s+delete\s+shadows|wbadmin\s+delete|cipher\s+/w", re.I)),
    ("code_persist", "Sets itself to start automatically", 25, "It adds itself to the computer's start-up list so it keeps running.", None,
     re.compile(rb"crontab\s|/etc/rc\.local|LaunchAgents|CurrentVersion\\+Run|schtasks\s+/create|systemctl\s+enable", re.I)),
]


def _near(text: bytes, first: re.Pattern, second: re.Pattern, span: int = 400) -> bool:
    return any(second.search(text, max(0, m.start() - span), m.end() + span) for m in first.finditer(text))


def _code_behaviour(scan: _Scan, text: bytes):
    """Judge code by what it does, not by being code. Sending email or calling an API is normal."""
    scan.test(_near(text, _FETCH, _RUN, 160), "code_download_run", "Downloads something and runs it", 45,
              "It fetches code or a program from the internet and runs it straight away, so what it really does is decided later, elsewhere.",
              "No download-and-run")
    hidden = re.search(rb"-e(?:nc|ncodedcommand)\s+[A-Za-z0-9+/=]{40,}", text, re.I) or _near(text, _EXEC, _UNPACK, 200) or \
        re.search(rb"[A-Za-z0-9+/]{2000,}={0,2}", text)
    scan.test(hidden, "code_hidden", "Hides part of its code", 45,
              "Part of the code is scrambled and unpacked only when it runs, which hides what it does from readers and scanners.",
              "No hidden code")
    for code, label, weight, detail, ok_label, pattern in CODE_BEHAVIOURS:
        if ok_label:
            scan.test(pattern.search(text), code, label, weight, detail, ok_label)
        elif pattern.search(text):
            scan.flag(code, label, weight, detail)


def _program(scan: _Scan, kind_id: str, ext: str):
    family = "mobile" if ext in MOBILE_EXT else "script" if ext in SCRIPT_EXT else "installer" if ext in INSTALLER_EXT else TYPE_FAMILY.get(kind_id, "installer")
    weight, detail = PROGRAM_ADVICE[family]
    if ext in LURE_SCRIPT_EXT or kind_id in ("lnk", "chm"):
        weight, detail = 70, "This kind of file runs commands as soon as it is opened. There is almost never a good reason to receive one in a message."
    label = {"mobile": "This is an app installer", "script": "This file runs commands when opened", "installer": "This is a program or installer"}[family]
    scan.flag("program_file", label, weight, detail)


def _mime_kind(declared: str) -> str | None:
    declared = (declared or "").split(";")[0].strip().lower()
    for prefix in ("image", "video", "audio"):
        if declared.startswith(prefix + "/"):
            return prefix
    if declared == "application/pdf" or any(x in declared for x in ("msword", "officedocument", "ms-excel", "ms-powerpoint", "opendocument", "rtf")):
        return "document"
    return None


def analyze(data: bytes, name: str = "", declared_type: str = "", truncated: bool = False, total_size: int | None = None) -> dict:
    """Describe a file without opening it. Never raises on hostile input."""
    name, bidi = clean_name(name)
    ext = extension(name)
    scan = _Scan(data, truncated)
    kind_id = sniff(data)
    try:
        if kind_id == "zip":
            kind_id = _zip(scan, ext)
        elif kind_id == "ole":
            kind_id = _ole(scan, ext)
        elif kind_id == "pdf":
            _pdf(scan)
        elif kind_id == "rtf":
            _rtf(scan)
        elif kind_id == "svg":
            _svg(scan)
        elif TYPES[kind_id][1] == "image":
            _image(scan, kind_id)
        elif TYPES[kind_id][1] in _MEDIA_KINDS:
            _media(scan, kind_id)
        elif kind_id == "html":
            _html(scan, EXT_KIND.get(ext) in ("web", None))
    except Exception:
        scan.unreadable("Part of the file's structure could not be read.")
    # A text file that is code (by its name or a "#!" first line) is read as code, not as a program.
    if kind_id in ("shell", "text") and _sniff_text(data[2:4096] if kind_id == "shell" else data[:4096]) == "text" and \
            (kind_id == "shell" or EXT_KIND.get(ext) == "code") and ext not in SCRIPT_EXT:
        kind_id = "code"
    label, kind = TYPES[kind_id]
    if kind_id == "code":
        first = data[:120].split(b"\n")[0].lower()
        lang = CODE_LANG.get(ext) or next((n for k, n in (("python", "Python"), ("node", "JavaScript"), ("ruby", "Ruby"), ("perl", "Perl"),
                                                          ("php", "PHP"), ("sh", "shell")) if k.encode() in first), "")
        label = f"{lang} source code" if lang else "Source code"
    elif ext in SCRIPT_EXT and kind == "text":
        label = f"Script that runs when opened (.{ext})"
    claimed = EXT_KIND.get(ext) or _mime_kind(declared_type)
    # A batch file or script is text inside, which is exactly what its name promises.
    same_family = claimed == kind or {claimed, kind} <= _MEDIA_KINDS or (claimed == "program" and ext in SCRIPT_EXT and kind in ("text", "code"))
    is_program = kind == "program" or ext in PROGRAM_EXT

    if _EICAR in data[:4096]:
        scan.flag("eicar_test", "Antivirus test signature (EICAR)", 98,
                  "This is the standard harmless test file that every security tool is expected to block. Seeing it flagged shows detection is working.")
    if kind == "program" and claimed not in (None, "program"):
        scan.flag("disguised_program", "A program disguised as a harmless file", 95,
                  f"The name suggests {'an' if claimed[0] in 'aei' else 'a'} {claimed} file, but the content is really a {label.lower()}. "
                  "Dressing a program up as a picture, video or document is a classic malware trick.")
    elif is_program:
        _program(scan, kind_id, ext)
    if kind_id == "code" or (ext in SCRIPT_EXT and kind in ("text", "program", "code") and kind_id not in ("pe", "elf", "macho", "lnk", "chm")):
        _code_behaviour(scan, data[:3_000_000])
    if kind_id == "code" and claimed in (None, "code", "text"):
        scan.note("This is code. Nothing happens unless someone runs it, so run it only if you know what it does.")
    elif claimed and not same_family and kind != "unknown":
        weight = 35 if claimed in ("image", "video", "audio") else 12 if kind == "text" else 20 if kind == "web" else 30
        scan.flag("type_mismatch", "The content does not match the file name", weight,
                  f"The name suggests {'an' if claimed[0] in 'aei' else 'a'} {claimed} file, but the content is really {label}.")
    if claimed:
        matches = same_family or (is_program and claimed == "program")
        scan.checks.insert(0, {"label": "The real file type matches its name" if matches else "The real file type does not match its name", "ok": matches})
    scan.checks.insert(0, {"label": "It is a program or installer" if is_program else "It is not a program or installer", "ok": not is_program})

    if bidi:
        scan.flag("name_trick", "The file name uses hidden characters", 60,
                  "Invisible text-direction characters make the name display backwards so a program can look like a document.")
    if double_extension(name):
        scan.flag("double_extension", "The file name hides its real ending", 60,
                  f"\"{name}\" is written to look like a harmless file, but the ending that counts is .{ext}.")
    if ext in DISK_EXT or kind_id == "iso":
        scan.flag("disk_image", "Disk image file", 55,
                  "Disk images open like a USB drive and can hide programs from your device's download protection. They are rarely sent for honest reasons.")
    if kind_id in OPAQUE_ARCHIVES:
        scan.flag("archive_opaque", "Archive type that could not be opened", 15, f"The contents of a {label} cannot be listed by this scanner.")
        scan.unreadable(f"The files inside this {label} were not inspected.")
    if kind_id == "onenote":
        scan.flag("onenote_file", "OneNote file", 45, "OneNote notebooks can hide scripts behind fake 'Double-click to view' buttons.")
    if kind == "unknown":
        scan.unreadable("The file type was not recognised, so its structure could not be checked." if data else "The file is empty.")
    if truncated:
        scan.note(f"Only the first {len(data) // (1024 * 1024)} MB were inspected because the file is very large.")

    score = min(100, sum(f["weight"] for f in scan.findings))
    verdict = "dangerous" if score >= 65 else "suspicious" if score >= 30 else "clean" if scan.complete else "unknown"
    return {"name": name or "unnamed file", "extension": ext, "type": label, "kind": kind, "declared_type": (declared_type or "")[:80],
            "size": total_size if total_size and total_size > len(data) else len(data), "bytes_checked": len(data),
            # A fingerprint is only meaningful when every byte was read.
            "sha256": None if truncated else hashlib.sha256(data).hexdigest(),
            "complete": scan.complete, "verdict": verdict, "score": score,
            "findings": scan.findings, "checks": scan.checks, "notes": scan.notes[:8], "links": scan.links[:20]}
