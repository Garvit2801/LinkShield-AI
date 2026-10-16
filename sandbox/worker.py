"""Disposable browser-evidence and file-inspection service.

SECURITY CONTRACT: this is not a malware-detonation engine. It never runs programs,
submits forms or enters real credentials. Files are fetched into memory, described by
static inspection (see filescan.py) and discarded; they are never written to disk.
Web content (pages, and HTML/SVG attachments) is rendered in a throwaway browser that
fast-forwards timers and types obviously fake details, without ever pressing submit,
to see what the page does over time (see app/security/behaviour.py).
For hostile URLs, run only on an isolated service with egress controls outside this process.
"""
import asyncio
import base64
import hmac
import os
import re
from urllib.parse import unquote, urljoin, urlsplit

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field
from playwright.async_api import async_playwright, Error as PlaywrightError

from app.security import behaviour
from app.security.guard import UnsafeURL, normalize_url, public_dns
from sandbox.filescan import analyze

app = FastAPI(title="LinkShield disposable-browser worker", docs_url=None, redoc_url=None)
LIMIT = asyncio.Semaphore(2)
MAX_FILE_BYTES = int(os.getenv("FILE_MAX_BYTES", str(40 * 1024 * 1024)))
MAX_UPLOAD_BYTES = int(os.getenv("UPLOAD_MAX_BYTES", str(25 * 1024 * 1024)))
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
# Pages are visited as an Android phone: most people receiving these links are on one, and scam kits often show phones something else.
PHONE_UA = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"
CANARY = "ls-canary-7731@example.com"
ATTACHMENT_ORIGIN = "https://attachment.linkshield.invalid/"
# Injected before any page script: records what the page tries to do. Permissions are denied by the browser context anyway.
PROBE = r"""(() => {
  const L = window.__ls = {clipboard: [], permissions: [], popups: 0, fullscreen: 0, pushes: 0, unload: 0};
  try { Object.defineProperty(Navigator.prototype, 'webdriver', {get: () => false}); } catch (e) {}
  const note = (k, v) => { try { if (Array.isArray(L[k])) { if (L[k].length < 10) L[k].push(String(v).slice(0, 300)); } else L[k]++; } catch (e) {} };
  const wrap = (obj, name, fn) => { try { const orig = obj && obj[name]; if (typeof orig !== 'function') return;
    obj[name] = function (...a) { try { fn(...a); } catch (e) {} return orig.apply(this, a); }; } catch (e) {} };
  if (navigator.clipboard) wrap(navigator.clipboard, 'writeText', t => note('clipboard', t));
  wrap(DataTransfer.prototype, 'setData', (t, v) => note('clipboard', v));
  wrap(document, 'execCommand', c => { if (String(c).toLowerCase() === 'copy') note('clipboard', String(document.getSelection() || '')); });
  if (window.Notification) wrap(Notification, 'requestPermission', () => note('permissions', 'notifications'));
  if (navigator.geolocation) { wrap(navigator.geolocation, 'getCurrentPosition', () => note('permissions', 'location'));
    wrap(navigator.geolocation, 'watchPosition', () => note('permissions', 'location')); }
  if (navigator.mediaDevices) wrap(navigator.mediaDevices, 'getUserMedia', c => note('permissions', c && c.video ? 'camera' : 'microphone'));
  if (navigator.credentials) wrap(navigator.credentials, 'get', () => note('permissions', 'saved logins'));
  wrap(Element.prototype, 'requestFullscreen', () => note('fullscreen'));
  wrap(Element.prototype, 'webkitRequestFullscreen', () => note('fullscreen'));
  if (navigator.keyboard) wrap(navigator.keyboard, 'lock', () => note('fullscreen'));
  wrap(window, 'open', () => note('popups'));
  wrap(history, 'pushState', () => note('pushes'));
  const add = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function (t, ...r) { if (t === 'beforeunload') note('unload'); return add.call(this, t, ...r); };
})();"""
# Content a browser shows as a page rather than saving as a file.
PAGE_TYPES = ("text/html", "application/xhtml+xml", "text/plain", "application/json", "text/xml", "application/xml",
              "text/css", "text/javascript", "application/javascript")


class Investigation(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


def authorize(authorization: str | None):
    token = os.environ.get("SANDBOX_TOKEN", "")
    if not token or not hmac.compare_digest(authorization or "", f"Bearer {token}"):
        raise HTTPException(401, "Unauthorized")


@app.get("/healthz")
async def healthz():
    return {"ok": True, "role": "sandbox_worker"}


@app.post("/investigate")
async def investigate(request: Investigation, authorization: str | None = Header(None)):
    authorize(authorization)
    try:
        url = normalize_url(request.url)
    except UnsafeURL as exc:
        raise HTTPException(422, str(exc)) from None
    if not await public_dns(urlsplit(url).hostname or ""):
        return {"status": "blocked", "evidence": {}, "error": "Destination is not a resolvable public host"}
    async with LIMIT:
        # A link can lead straight to a file. Find out before a browser is pointed at it.
        probe = await guarded_fetch(url)
        if probe["kind"] == "file":
            return {"status": "completed", "target": "file", "files": [probe["file"]],
                    "evidence": {"final_url": probe["final_url"], "redirects": probe["redirects"]}}
        try:
            result = await asyncio.wait_for(open_page(url), timeout=32)
        except asyncio.TimeoutError:
            return {"status": "error", "evidence": {}, "error": "Sandbox investigation timed out"}
        except Exception:
            return {"status": "error", "evidence": {}, "error": "Page could not be investigated"}
        # Files the page tried to push are fetched again here, outside the browser, and inspected.
        files = []
        referer = (result.get("evidence") or {}).get("final_url", url)
        for link in result.pop("download_urls", [])[:2]:
            got = await guarded_fetch(link, referer=referer, pages_ok=False)
            if got["kind"] == "file":
                files.append(got["file"])
        result = {**result, "target": "page", "files": files}
        if probe["kind"] == "error":
            result["file_error"] = probe.get("error", "")
        return result


@app.post("/scan-file")
async def scan_file(request: Request, authorization: str | None = Header(None), x_file_name: str = Header("")):
    """Inspect bytes handed over by the API (a file the user already has). Nothing is stored."""
    authorize(authorization)
    data = bytearray()
    async for chunk in request.stream():
        data += chunk
        if len(data) > MAX_UPLOAD_BYTES:
            raise HTTPException(413, "File is too large to inspect")
    async with LIMIT:
        report = await asyncio.to_thread(analyze, bytes(data), unquote(x_file_name)[:300], request.headers.get("x-file-type", ""))
        if report["type"] in ("Web page (HTML)", "SVG image") and report["complete"]:
            report = await render_attachment(report, bytes(data))
    return {"status": "completed", "file": report}


async def render_attachment(report: dict, data: bytes) -> dict:
    """Open an HTML or SVG attachment in the throwaway browser, as if the person had tapped it, and add what it did."""
    kind = "image/svg+xml" if report["type"] == "SVG image" else "text/html"
    try:
        seen = await asyncio.wait_for(open_page(ATTACHMENT_ORIGIN + ("file.svg" if kind == "image/svg+xml" else "file.html"), (data, kind)), timeout=32)
    except Exception:
        report["notes"] = (report["notes"] + ["The file could not be opened in the safe browser, so only its structure was checked."])[:8]
        return report
    if seen.get("status") != "completed":
        return report
    ev = seen["evidence"]
    found = behaviour.findings(ev.get("behaviour") or {})
    if ev.get("generated_downloads"):
        found.append({"code": "smuggled_download", "label": "Builds a file inside the browser when opened", "weight": 55,
                      "detail": "Opening it assembles a download with script, a trick for slipping malware past email and chat scanners."})
    if ev.get("downloads", 0) > ev.get("generated_downloads", 0):
        found.append({"code": "download_attempt", "label": "Starts a download when opened", "weight": 38, "detail": "Opening the file tried to download something."})
    # Having watched it, a web page file that did nothing suspicious is no longer worth a warning on its own.
    for f in report["findings"]:
        if f["code"] == "html_file":
            f["weight"] = 10
            f["detail"] += " The sandbox opened it and watched what it did."
    known = {f["code"] for f in report["findings"]}
    report["findings"] += [f for f in found if f["code"] not in known]
    report["checks"] += behaviour.checks(ev.get("behaviour") or {})
    if ev.get("final_url", "").startswith(("http://", "https://")) and not ev["final_url"].startswith(ATTACHMENT_ORIGIN):
        report["links"] = list(dict.fromkeys([ev["final_url"]] + report["links"]))[:20]
        report["notes"] = (report["notes"] + [f"When opened, it sends the browser to {urlsplit(ev['final_url']).hostname}."])[:8]
    report["opened_in_browser"] = True
    report["score"] = min(100, sum(f["weight"] for f in report["findings"]))
    report["verdict"] = "dangerous" if report["score"] >= 65 else "suspicious" if report["score"] >= 30 else "clean"
    return report


def _file_name(disposition: str, url: str) -> str:
    star = re.search(r"filename\*\s*=\s*[^']*'[^']*'([^;]+)", disposition or "", re.I)
    plain = re.search(r'filename\s*=\s*"?([^";]+)"?', disposition or "", re.I)
    if star:
        return unquote(star.group(1).strip())
    if plain:
        return plain.group(1).strip()
    return unquote(urlsplit(url).path.rsplit("/", 1)[-1])


async def guarded_fetch(url: str, referer: str = "", pages_ok: bool = True, transport=None) -> dict:
    try:
        return await asyncio.wait_for(fetch_file(url, referer, pages_ok, transport), timeout=28)
    except Exception:
        return {"kind": "error", "error": "The file could not be fetched"}


async def fetch_file(url: str, referer: str = "", pages_ok: bool = True, transport=None) -> dict:
    """Download a file into memory with a size cap, re-checking every redirect hop, then inspect it.

    Returns kind "page" when the address serves a web page (and pages_ok), "file" with an
    inspection report, or "error".
    """
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if referer:
        headers["Referer"] = referer
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 22
    async with httpx.AsyncClient(follow_redirects=False, timeout=httpx.Timeout(8, read=10), headers=headers,
                                 trust_env=False, transport=transport) as client:
        for hop in range(7):
            try:
                url = normalize_url(url)
            except UnsafeURL:
                return {"kind": "error", "error": "Download address is not allowed"}
            if not await public_dns(urlsplit(url).hostname or ""):
                return {"kind": "error", "error": "Download address is not a public host"}
            async with client.stream("GET", url) as response:
                if response.status_code in (301, 302, 303, 307, 308) and response.headers.get("location"):
                    url = urljoin(url, response.headers["location"])
                    continue
                if response.status_code >= 400:
                    return {"kind": "error", "error": f"Server answered {response.status_code}"}
                declared = response.headers.get("content-type", "")
                disposition = response.headers.get("content-disposition", "")
                attachment = disposition.strip().lower().startswith("attachment")
                if pages_ok and not attachment and declared.split(";")[0].strip().lower() in PAGE_TYPES:
                    return {"kind": "page"}
                data, truncated = bytearray(), False
                async for chunk in response.aiter_bytes(65536):
                    data += chunk
                    if len(data) > MAX_FILE_BYTES or loop.time() > deadline:
                        del data[MAX_FILE_BYTES:]
                        truncated = True
                        break
                length = response.headers.get("content-length", "")
                total = int(length) if length.isdigit() and not response.headers.get("content-encoding") else None
            report = await asyncio.to_thread(analyze, bytes(data), _file_name(disposition, url), declared, truncated, total)
            return {"kind": "file", "file": {**report, "source_url": url}, "final_url": url, "redirects": hop}
    return {"kind": "error", "error": "Too many redirects"}


async def open_page(url: str, content: tuple[bytes, str] | None = None) -> dict:
    """Observe one untrusted page (or attachment, given as content) without submitting forms or saving downloads."""
    blocked, hops, pushed, generated = 0, [], [], 0
    requests, dialogs, popups = [], [], 0
    phase = {"late": False}
    late_downloads = 0
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=["--disable-extensions", "--disable-background-networking",
                                                          "--disable-sync", "--no-first-run", "--disable-dev-shm-usage"])
        context = await browser.new_context(accept_downloads=False, service_workers="block",
                                            permissions=[], ignore_https_errors=False, java_script_enabled=True,
                                            user_agent=PHONE_UA, viewport={"width": 412, "height": 860}, device_scale_factor=2,
                                            is_mobile=True, has_touch=True, locale="en-IN", timezone_id="Asia/Kolkata")
        await context.add_init_script(PROBE)
        page = await context.new_page()
        page.set_default_timeout(5000)

        def on_download(download):
            nonlocal generated, late_downloads
            hops.append("download-attempt")
            if phase["late"]:
                late_downloads += 1
            if download.url.startswith(("https://", "http://")):
                pushed.append(download.url)
            else:
                # blob: and data: downloads are assembled by script inside the page ("HTML smuggling").
                generated += 1

        async def on_popup(new_page):
            nonlocal popups
            popups += 1
            try:
                await new_page.close()
            except PlaywrightError:
                pass

        async def on_dialog(dialog):
            dialogs.append(dialog.message[:200])
            try:
                await dialog.dismiss()
            except PlaywrightError:
                pass

        def on_request(req):
            if len(requests) < 400:
                requests.append((req.url[:2000], (req.post_data or "")[:4000] if req.method != "GET" else ""))

        page.on("download", on_download)
        page.on("dialog", on_dialog)
        context.on("page", lambda pg: asyncio.ensure_future(on_popup(pg)) if pg != page else None)
        context.on("request", on_request)

        async def safe_route(route):
            nonlocal blocked
            req_url = route.request.url
            # Only browser network requests; block internal IPs and non-web schemes.
            try:
                if not req_url.startswith(("https://", "http://")):
                    raise UnsafeURL("Only web navigation is allowed")
                dest = normalize_url(req_url)
                if not await public_dns(urlsplit(dest).hostname or ""):
                    raise UnsafeURL("Non-public DNS result")
            except (UnsafeURL, ValueError):
                blocked += 1
                await route.abort("blockedbyclient")
                return
            # Decline potentially executable/binary resource types; never download or run binaries.
            if route.request.resource_type in ("media", "font", "websocket"):
                await route.abort("blockedbyclient")
                return
            await route.continue_()

        await context.route("**/*", safe_route)
        if content:
            # The attachment is served from a made-up address so it behaves exactly as if opened from a download.
            await page.route(url, lambda route: route.fulfill(status=200, body=content[0], content_type=content[1]))
        page.on("framenavigated", lambda f: hops.append(f.url) if f == page.main_frame else None)

        def downloads_only():
            # The address produced a download instead of a page, so there is nothing to render.
            return {"status": "completed", "download_urls": pushed, "evidence": {
                "title": "", "final_url": url, "redirects": 0, "password_inputs": 0, "payment_inputs": 0, "cross_domain_forms": 0,
                "downloads": hops.count("download-attempt"), "generated_downloads": generated, "blocked_requests": blocked, "screenshot_base64": ""}}

        async def settle(ms):
            try:
                await page.wait_for_load_state("networkidle", timeout=ms)
            except PlaywrightError:
                pass

        try:
            # A fake clock lets code that waits minutes before acting run now (see the fast-forward below).
            await page.clock.install()
            try:
                response = await page.goto(url, wait_until="domcontentloaded", timeout=10000)
            except PlaywrightError:
                if "download-attempt" in hops:
                    return downloads_only()
                raise
            await settle(4000)
            landed = urlsplit(page.url).hostname or ""
            tests = ["downloads", "clipboard", "permissions", "lockin", "popups", "exfil"]
            # Fast-forward 30 seconds, then 5 minutes: every timer due in that time fires once.
            phase["late"] = True
            for jump in ("00:30", "05:00"):
                try:
                    await page.clock.fast_forward(jump)
                except PlaywrightError:
                    break
                await page.wait_for_timeout(900)
            tests.append("delayed")
            await settle(2500)
            phase["late"] = False
            delayed_redirect = (urlsplit(page.url).hostname or "") not in ("", landed)
            # Type obviously fake details into the first login-style box. Never press Enter or any button.
            keystroke_leak = False
            field = page.locator('input[type="password"], input[type="email"], input[type="tel"], input[name*="user" i], input[name*="mobile" i]').first
            try:
                if await field.count() and await field.is_visible():
                    before = len(requests)
                    await field.press_sequentially(CANARY, delay=25, timeout=4000)
                    await page.wait_for_timeout(1500)
                    keystroke_leak = any("ls-canary-7731" in u or "ls-canary-7731" in body for u, body in requests[before:])
                    tests.append("keystrokes")
            except PlaywrightError:
                pass
            title = (await page.title())[:200]
            final = page.url
            text = (await page.locator("body").inner_text(timeout=4000))[:3500]
            password_fields = await page.locator('input[type="password"]').count()
            payment_fields = await page.locator('input[autocomplete*="cc-"], input[name*="card" i], input[name*="cvv" i]').count()
            form_actions = await page.locator("form[action]").evaluate_all("xs => xs.map(x => x.action).slice(0, 25)")
            initial_host = urlsplit(final).hostname or ""
            external_forms = sum(1 for action in form_actions if urlsplit(action).hostname not in (None, initial_host))
            probe = await page.evaluate("() => window.__ls || {}")
            hosts = {urlsplit(u).hostname or "" for u, _ in requests}
            seen = {
                "tests": tests, "clipboard": probe.get("clipboard", []), "permissions": probe.get("permissions", []),
                "fullscreen": bool(probe.get("fullscreen")), "back_trap": probe.get("pushes", 0) >= 5 or bool(probe.get("unload")),
                "popups": popups + int(probe.get("popups", 0)), "dialogs": len(dialogs), "keystroke_leak": keystroke_leak,
                "exfil_hosts": sorted(h for h in hosts if behaviour.is_exfil(h))[:5], "password_inputs": password_fields,
                "delayed_redirect": delayed_redirect, "late_downloads": late_downloads,
                "miner": any(behaviour.MINER.search(u) for u, _ in requests), "requests": len(requests), "hosts": len(hosts),
            }
            screenshot = await page.screenshot(type="jpeg", quality=52, full_page=False, timeout=4000)
            screenshot_b64 = base64.b64encode(screenshot).decode("ascii") if len(screenshot) <= 330000 else ""
            evidence = {"title": title, "final_url": final, "page_text": text, "http_status": response.status if response else 0,
                        "redirects": max(0, len([h for h in hops if h != "download-attempt"])-1),
                        "password_inputs": password_fields, "payment_inputs": payment_fields,
                        "cross_domain_forms": external_forms, "downloads": hops.count("download-attempt"),
                        "generated_downloads": generated, "blocked_requests": blocked, "screenshot_base64": screenshot_b64,
                        "behaviour": seen}
            return {"status": "completed", "evidence": evidence, "download_urls": pushed}
        except (PlaywrightError, TimeoutError):
            return {"status": "error", "evidence": {}, "error": "Browser navigation failed or timed out"}
        finally:
            await context.close()
            await browser.close()
