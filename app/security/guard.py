"""Strict URL parsing and public-IP checks. Network policy must ALSO block private egress.
DNS checks alone do not prevent DNS rebinding: do not use this as a sole sandbox boundary.
"""
import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit


class UnsafeURL(ValueError):
    pass


def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw or len(raw) > 2048 or any(ord(x) < 32 for x in raw):
        raise UnsafeURL("Enter one valid link (maximum 2,048 characters).")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parts = urlsplit(raw)
        host = (parts.hostname or "").rstrip(".").lower()
        port = parts.port
    except (ValueError, TypeError):
        raise UnsafeURL("Invalid URL or port.") from None
    if parts.scheme.lower() not in ("https", "http") or not host or parts.username or parts.password:
        raise UnsafeURL("Only public HTTP(S) URLs without credentials are accepted.")
    if port not in (None, 80, 443):
        raise UnsafeURL("Links using nonstandard ports are not supported.")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise UnsafeURL("Invalid domain name.") from None
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".test", ".invalid")):
        raise UnsafeURL("Local and internal addresses cannot be scanned.")
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        if "." not in host or len(host) > 253:
            raise UnsafeURL("Enter a valid public domain name.")
        if any(not s or len(s) > 63 for s in host.split(".")):
            raise UnsafeURL("Invalid domain name.")
    else:
        if not address.is_global:
            raise UnsafeURL("Private or reserved IP addresses cannot be scanned.")
    host_uri = f"[{host}]" if ":" in host else host
    netloc = host_uri + (f":{port}" if port else "")
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


async def public_dns(host: str) -> bool:
    """Defense in depth for sandbox worker; does not pin browser DNS resolution."""
    try:
        results = await asyncio.wait_for(asyncio.to_thread(socket.getaddrinfo, host, None), timeout=3)
        return bool(results) and all(ipaddress.ip_address(r[4][0]).is_global for r in results)
    except (OSError, ValueError, asyncio.TimeoutError):
        return False
