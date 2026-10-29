"""The single IOC extractor. Replaces the duplicate logic in ingestion and the context agent."""

from __future__ import annotations

import ipaddress
import re
from typing import Callable, Literal

import tldextract

from app.normalization.canonical import CanonicalEvent

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # bundled snapshot, no network

_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
_DOMAIN_RE = re.compile(r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w-])", re.I)
_URL_HOST_RE = re.compile(r"(?:https?|hxxps?)://([^/\s\"'<>?#]+)", re.I)
_HEX_RE = re.compile(r"^[0-9a-f]+$")
# Real ccTLD/gTLDs that overwhelmingly appear as file extensions inside command lines.
_FILE_LIKE_TLDS = {"py", "sh", "zip", "mov", "pl", "rs", "md", "cc", "ps", "so"}
# Bare-text matches (script bodies, command lines) only accept these TLDs: script code such as
# `$ms.Seek(0)`, `WScript.Shell`, `$service.Name` otherwise looks like a domain (.seek/.shell/.name are real gTLDs).
_TEXT_TLDS = {
    "com", "net", "org", "io", "gov", "edu", "co", "uk", "de", "ru", "cn", "xyz", "top", "info", "biz",
    "me", "us", "cloud", "ai", "app", "dev", "tk", "ml", "ga", "cf", "gq", "pw", "su", "cc", "in", "br",
    "fr", "nl", "it", "jp", "kr", "au", "ca", "onion",
}


def defang(text: str) -> str:
    return (text.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
                .replace("hxxp", "http").replace("hXXp", "http"))


def public_ip(value: str | None) -> str | None:
    """Return the normalized IP only when it is globally routable (not private/reserved/multicast)."""
    if not value:
        return None
    text = value.strip()
    if text.lower().startswith("::ffff:"):
        text = text[7:]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    return str(ip) if ip.is_global and not ip.is_multicast else None


def public_domain(value: str | None, allow_file_tlds: bool = False) -> str | None:
    """Return a lowercase domain only if it has a real public suffix (so 'wpad', '*.local', 'calc.exe' fail)."""
    if not value:
        return None
    text = value.strip().lower().rstrip(".")
    if not text or "/" in text or " " in text:
        return None
    parts = _EXTRACT(text)
    if not parts.suffix or not parts.domain:
        return None
    if not allow_file_tlds and parts.suffix in _FILE_LIKE_TLDS:
        return None
    return text


def ioc_kind(ioc: str) -> Literal["ip", "domain", "hash"]:
    if public_ip(ioc) or re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", ioc):
        return "ip"
    if _HEX_RE.match(ioc) and len(ioc) in (32, 40, 64):
        return "hash"
    return "domain"


def _text_iocs(text: str | None) -> list[str]:
    if not text:
        return []
    text = defang(text)
    found: list[str] = []
    for match in _URL_HOST_RE.finditer(text):
        host = match.group(1).split(":")[0]
        candidate = public_ip(host) or public_domain(host, allow_file_tlds=True)
        if candidate:
            found.append(candidate)
    for match in _IPV4_RE.finditer(text):
        ip = public_ip(match.group(0))
        if ip:
            found.append(ip)
    for match in _DOMAIN_RE.finditer(text):
        start, end = match.span()
        if (start > 0 and text[start - 1] == "$") or text[end:end + 1] == "(":
            continue  # variable / method call in script code, not a hostname
        if match.group(0).rsplit(".", 1)[-1].lower() not in _TEXT_TLDS:
            continue
        domain = public_domain(match.group(0))
        if domain:
            found.append(domain)
    return found


def extract_iocs(
    event: CanonicalEvent,
    is_benign_domain: Callable[[str], bool] | None = None,
) -> list[str]:
    """Ordered, deduplicated indicators: public IPs, public domains, one hash (sha256 preferred)."""
    candidates: list[str] = []
    for ip in (event.dst_ip, event.src_ip):
        ip = public_ip(ip)
        if ip:
            candidates.append(ip)

    dns = public_domain(event.query_name, allow_file_tlds=True)
    if dns:
        candidates.append(dns)
    for part in (event.query_results or "").split(";"):
        ip = public_ip(part.strip())
        if ip:
            candidates.append(ip)

    for algo in ("sha256", "sha1", "md5"):
        if event.hashes.get(algo):
            candidates.append(event.hashes[algo])
            break

    candidates += _text_iocs(event.command_line)
    candidates += _text_iocs(event.script_block)

    seen: set[str] = set()
    result: list[str] = []
    for item in candidates:
        key = item.lower()
        if key in seen:
            continue
        if ioc_kind(key) == "domain" and is_benign_domain and is_benign_domain(key):
            continue
        seen.add(key)
        result.append(key)
    return result
