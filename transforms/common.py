"""
Shared helpers for transforms: a pooled async HTTP client, target validation,
and org-scope enforcement (so pivots never wander off the authorized domain).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional

import httpx

USER_AGENT = "TOP-RECON/1.0 (authorized attack-surface recon)"

# A pragmatic multi-label public-suffix set covering the common cases so apex
# extraction is correct for co.uk, com.au, etc. without a heavy dependency.
_MULTI_SUFFIX = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au",
    "co.nz", "co.za", "com.br", "com.cn", "com.mx", "co.jp", "co.in",
    "co.kr", "com.sg", "com.tr", "com.ng", "org.ng", "gov.ng", "edu.ng",
}

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+$")

_shared_client: Optional[httpx.AsyncClient] = None


def http_client() -> httpx.AsyncClient:
    """One pooled keep-alive async client, reused across all transforms."""
    global _shared_client
    if _shared_client is None or _shared_client.is_closed:
        _shared_client = httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT},
            timeout=httpx.Timeout(20.0, connect=10.0),
            follow_redirects=True,
            limits=httpx.Limits(max_connections=40, max_keepalive_connections=20),
            trust_env=False,
        )
    return _shared_client


async def close_http() -> None:
    global _shared_client
    if _shared_client is not None and not _shared_client.is_closed:
        await _shared_client.aclose()
    _shared_client = None


def is_valid_domain(value: str) -> bool:
    v = (value or "").strip().rstrip(".").lower()
    if v.startswith("*."):
        v = v[2:]
    return bool(_DOMAIN_RE.match(v))


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def apex_domain(host: str) -> str:
    """Return the registrable apex for *host* (e.g. api.foo.co.uk → foo.co.uk)."""
    h = (host or "").strip().rstrip(".").lower()
    if h.startswith("*."):
        h = h[2:]
    labels = h.split(".")
    if len(labels) <= 2:
        return h
    last2 = ".".join(labels[-2:])
    last3 = ".".join(labels[-3:])
    if last2 in _MULTI_SUFFIX and len(labels) >= 3:
        return last3
    return last2


def in_scope(host: str, seed_apex: str) -> bool:
    """True if *host* is the seed apex or a subdomain of it (org-scope guard)."""
    h = (host or "").strip().rstrip(".").lower()
    if h.startswith("*."):
        h = h[2:]
    seed = (seed_apex or "").strip().rstrip(".").lower()
    return bool(h) and (h == seed or h.endswith("." + seed))


def clean_host(value: str) -> str:
    return (value or "").strip().rstrip(".").lower().lstrip("*.").strip()
