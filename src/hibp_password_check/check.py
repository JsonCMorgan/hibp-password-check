"""HIBP Pwned Passwords range API (k-anonymity)."""

from __future__ import annotations

import hashlib
import ssl
from typing import Any, Callable
from urllib.request import Request, urlopen

_API = "https://api.pwnedpasswords.com/range/{prefix}"
_TIMEOUT = 15


def sha1_password(password: str) -> str:
    """Uppercase SHA-1 of UTF-8 password (HIBP format)."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def lookup_pwned_count(
    password: str,
    *,
    fetch: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    """
    Return breach count using k-anonymity (only first 5 hash chars sent).

    Uses network unless fetch is injected (tests).
    """
    if not password:
        return {"ok": False, "error": "Password required."}

    digest = sha1_password(password)
    prefix, suffix = digest[:5], digest[5:]

    if fetch is None:
        url = _API.format(prefix=prefix)
        req = Request(url, headers={"User-Agent": "hibp-password-check/0.1 (portfolio)"})
        ctx = ssl.create_default_context()
        with urlopen(req, timeout=_TIMEOUT, context=ctx) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    else:
        body = fetch(prefix)

    count = 0
    for line in body.splitlines():
        part, _, n = line.partition(":")
        if part.strip().upper() == suffix:
            count = int(n.strip())
            break

    return {
        "ok": True,
        "pwned": count > 0,
        "count": count,
        "hash_prefix_sent": prefix,
        "privacy": "k-anonymity: only 5-char SHA-1 prefix leaves this machine.",
    }