"""
Fix for Issue #112 — Host Header Injection for Cache Poisoning
==============================================================

Vulnerability
-------------
Web applications that trust the inbound ``Host`` header (or its proxy
equivalents: ``X-Forwarded-Host``, ``X-Host``, ``X-Forwarded-Server``,
``Forwarded``) when building absolute URLs, password-reset links, OAuth
redirect URIs, or cache keys are exposed to two related attacks:

1. **Host Header Injection** — an attacker rewrites the host used in
   server-generated links (e.g. ``https://evil.tld/reset?token=...``)
   to phish victims or hijack tokens.
2. **Web-Cache Poisoning** — a CDN/proxy caches a response keyed on the
   path but with attacker-controlled content in the body (because the
   app reflected the bad host into a link or canonical tag), then
   serves that poisoned response to every subsequent visitor.

Root cause: the application accepts whatever host the client sends.
The HTTP/1.1 spec allows arbitrary text in the ``Host`` header, and
intermediaries forward attacker-controlled ``X-Forwarded-*`` headers
verbatim unless the app strips/validates them.

Fix Strategy
------------
1. Maintain an explicit allow-list of trusted hostnames (and optional
   ports) configured out-of-band — never inferred from the request.
2. Validate every host-bearing header against the allow-list using a
   strict, case-insensitive, port-aware comparison.
3. Reject requests with multiple ``Host`` headers, CRLF, embedded
   credentials, or non-ASCII bytes (defends against smuggling +
   header-injection chains).
4. Provide a single ``safe_external_url()`` helper so application code
   never concatenates ``request.host`` into URLs directly.
5. Cache keys that vary on host MUST use the *validated* host, never
   the raw header.

This module is framework-agnostic — drop in next to Flask/FastAPI/
Django/aiohttp request objects.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Optional, Tuple
from urllib.parse import quote, urlsplit, urlunsplit

# RFC 3986 reg-name + optional :port. Disallows CR/LF, spaces, '@', '/'
# (which would smuggle userinfo or path), and any non-ASCII byte.
_HOST_RE = re.compile(
    r"^(?P<host>[A-Za-z0-9](?:[A-Za-z0-9\-\.]{0,253}[A-Za-z0-9])?)"
    r"(?::(?P<port>[0-9]{1,5}))?$"
)

# Headers that can carry a client-supplied host. All are stripped or
# validated before use.
_HOST_HEADERS = (
    "host",
    "x-forwarded-host",
    "x-forwarded-server",
    "x-host",
    "x-original-host",
    "forwarded",  # RFC 7239
)


class HostValidationError(ValueError):
    """Raised when an inbound host header fails validation."""


@dataclass(frozen=True)
class TrustedHost:
    """A single entry in the allow-list."""

    hostname: str
    port: Optional[int] = None  # None = any port

    def matches(self, host: str, port: Optional[int]) -> bool:
        if host.lower() != self.hostname.lower():
            return False
        if self.port is None:
            return True
        return port == self.port


@dataclass(frozen=True)
class HostPolicy:
    """Immutable allow-list policy. Construct once at app startup."""

    trusted: Tuple[TrustedHost, ...] = field(default_factory=tuple)
    allow_ip_literals: bool = False  # only enable for internal tools

    @classmethod
    def from_iterable(cls, hosts: Iterable[str], *, allow_ip_literals: bool = False) -> "HostPolicy":
        parsed: list[TrustedHost] = []
        for raw in hosts:
            h, p = _parse_host_port(raw, allow_ip_literals=allow_ip_literals)
            parsed.append(TrustedHost(h.lower(), p))
        if not parsed:
            raise ValueError("HostPolicy requires at least one trusted host")
        return cls(tuple(parsed), allow_ip_literals)

    def is_allowed(self, host: str, port: Optional[int]) -> bool:
        return any(t.matches(host, port) for t in self.trusted)


def _parse_host_port(raw: str, *, allow_ip_literals: bool) -> Tuple[str, Optional[int]]:
    """Parse and structurally validate a 'host[:port]' string.

    Rejects: CRLF, whitespace, embedded credentials, multiple ':' (unless
    bracketed IPv6), non-ASCII, ports out of range.
    """
    if not raw or not isinstance(raw, str):
        raise HostValidationError("empty host")
    if len(raw) > 255:
        raise HostValidationError("host too long")
    if any(c in raw for c in ("\r", "\n", "\t", " ", "@", "/", "\\", "\x00")):
        raise HostValidationError("illegal character in host")
    try:
        raw.encode("ascii")
    except UnicodeEncodeError:
        # Refuse raw non-ASCII; callers must IDNA-encode beforehand.
        raise HostValidationError("non-ASCII host")

    # Bracketed IPv6: [::1]:8443
    if raw.startswith("["):
        end = raw.find("]")
        if end == -1:
            raise HostValidationError("unterminated IPv6 bracket")
        ip_part = raw[1:end]
        try:
            ipaddress.IPv6Address(ip_part)
        except ValueError as e:
            raise HostValidationError(f"bad IPv6 literal: {e}")
        if not allow_ip_literals:
            raise HostValidationError("IP literal not permitted")
        port = _parse_port(raw[end + 1 :])
        return ip_part, port

    m = _HOST_RE.match(raw)
    if not m:
        raise HostValidationError(f"malformed host: {raw!r}")
    host = m.group("host")
    port_s = m.group("port")
    port = int(port_s) if port_s is not None else None
    if port is not None and not (1 <= port <= 65535):
        raise HostValidationError("port out of range")

    # If it parses as an IPv4 literal, gate on allow_ip_literals.
    try:
        ipaddress.IPv4Address(host)
        if not allow_ip_literals:
            raise HostValidationError("IP literal not permitted")
    except ipaddress.AddressValueError:
        pass

    return host, port


def _parse_port(suffix: str) -> Optional[int]:
    if not suffix:
        return None
    if not suffix.startswith(":"):
        raise HostValidationError("expected ':port' after IPv6 literal")
    try:
        port = int(suffix[1:])
    except ValueError:
        raise HostValidationError("non-numeric port")
    if not (1 <= port <= 65535):
        raise HostValidationError("port out of range")
    return port


def validated_host(
    headers: Mapping[str, str],
    policy: HostPolicy,
    *,
    trust_forwarded: bool = False,
) -> str:
    """Return the validated 'host[:port]' for this request.

    Args:
        headers: case-insensitive view of the inbound request headers.
            (A plain dict works if the framework normalises keys; the
            function lowercases lookups defensively.)
        policy: the application's allow-list.
        trust_forwarded: only set True if the app is *known* to sit
            behind a proxy you control AND that proxy overwrites the
            ``X-Forwarded-Host`` header. Otherwise leave False so an
            attacker cannot bypass the allow-list by injecting it.

    Raises:
        HostValidationError: on any malformed or untrusted host.
    """
    lower = {k.lower(): v for k, v in headers.items()}

    # Defence against duplicate Host headers (smuggling vector). Some
    # WSGI servers join duplicates with ', '. Reject that outright.
    raw_host = lower.get("host", "")
    if "," in raw_host:
        raise HostValidationError("multiple Host headers")

    candidate = raw_host
    if trust_forwarded:
        fwd = lower.get("x-forwarded-host", "").split(",")[0].strip()
        if fwd:
            candidate = fwd

    host, port = _parse_host_port(candidate, allow_ip_literals=policy.allow_ip_literals)
    if not policy.is_allowed(host, port):
        raise HostValidationError(f"host not in allow-list: {host!r}")

    return f"{host}:{port}" if port is not None else host


def safe_external_url(
    headers: Mapping[str, str],
    policy: HostPolicy,
    path: str,
    *,
    scheme: str = "https",
    query: str = "",
    fragment: str = "",
    trust_forwarded: bool = False,
) -> str:
    """Build an absolute URL safely, using only validated host data.

    Use this everywhere your app would otherwise concatenate
    ``request.host`` into a link (password reset emails, OAuth redirect
    URIs, canonical tags, ``Location:`` headers, sitemap entries, …).
    """
    if scheme not in ("http", "https"):
        raise ValueError("scheme must be http or https")
    netloc = validated_host(headers, policy, trust_forwarded=trust_forwarded)
    safe_path = quote(path, safe="/%:@!$&'()*+,;=~")
    return urlunsplit((scheme, netloc, safe_path or "/", query, fragment))


def cache_key(
    headers: Mapping[str, str],
    policy: HostPolicy,
    path: str,
    *,
    trust_forwarded: bool = False,
) -> str:
    """Return a cache key that varies on the *validated* host.

    Never key a cache on the raw Host header — an attacker would split
    the cache by sending an unknown host and could then read back any
    poisoned entry by re-sending the same bad host.
    """
    netloc = validated_host(headers, policy, trust_forwarded=trust_forwarded)
    parts = urlsplit(path if path.startswith("/") else "/" + path)
    return f"{netloc}|{parts.path}|{parts.query}"


# ---------------------------------------------------------------------
# Self-tests — run with: python fixes/host_header_injection_fix.py
# ---------------------------------------------------------------------
if __name__ == "__main__":
    policy = HostPolicy.from_iterable(["example.com", "api.example.com:8443"])

    # Happy paths
    assert validated_host({"Host": "example.com"}, policy) == "example.com"
    assert validated_host({"Host": "EXAMPLE.com"}, policy) == "EXAMPLE.com"
    assert validated_host({"Host": "api.example.com:8443"}, policy) == "api.example.com:8443"
    assert safe_external_url({"Host": "example.com"}, policy, "/reset", query="t=abc") == \
        "https://example.com/reset?t=abc"

    # Attacks that MUST be rejected
    bad_cases = [
        {"Host": "evil.tld"},                                # not allow-listed
        {"Host": "example.com\r\nX-Injected: 1"},            # CRLF injection
        {"Host": "example.com, evil.tld"},                   # duplicate header
        {"Host": "user@evil.tld"},                           # userinfo smuggling
        {"Host": "example.com:99999"},                       # port out of range
        {"Host": ""},                                        # empty
        {"Host": "exämple.com"},                             # non-ASCII (must IDNA first)
        {"Host": "example.com/evil"},                        # path smuggling
    ]
    for h in bad_cases:
        try:
            validated_host(h, policy)
        except HostValidationError:
            continue
        raise AssertionError(f"should have rejected: {h!r}")

    # X-Forwarded-Host is ignored unless explicitly trusted
    assert validated_host(
        {"Host": "example.com", "X-Forwarded-Host": "evil.tld"}, policy
    ) == "example.com"

    # And even when trusted, the forwarded value is allow-list-checked
    try:
        validated_host(
            {"Host": "example.com", "X-Forwarded-Host": "evil.tld"},
            policy,
            trust_forwarded=True,
        )
    except HostValidationError:
        pass
    else:
        raise AssertionError("trusted forwarded host bypassed allow-list")

    # Cache key uses validated host, not raw header
    k1 = cache_key({"Host": "example.com"}, policy, "/a?b=1")
    k2 = cache_key({"Host": "EXAMPLE.com"}, policy, "/a?b=1")
    assert k1.split("|")[1:] == k2.split("|")[1:]

    print("OK — all host-header-injection defences verified.")
