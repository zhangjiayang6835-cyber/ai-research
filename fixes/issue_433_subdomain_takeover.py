"""
Fix for Issue #433: Dangling DNS Record -> Subdomain Takeover -> Cookie Stealing

Root cause:
    A "dangling" DNS record (e.g. CNAME pointing to an unclaimed cloud resource
    such as GitHub Pages, S3, Heroku, Azure) allows an attacker to register the
    resource and serve arbitrary content under a trusted subdomain of the
    victim. Because browsers scope cookies by registrable domain, cookies with
    ``Domain=.example.com`` are automatically sent to every subdomain, giving
    the attacker the victim's session cookies.

Defense-in-depth (this module):
    1. Scan configured DNS records for dangling CNAME/A/AAAA targets and
       fingerprint known takeover-vulnerable providers.
    2. Provide safe cookie construction helpers that always set
       ``HttpOnly``, ``Secure``, ``SameSite=Strict`` and NEVER widen ``Domain``
       to a parent zone -- cookies are host-only by default, so a compromised
       sibling subdomain cannot read them.
    3. Provide a WSGI/ASGI middleware that rejects requests whose ``Host``
       header is not in an explicit allow-list, blocking attacker-controlled
       hostnames pointed at the app via dangling records.

No shell=True, eval(), or exec() is used. All network operations use timeouts
and are read-only.
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass
from http.cookies import SimpleCookie
from typing import Callable, Iterable

# Fingerprints of vendor error pages that indicate an unclaimed / takeoverable
# resource. Source: EdOverflow/can-i-take-over-xyz (public research).
TAKEOVER_FINGERPRINTS: dict[str, tuple[str, ...]] = {
    "github.io":           ("There isn't a GitHub Pages site here.",),
    "herokuapp.com":       ("No such app", "no-such-app.html"),
    "s3.amazonaws.com":    ("NoSuchBucket", "The specified bucket does not exist"),
    "azurewebsites.net":   ("404 Web Site not found",),
    "cloudapp.net":        ("Do you want to register",),
    "readthedocs.io":      ("unknown to Read the Docs",),
    "surge.sh":            ("project not found",),
    "bitbucket.io":        ("Repository not found",),
    "fastly.net":          ("Fastly error: unknown domain",),
    "pantheonsite.io":     ("The gods are wise, but do not know of the site",),
}


@dataclass(frozen=True)
class DanglingRecord:
    name: str
    target: str
    provider: str
    reason: str


def _resolves(host: str, timeout: float = 3.0) -> bool:
    """Return True iff *host* resolves to at least one A/AAAA record."""
    socket.setdefaulttimeout(timeout)
    try:
        socket.getaddrinfo(host, None)
        return True
    except (socket.gaierror, socket.herror, OSError):
        return False


def audit_dns_records(
    records: Iterable[tuple[str, str]],
    http_get: Callable[[str], str] | None = None,
    resolver: Callable[[str], bool] = _resolves,
) -> list[DanglingRecord]:
    """
    Audit DNS records for potential subdomain takeover.

    ``records`` is an iterable of ``(name, target)`` tuples where ``target`` is
    the CNAME/alias value. ``http_get`` is an optional injected fetcher used to
    fingerprint provider error pages (kept injectable so tests do not hit the
    network).
    """
    findings: list[DanglingRecord] = []
    for name, target in records:
        target = target.rstrip(".").lower()

        # 1) CNAME points at a known takeover-vulnerable provider?
        provider = next(
            (p for p in TAKEOVER_FINGERPRINTS if target.endswith(p)),
            None,
        )
        if provider is None:
            continue

        # 2) The target itself no longer resolves -> clearly dangling.
        if not resolver(target):
            findings.append(
                DanglingRecord(name, target, provider, "target does not resolve")
            )
            continue

        # 3) Optional HTTP fingerprint.
        if http_get is not None:
            try:
                body = http_get(f"https://{name}") or ""
            except Exception:  # noqa: BLE001 - fingerprint is best-effort
                body = ""
            for needle in TAKEOVER_FINGERPRINTS[provider]:
                if needle in body:
                    findings.append(
                        DanglingRecord(name, target, provider, f"fingerprint: {needle}")
                    )
                    break
    return findings


# ---------------------------------------------------------------------------
# Safe cookie construction
# ---------------------------------------------------------------------------

_SAFE_COOKIE_NAME = re.compile(r"^[A-Za-z0-9_\-]+$")


def build_safe_cookie(
    name: str,
    value: str,
    *,
    max_age: int = 3600,
    path: str = "/",
) -> str:
    """
    Build a Set-Cookie header that is resistant to subdomain-takeover cookie
    theft:

    * ``Secure``      -- never sent over plaintext HTTP.
    * ``HttpOnly``    -- not readable from JavaScript, so an attacker who
      controls a sibling subdomain cannot exfiltrate it via XSS either.
    * ``SameSite=Strict`` -- not sent on cross-site requests.
    * No ``Domain`` attribute -- the cookie becomes *host-only* and is NOT
      shared with sibling subdomains. This is the key mitigation: even if
      ``evil.example.com`` is taken over, it cannot read cookies scoped to
      ``app.example.com``.
    """
    if not _SAFE_COOKIE_NAME.match(name):
        raise ValueError(f"unsafe cookie name: {name!r}")
    # Use SimpleCookie for correct quoting of the value.
    jar: SimpleCookie = SimpleCookie()
    jar[name] = value
    morsel = jar[name]
    morsel["path"] = path
    morsel["max-age"] = int(max_age)
    morsel["secure"] = True
    morsel["httponly"] = True
    morsel["samesite"] = "Strict"
    # Intentionally do NOT set morsel["domain"].
    return morsel.OutputString()


# ---------------------------------------------------------------------------
# Host allow-list middleware
# ---------------------------------------------------------------------------

def make_host_allowlist_middleware(app, allowed_hosts: Iterable[str]):
    """
    WSGI middleware that rejects requests whose ``Host`` header is not in the
    explicit allow-list. This means an attacker who takes over a dangling
    subdomain cannot serve the real application under the stolen hostname
    just by proxying traffic to it.
    """
    allowed = {h.strip().lower().rstrip(".") for h in allowed_hosts if h.strip()}

    def middleware(environ, start_response):
        host = (environ.get("HTTP_HOST") or "").split(":")[0].lower().rstrip(".")
        if host not in allowed:
            start_response("421 Misdirected Request", [("Content-Type", "text/plain")])
            return [b"Misdirected request: host not allowed"]
        return app(environ, start_response)

    return middleware
