"""
Fix for Issue: CORS Misconfiguration + Origin Reflection -> Credential Theft

Vulnerability
-------------
The API reflected the incoming ``Origin`` request header verbatim into the
``Access-Control-Allow-Origin`` response header while also sending
``Access-Control-Allow-Credentials: true``. This lets ANY website read
credentialed cross-origin responses from the API (session cookies, auth
tokens, private data), because browsers will happily send credentials to a
CORS response that echoes back the requesting page's own Origin.

Fix Strategy
------------
1. Maintain an explicit allow-list of trusted origins. Never reflect an
   arbitrary ``Origin`` header value that isn't on the list.
2. Only ever return a *specific* origin (never ``*``) when credentials are
   enabled. ``Access-Control-Allow-Credentials: true`` and
   ``Access-Control-Allow-Origin: *`` must never be combined -- this is
   rejected outright by browsers as insecure, and we also refuse to build
   such a combination server-side to avoid config drift.
3. Always emit ``Vary: Origin`` when the allowed-origin value depends on the
   request's ``Origin`` header, so shared caches/CDNs cannot serve one
   origin's CORS-enabled response to a different, disallowed origin
   (cache-based CORS bypass).
4. Default-deny: if the Origin is missing or not on the allow-list, omit the
   CORS headers entirely (the browser then blocks the cross-origin read).

The implementation is dependency-free and framework-agnostic so it can be
dropped into Flask/FastAPI/Django/aiohttp middleware.

Usage:
    policy = CORSPolicy(
        allowed_origins={"https://app.example.com", "https://admin.example.com"},
        allow_credentials=True,
    )

    @app.after_request
    def add_cors_headers(response):
        origin = request.headers.get("Origin", "")
        for key, value in policy.build_headers(origin).items():
            response.headers[key] = value
        return response
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, Optional


_DEFAULT_ALLOWED_METHODS = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
_DEFAULT_ALLOWED_HEADERS = "Authorization, Content-Type"


@dataclass
class CORSPolicy:
    """Builds safe CORS response headers based on an explicit allow-list.

    ``allow_credentials`` and a wildcard origin are mutually exclusive by
    design: if ``allow_credentials`` is True, the allow-list MUST be used and
    ``Access-Control-Allow-Origin`` will only ever be a specific origin (never
    ``*``). If no allow-list is configured (wildcard mode), credentials are
    always forced to False regardless of the ``allow_credentials`` flag,
    closing off the vulnerable combination entirely.
    """

    allowed_origins: FrozenSet[str] = field(default_factory=frozenset)
    allow_credentials: bool = False
    allowed_methods: str = _DEFAULT_ALLOWED_METHODS
    allowed_headers: str = _DEFAULT_ALLOWED_HEADERS
    max_age_seconds: int = 600

    def __post_init__(self) -> None:
        # Normalize to a frozenset of lower-cased, trimmed origins for exact
        # scheme+host+port matching (CORS origins are case-sensitive in
        # practice for host, but we normalize defensively without weakening
        # the check -- exact string match is still required afterwards).
        normalized = frozenset(o.strip() for o in self.allowed_origins if o and o.strip())
        object.__setattr__(self, "allowed_origins", normalized)

        # Never allow the insecure combination of wildcard + credentials.
        if not self.allowed_origins:
            object.__setattr__(self, "allow_credentials", False)

    @classmethod
    def from_origins(
        cls,
        origins: Iterable[str],
        *,
        allow_credentials: bool = False,
        allowed_methods: str = _DEFAULT_ALLOWED_METHODS,
        allowed_headers: str = _DEFAULT_ALLOWED_HEADERS,
        max_age_seconds: int = 600,
    ) -> "CORSPolicy":
        return cls(
            allowed_origins=frozenset(origins),
            allow_credentials=allow_credentials,
            allowed_methods=allowed_methods,
            allowed_headers=allowed_headers,
            max_age_seconds=max_age_seconds,
        )

    def is_allowed(self, origin: str) -> bool:
        """Strict allow-list membership check (no reflection of arbitrary origins)."""
        if not origin:
            return False
        return origin in self.allowed_origins

    def build_headers(self, request_origin: Optional[str]) -> Dict[str, str]:
        """Build the safe set of CORS response headers for a given request.

        Returns an empty dict (no CORS headers) when:
          * no ``Origin`` header was sent, or
          * the origin is not on the allow-list (default-deny).

        Always includes ``Vary: Origin`` whenever an ``Origin``-dependent
        decision was made, so caches do not leak one origin's response to
        another.
        """
        headers: Dict[str, str] = {}

        if not self.allowed_origins:
            # Wildcard mode: credentials are always disabled (see
            # __post_init__), so a shared, non-reflected wildcard response is
            # safe to serve to anyone.
            headers["Access-Control-Allow-Origin"] = "*"
            headers["Access-Control-Allow-Methods"] = self.allowed_methods
            headers["Access-Control-Allow-Headers"] = self.allowed_headers
            headers["Access-Control-Max-Age"] = str(self.max_age_seconds)
            return headers

        # Allow-list mode: never reflect an arbitrary Origin. Only echo back
        # the origin if it is explicitly present on the allow-list.
        headers["Vary"] = "Origin"

        if not request_origin or not self.is_allowed(request_origin):
            # Default-deny: omit Access-Control-Allow-Origin entirely so the
            # browser blocks the cross-origin read.
            return headers

        headers["Access-Control-Allow-Origin"] = request_origin
        headers["Access-Control-Allow-Methods"] = self.allowed_methods
        headers["Access-Control-Allow-Headers"] = self.allowed_headers
        headers["Access-Control-Max-Age"] = str(self.max_age_seconds)

        # Only ever emit credentials=true alongside a *specific*, allow-listed
        # origin -- never combined with a wildcard (enforced by construction
        # above, since wildcard mode returns earlier and never reaches here).
        if self.allow_credentials:
            headers["Access-Control-Allow-Credentials"] = "true"

        return headers


def build_cors_headers(
    request_origin: Optional[str],
    allowed_origins: Iterable[str],
    *,
    allow_credentials: bool = False,
) -> Dict[str, str]:
    """Convenience one-shot helper wrapping :class:`CORSPolicy`."""
    policy = CORSPolicy.from_origins(allowed_origins, allow_credentials=allow_credentials)
    return policy.build_headers(request_origin)


# --------------------------------------------------------------------- self-test
if __name__ == "__main__":
    trusted = {"https://app.example.com", "https://admin.example.com"}

    # Allowed origin: reflected exactly, Vary present, credentials true only
    # because policy explicitly enabled it for this specific allow-listed origin.
    policy = CORSPolicy.from_origins(trusted, allow_credentials=True)
    headers = policy.build_headers("https://app.example.com")
    assert headers["Access-Control-Allow-Origin"] == "https://app.example.com"
    assert headers["Access-Control-Allow-Credentials"] == "true"
    assert headers["Vary"] == "Origin"

    # Disallowed / attacker origin: no reflection, no ACAO header at all.
    headers_evil = policy.build_headers("https://evil.attacker.example")
    assert "Access-Control-Allow-Origin" not in headers_evil
    assert "Access-Control-Allow-Credentials" not in headers_evil
    assert headers_evil.get("Vary") == "Origin"

    # Missing Origin header: no CORS headers leaked.
    headers_none = policy.build_headers(None)
    assert "Access-Control-Allow-Origin" not in headers_none

    # Wildcard / public mode: credentials must NEVER be true, even if the
    # caller mistakenly asks for it.
    public_policy = CORSPolicy.from_origins([], allow_credentials=True)
    public_headers = public_policy.build_headers("https://anything.example")
    assert public_headers["Access-Control-Allow-Origin"] == "*"
    assert "Access-Control-Allow-Credentials" not in public_headers

    print("cors_origin_whitelist_fix self-test passed")
