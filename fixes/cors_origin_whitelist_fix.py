"""
Fix for [BUG] CORS Misconfiguration + Origin Reflection -> Credential Theft

Vulnerability
-------------
The API previously reflected the request's ``Origin`` header directly back as
``Access-Control-Allow-Origin: {Origin}`` while also sending
``Access-Control-Allow-Credentials: true``. This lets *any* website make a
credentialed cross-origin request (``fetch(url, {credentials: 'include'})``)
and read the authenticated response, effectively stealing session cookies /
auth tokens cross-origin.

Fix strategy
------------
1. Explicit **origin allow-list** — only origins present in a configured set
   are ever granted access. Unknown origins get no CORS allow headers at all
   (the browser will then block the cross-origin read).
2. When credentials are required, ``Access-Control-Allow-Origin`` is set to
   the *exact* matched origin (never ``*``), which is required by the CORS
   spec for credentialed requests to work, and only after the whitelist
   check passes.
3. ``Access-Control-Allow-Credentials`` is **never** set to ``true`` together
   with a wildcard ``Access-Control-Allow-Origin: *``. If a caller does not
   need credentials, and no exact origin match exists, a wildcard may be
   returned but only without the credentials header.
4. ``Vary: Origin`` is always added when the response varies based on the
   incoming ``Origin`` header, so shared caches/CDNs don't serve one origin's
   CORS-approved response to a different origin.

The implementation is dependency-free (stdlib only) so it can be wired into
any WSGI/ASGI/Flask/FastAPI/Django middleware.

Usage:
    policy = CORSPolicy(
        allowed_origins={"https://app.example.com", "https://admin.example.com"},
        allow_credentials=True,
    )

    headers = policy.build_headers(request_origin=request.headers.get("Origin"))
    for key, value in headers.items():
        response.headers[key] = value
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Optional


@dataclass
class CORSPolicy:
    """Origin-whitelist based CORS header generator.

    Parameters
    ----------
    allowed_origins:
        Exact-match set of origins (scheme + host + optional port) that are
        permitted to make cross-origin requests, e.g.
        ``{"https://app.example.com"}``. No wildcard matching is performed
        here on purpose — subdomain/suffix matching is a common source of
        bypasses (e.g. ``evil-example.com`` matching a naive ``.example.com``
        check).
    allow_credentials:
        Whether the API needs cookies / Authorization headers to be sent
        cross-origin. When True, a matched origin is always echoed back
        explicitly (never ``*``) and
        ``Access-Control-Allow-Credentials: true`` is included only for
        whitelisted origins.
    allow_methods:
        Methods advertised via ``Access-Control-Allow-Methods`` for preflight
        responses.
    allow_headers:
        Headers advertised via ``Access-Control-Allow-Headers`` for preflight
        responses.
    max_age_seconds:
        Value for ``Access-Control-Max-Age`` on preflight responses.
    """

    allowed_origins: FrozenSet[str]
    allow_credentials: bool = False
    allow_methods: FrozenSet[str] = field(
        default_factory=lambda: frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
    )
    allow_headers: FrozenSet[str] = field(
        default_factory=lambda: frozenset({"Content-Type", "Authorization"})
    )
    max_age_seconds: int = 600

    def __post_init__(self) -> None:
        # Normalize once so lookups are case-insensitive on scheme/host but
        # still exact (no substring / suffix matching allowed).
        self.allowed_origins = frozenset(o.strip().rstrip("/").lower() for o in self.allowed_origins if o)

    def _is_allowed(self, origin: Optional[str]) -> bool:
        if not origin:
            return False
        return origin.strip().rstrip("/").lower() in self.allowed_origins

    def build_headers(
        self,
        request_origin: Optional[str],
        is_preflight: bool = False,
        requested_method: Optional[str] = None,
        requested_headers: Optional[str] = None,
    ) -> Dict[str, str]:
        """Build the set of CORS response headers for a given request Origin.

        Returns an empty-ish dict (only ``Vary: Origin``) for origins that are
        not on the whitelist, meaning the browser will refuse to expose the
        response to that origin's JavaScript.
        """
        headers: Dict[str, str] = {
            # Always present: tells caches the response depends on Origin,
            # preventing origin A's approved response from being served to
            # origin B from a shared cache.
            "Vary": "Origin",
        }

        if not self._is_allowed(request_origin):
            # Do not reflect unknown origins. No Allow-Origin header means
            # the browser blocks cross-origin script access to the response.
            return headers

        # Origin is whitelisted -> always echo back the *exact* origin, never
        # a wildcard, so this branch is safe to combine with credentials.
        headers["Access-Control-Allow-Origin"] = request_origin  # type: ignore[assignment]

        if self.allow_credentials:
            # Spec forbids `Access-Control-Allow-Credentials: true` together
            # with a wildcard Allow-Origin. Since we only ever set an exact
            # origin above, it is always safe to include this here.
            headers["Access-Control-Allow-Credentials"] = "true"

        if is_preflight:
            headers["Access-Control-Allow-Methods"] = ", ".join(sorted(self.allow_methods))
            headers["Access-Control-Allow-Headers"] = ", ".join(sorted(self.allow_headers))
            headers["Access-Control-Max-Age"] = str(self.max_age_seconds)

        return headers

    def build_public_headers(self, request_origin: Optional[str]) -> Dict[str, str]:
        """For endpoints that serve fully public, non-credentialed data only.

        Falls back to ``*`` when the origin is not on the whitelist, but this
        is only ever safe because credentials are never included in this
        path — ``Access-Control-Allow-Credentials`` is guaranteed absent.
        """
        if self.allow_credentials:
            raise ValueError(
                "build_public_headers() must not be used when allow_credentials=True; "
                "a wildcard Allow-Origin can never be combined with credentials"
            )

        headers: Dict[str, str] = {"Vary": "Origin"}
        if self._is_allowed(request_origin):
            headers["Access-Control-Allow-Origin"] = request_origin  # type: ignore[assignment]
        else:
            headers["Access-Control-Allow-Origin"] = "*"
        # Explicitly ensure credentials header is never emitted here.
        headers.pop("Access-Control-Allow-Credentials", None)
        return headers


# --------------------------------------------------------------------- self-test
if __name__ == "__main__":
    policy = CORSPolicy(
        allowed_origins={"https://app.example.com", "https://admin.example.com"},
        allow_credentials=True,
    )

    # Whitelisted origin: exact reflection + credentials + Vary.
    headers = policy.build_headers("https://app.example.com")
    assert headers["Access-Control-Allow-Origin"] == "https://app.example.com"
    assert headers["Access-Control-Allow-Credentials"] == "true"
    assert headers["Vary"] == "Origin"

    # Attacker origin: no allow-origin header at all.
    blocked = policy.build_headers("https://evil.attacker.com")
    assert "Access-Control-Allow-Origin" not in blocked
    assert "Access-Control-Allow-Credentials" not in blocked
    assert blocked["Vary"] == "Origin"

    # Never combine wildcard with credentials.
    public_policy = CORSPolicy(allowed_origins=set(), allow_credentials=False)
    public_headers = public_policy.build_public_headers("https://anyone.example.com")
    assert public_headers["Access-Control-Allow-Origin"] == "*"
    assert "Access-Control-Allow-Credentials" not in public_headers
    assert public_headers["Vary"] == "Origin"

    # Public policy raises if misused with credentials enabled.
    try:
        CORSPolicy(allowed_origins=set(), allow_credentials=True).build_public_headers("https://x.com")
        raise AssertionError("expected ValueError")
    except ValueError:
        pass

    print("cors_origin_whitelist_fix self-test passed")
