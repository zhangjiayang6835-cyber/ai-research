"""
Fix for Issue #98: Session Token in URL

VULNERABILITY
-------------
Session identifiers, bearer tokens, JWTs, API keys, and refresh tokens must not
be accepted in URL query strings. URLs are copied into browser history, server
access logs, reverse-proxy logs, analytics tools, crash reports, bookmarks, and
Referer headers. A token in the URL can therefore be disclosed to parties that
should never see credential material.

FIX
---
Reject token-like query parameters at the request boundary and only accept
session credentials from secure channels such as HttpOnly Secure cookies or
Authorization headers. This module provides:

  * case-insensitive detection of common token-bearing query parameters;
  * a helper to strip sensitive parameters from redirect/canonical URLs;
  * WSGI middleware that blocks unsafe requests before the application handles
    them;
  * secure cookie defaults for an explicit one-time token migration flow.

Drop-in WSGI usage:

    from fixes.session_token_url_fix import SessionTokenURLGuard

    app = SessionTokenURLGuard(app)

The guard is dependency-free and works on Python 3.8+.
"""

from __future__ import annotations

from dataclasses import dataclass
from http.cookies import SimpleCookie
from typing import Callable, Iterable, Mapping, MutableMapping, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


DEFAULT_SENSITIVE_QUERY_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "bearer",
        "id_token",
        "jwt",
        "refresh_token",
        "session",
        "session_id",
        "session_token",
        "sid",
        "token",
    }
)

NO_STORE_HEADERS = (
    ("Cache-Control", "no-store"),
    ("Pragma", "no-cache"),
    ("Referrer-Policy", "no-referrer"),
)


class SessionTokenInUrlError(ValueError):
    """Raised when a URL contains token-like query parameters."""


@dataclass(frozen=True)
class SanitizedURL:
    """Result of removing credential-bearing parameters from a URL."""

    url: str
    removed_keys: Tuple[str, ...]

    @property
    def changed(self) -> bool:
        return bool(self.removed_keys)


def _normalize_key(key: str) -> str:
    return key.strip().lower().replace("-", "_")


def _sensitive_key_set(keys: Iterable[str]) -> frozenset[str]:
    return frozenset(_normalize_key(key) for key in keys)


def is_sensitive_query_key(
    key: str,
    sensitive_keys: Iterable[str] = DEFAULT_SENSITIVE_QUERY_KEYS,
) -> bool:
    """Return True when a query parameter name is unsafe for URL transport."""

    return _normalize_key(key) in _sensitive_key_set(sensitive_keys)


def strip_sensitive_query_params(
    url: str,
    sensitive_keys: Iterable[str] = DEFAULT_SENSITIVE_QUERY_KEYS,
) -> SanitizedURL:
    """Remove token-like query parameters while preserving all safe parameters.

    The helper keeps parameter ordering for non-sensitive keys and preserves the
    URL path and fragment. It is safe to use when building redirect targets or
    canonical URLs after rejecting an unsafe request.
    """

    parts = urlsplit(url)
    removed = []
    kept = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if is_sensitive_query_key(key, sensitive_keys):
            removed.append(key)
        else:
            kept.append((key, value))

    clean_query = urlencode(kept, doseq=True)
    clean_url = urlunsplit(
        (parts.scheme, parts.netloc, parts.path, clean_query, parts.fragment)
    )
    return SanitizedURL(url=clean_url, removed_keys=tuple(removed))


def reject_session_tokens_in_url(
    url: str,
    sensitive_keys: Iterable[str] = DEFAULT_SENSITIVE_QUERY_KEYS,
) -> None:
    """Raise if a URL carries session/token material in its query string."""

    result = strip_sensitive_query_params(url, sensitive_keys)
    if result.changed:
        keys = ", ".join(sorted({key.lower() for key in result.removed_keys}))
        raise SessionTokenInUrlError(
            f"Session or credential token must not be sent in URL query "
            f"parameters: {keys}"
        )


def build_secure_session_cookie(
    name: str,
    value: str,
    *,
    max_age: Optional[int] = None,
    same_site: str = "Lax",
    path: str = "/",
) -> str:
    """Build an HttpOnly Secure cookie for server-side session transport."""

    if not name or is_sensitive_query_key(name):
        # Cookie names such as "session" are fine for cookies, but this helper
        # is intentionally explicit to avoid reusing raw query names as-is.
        name = "session_id"

    cookie = SimpleCookie()
    cookie[name] = value
    morsel = cookie[name]
    morsel["httponly"] = True
    morsel["secure"] = True
    morsel["samesite"] = same_site
    morsel["path"] = path
    if max_age is not None:
        morsel["max-age"] = str(max_age)
    return morsel.OutputString()


def migrate_one_time_token_to_cookie(
    url: str,
    *,
    token_param: str = "one_time_token",
    cookie_name: str = "session_id",
    max_age: int = 300,
) -> Tuple[str, Optional[str]]:
    """Exchange one explicit transition token for a secure cookie header.

    This is for compatibility callbacks only. Long-lived session identifiers
    should never be minted into URLs. After this exchange, redirect to the
    returned clean URL and invalidate the one-time token server-side.
    """

    parts = urlsplit(url)
    token_param_norm = _normalize_key(token_param)
    token_value = None
    kept = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if _normalize_key(key) == token_param_norm:
            token_value = value
        else:
            kept.append((key, value))

    clean_url = urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            urlencode(kept, doseq=True),
            parts.fragment,
        )
    )
    if token_value is None:
        return clean_url, None
    return clean_url, build_secure_session_cookie(
        cookie_name,
        token_value,
        max_age=max_age,
    )


class SessionTokenURLGuard:
    """WSGI middleware that rejects credential-bearing query parameters."""

    def __init__(
        self,
        app: Callable,
        *,
        sensitive_keys: Iterable[str] = DEFAULT_SENSITIVE_QUERY_KEYS,
        error_body: bytes = b"Session token must not be sent in the URL.\n",
    ) -> None:
        self.app = app
        self.sensitive_keys = _sensitive_key_set(sensitive_keys)
        self.error_body = error_body

    def __call__(self, environ: MutableMapping[str, str], start_response: Callable):
        query = environ.get("QUERY_STRING", "")
        url = "https://local.invalid/?" + query
        result = strip_sensitive_query_params(url, self.sensitive_keys)
        if result.changed:
            start_response(
                "400 Bad Request",
                [
                    ("Content-Type", "text/plain; charset=utf-8"),
                    *NO_STORE_HEADERS,
                ],
            )
            return [self.error_body]
        return self.app(environ, start_response)


def _demo_app(environ: Mapping[str, str], start_response: Callable):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"ok"]


if __name__ == "__main__":
    # Detection is case-insensitive and catches common token parameter names.
    for unsafe in (
        "https://app.example/callback?session_token=abc",
        "https://app.example/callback?Access-Token=abc",
        "https://app.example/callback?jwt=header.payload.sig",
        "https://app.example/callback?sid=abc",
    ):
        try:
            reject_session_tokens_in_url(unsafe)
        except SessionTokenInUrlError:
            pass
        else:
            raise AssertionError(f"unsafe URL was accepted: {unsafe}")

    # Safe parameters survive in order; sensitive parameters are removed.
    cleaned = strip_sensitive_query_params(
        "https://app.example/search?q=hat&token=secret&page=2#top"
    )
    assert cleaned.url == "https://app.example/search?q=hat&page=2#top"
    assert cleaned.removed_keys == ("token",)

    # Normal URLs are accepted unchanged.
    normal = "https://app.example/search?q=hat&page=2"
    assert strip_sensitive_query_params(normal).url == normal
    reject_session_tokens_in_url(normal)

    # One-time transition token is removed and converted to a secure cookie.
    clean_url, cookie = migrate_one_time_token_to_cookie(
        "https://app.example/callback?one_time_token=abc123&next=%2Fdashboard"
    )
    assert clean_url == "https://app.example/callback?next=%2Fdashboard"
    assert cookie is not None
    assert "abc123" in cookie
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite=Lax" in cookie

    # WSGI middleware blocks unsafe requests and allows normal traffic.
    events = []

    def capture_start(status, headers):
        events.append((status, dict(headers)))

    guard = SessionTokenURLGuard(_demo_app)
    blocked_body = b"".join(
        guard({"QUERY_STRING": "token=abc"}, capture_start)
    )
    assert events[-1][0] == "400 Bad Request"
    assert events[-1][1]["Cache-Control"] == "no-store"
    assert blocked_body.startswith(b"Session token")

    allowed_body = b"".join(
        guard({"QUERY_STRING": "q=public&page=1"}, capture_start)
    )
    assert events[-1][0] == "200 OK"
    assert allowed_body == b"ok"

    print("OK - session_token_url_fix self-tests passed")
