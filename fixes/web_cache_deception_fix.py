"""
Fix for Issue — Web Cache Deception -> Session Token Leak ($150 bounty).

Root cause
----------
The CDN was configured to cache static assets based on a URL-extension
heuristic (e.g. "anything under /assets/ ending in .css is cacheable").
Because many application frameworks route arbitrary sub-paths to the same
handler, an attacker can craft a URL such as:

    /account/settings/nonexistent.css

The origin server 404s / falls through to the authenticated settings page
and renders it as HTML (containing session tokens, CSRF tokens, or other
PII) -- but because the *path* ends in ".css", the CDN caches the response
as if it were a static stylesheet. The attacker (or any other user) can then
read the cached response and steal the victim's session data.

This is a classic **Web Cache Deception** (CWE-524 / CAPEC-663) attack: the
cache makes a caching decision using an untrusted, attacker-influenced
signal (the request path/extension) instead of validating what the origin
actually returned.

Fix strategy
------------
1. **Cache keys must include the response `Content-Type`.** A response can
   never be served from the cache to satisfy a request unless the stored
   `Content-Type` matches what would be produced for a fresh request. This
   means an HTML response accidentally cached under a `.css`-suffixed path
   can never be misinterpreted as, or reused for, a legitimate `.css`
   request.
2. **Sensitive / authenticated pages always emit `Cache-Control: no-store`**
   (plus `Pragma: no-cache` and `X-Content-Type-Options: nosniff`),
   independent of the request path's apparent extension. This is
   defense-in-depth: even if the CDN policy is misconfigured, the origin
   refuses to let intermediaries store the response at all.
3. **CDN path policy explicitly excludes authentication/account paths**
   from caching, and only allows caching for known static-asset path
   prefixes *and only when the actual Content-Type matches an expected
   static MIME type*. Caching is denied by default (fail closed).

Drop-in usage: call `is_cacheable()` / `build_cache_key()` from the CDN edge
logic (or from an origin-side response filter that sets the appropriate
headers), and call `apply_sensitive_page_headers()` from any
authentication/account/session handler.
"""

from __future__ import annotations

import unittest
from dataclasses import dataclass, field
from typing import FrozenSet, Mapping, MutableMapping, Optional, Tuple
from urllib.parse import urlsplit


# ---------------------------------------------------------------------------
# Policy configuration
# ---------------------------------------------------------------------------

# Path prefixes that are considered "static asset" territory and are
# eligible for CDN caching -- but ONLY if the Content-Type also matches
# (see STATIC_CONTENT_TYPES below). This replaces extension-based matching.
STATIC_PATH_PREFIXES: FrozenSet[str] = frozenset({
    "/assets/",
    "/static/",
    "/public/",
    "/dist/",
})

# Content-Types that are legitimately cacheable as static assets.
STATIC_CONTENT_TYPES: FrozenSet[str] = frozenset({
    "text/css",
    "application/javascript",
    "text/javascript",
    "application/json",  # only for known static json manifests under STATIC_PATH_PREFIXES
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/svg+xml",
    "image/webp",
    "font/woff",
    "font/woff2",
    "application/font-woff",
})

# Path prefixes / exact paths that must NEVER be cached, regardless of
# Content-Type. This is the authoritative "authentication / sensitive
# pages" exclusion list required by the fix.
SENSITIVE_PATH_PREFIXES: FrozenSet[str] = frozenset({
    "/account/",
    "/settings/",
    "/session/",
    "/auth/",
    "/oauth/",
    "/admin/",
    "/api/private/",
})

SENSITIVE_EXACT_PATHS: FrozenSet[str] = frozenset({
    "/login",
    "/logout",
    "/settings",
    "/account",
    "/session",
    "/2fa",
    "/password/reset",
})


def _normalize_path(path: str) -> str:
    """Split off query/fragment and strip trailing slashes consistently
    (but keep a single leading slash) so prefix checks are reliable."""
    parts = urlsplit(path)
    p = parts.path or "/"
    if not p.startswith("/"):
        p = "/" + p
    return p


def _is_sensitive_path(path: str) -> bool:
    p = _normalize_path(path)
    if p in SENSITIVE_EXACT_PATHS:
        return True
    return any(p.startswith(prefix) for prefix in SENSITIVE_PATH_PREFIXES)


def _is_static_path(path: str) -> bool:
    p = _normalize_path(path)
    return any(p.startswith(prefix) for prefix in STATIC_PATH_PREFIXES)


# ---------------------------------------------------------------------------
# Cache key construction (Content-Type-aware)
# ---------------------------------------------------------------------------

def build_cache_key(path: str, query: str, content_type: str) -> str:
    """Return a cache key that varies on the response Content-Type.

    This is the core structural fix: the CDN can no longer conflate an
    HTML response with a static asset merely because the URL happens to
    end in ".css" -- the actual Content-Type returned by the origin is
    baked into the key, so a poisoned entry (HTML cached under a
    `.css`-looking path) can never satisfy a legitimate request for that
    path with a *different* Content-Type, and vice-versa.
    """
    normalized_type = (content_type or "").split(";")[0].strip().lower()
    p = _normalize_path(path)
    return f"{p}|{query}|{normalized_type}"


def is_cacheable(path: str, content_type: str) -> bool:
    """Return True only if this (path, content_type) pair is eligible for
    CDN caching under the fail-closed policy:

      1. Sensitive/authentication paths are NEVER cacheable, no matter
         what Content-Type the origin returns (blocks the deception).
      2. Only requests under a known static-asset path prefix AND whose
         actual Content-Type is a known static MIME type are cacheable.
      3. Everything else defaults to not cacheable (fail closed).
    """
    if _is_sensitive_path(path):
        return False

    normalized_type = (content_type or "").split(";")[0].strip().lower()
    if not _is_static_path(path):
        return False
    if normalized_type not in STATIC_CONTENT_TYPES:
        return False
    return True


# ---------------------------------------------------------------------------
# Response header helpers
# ---------------------------------------------------------------------------

def apply_sensitive_page_headers(
    headers: MutableMapping[str, str],
    path: Optional[str] = None,
) -> MutableMapping[str, str]:
    """Force no-store caching + MIME-sniffing protection on a response.

    Call this from any authentication/account/session handler (or, as
    defense-in-depth, unconditionally from a global response filter --
    it is safe to apply to every response). ``path`` is optional and only
    used to decide whether to *skip* forcing no-store for genuinely
    static asset responses when this helper is applied globally.
    """
    if path is not None and _is_static_path(path):
        # Do not clobber legitimate static-asset caching headers.
        return headers

    headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    headers["Pragma"] = "no-cache"
    headers["X-Content-Type-Options"] = "nosniff"
    return headers


def apply_static_asset_headers(
    headers: MutableMapping[str, str],
    content_type: str,
) -> MutableMapping[str, str]:
    """Set headers for a genuinely static, cacheable asset response.

    Always sets X-Content-Type-Options so intermediaries/browsers never
    MIME-sniff a response into a different type than what was cached.
    """
    headers["X-Content-Type-Options"] = "nosniff"
    normalized_type = (content_type or "").split(";")[0].strip().lower()
    if normalized_type in STATIC_CONTENT_TYPES:
        headers["Cache-Control"] = "public, max-age=86400, immutable"
    else:
        # Should not happen if is_cacheable() gated this call, but fail safe.
        headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    return headers


# ---------------------------------------------------------------------------
# CDN edge decision entry point
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CDNDecision:
    cacheable: bool
    cache_key: Optional[str]
    headers: Mapping[str, str] = field(default_factory=dict)


def evaluate_response_for_cdn(
    path: str,
    query: str,
    content_type: str,
) -> CDNDecision:
    """Single entry point the CDN/edge logic (or an origin response
    filter) should call for every outbound response.

    Returns a decision object describing whether the response may be
    cached, the Content-Type-aware cache key (if cacheable), and the
    headers that must be attached to the response either way.
    """
    headers: MutableMapping[str, str] = {}

    if not is_cacheable(path, content_type):
        apply_sensitive_page_headers(headers, path=None)
        return CDNDecision(cacheable=False, cache_key=None, headers=headers)

    apply_static_asset_headers(headers, content_type)
    key = build_cache_key(path, query, content_type)
    return CDNDecision(cacheable=True, cache_key=key, headers=headers)


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

class WebCacheDeceptionTests(unittest.TestCase):
    def test_legit_static_asset_is_cacheable(self):
        decision = evaluate_response_for_cdn("/assets/app.css", "", "text/css")
        self.assertTrue(decision.cacheable)
        self.assertIsNotNone(decision.cache_key)
        self.assertIn("text/css", decision.cache_key)
        self.assertEqual(decision.headers["X-Content-Type-Options"], "nosniff")

    def test_deceptive_css_suffixed_account_path_not_cached(self):
        # The core exploit: /account/settings/nonexistent.css renders HTML.
        decision = evaluate_response_for_cdn(
            "/account/settings/nonexistent.css", "", "text/html"
        )
        self.assertFalse(decision.cacheable)
        self.assertIsNone(decision.cache_key)
        self.assertIn("no-store", decision.headers["Cache-Control"])

    def test_sensitive_path_never_cacheable_even_with_static_content_type(self):
        # Even if somehow the origin returned text/css for an account path,
        # it must still be denied because the path is sensitive.
        decision = evaluate_response_for_cdn(
            "/account/settings/style.css", "", "text/css"
        )
        self.assertFalse(decision.cacheable)
        self.assertIn("no-store", decision.headers["Cache-Control"])

    def test_auth_pages_excluded(self):
        for path in ("/login", "/logout", "/settings", "/auth/callback"):
            decision = evaluate_response_for_cdn(path, "", "text/html")
            self.assertFalse(decision.cacheable, path)
            self.assertIn("no-store", decision.headers["Cache-Control"], path)

    def test_cache_key_varies_by_content_type(self):
        key_css = build_cache_key("/assets/app.css", "", "text/css")
        key_html = build_cache_key("/assets/app.css", "", "text/html")
        self.assertNotEqual(key_css, key_html)

    def test_non_static_content_type_under_static_prefix_not_cached(self):
        # /assets/whoami returning HTML must not be cached even though the
        # path is under a normally-static prefix.
        decision = evaluate_response_for_cdn("/assets/whoami", "", "text/html")
        self.assertFalse(decision.cacheable)

    def test_apply_sensitive_page_headers_sets_nosniff_and_no_store(self):
        headers: dict = {}
        apply_sensitive_page_headers(headers)
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("no-store", headers["Cache-Control"])
        self.assertEqual(headers["Pragma"], "no-cache")

    def test_static_asset_headers_do_not_get_overwritten_globally(self):
        headers = {"Cache-Control": "public, max-age=86400, immutable"}
        apply_sensitive_page_headers(headers, path="/assets/app.css")
        self.assertEqual(headers["Cache-Control"], "public, max-age=86400, immutable")


def _run_self_tests() -> None:  # pragma: no cover - executed via __main__
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(WebCacheDeceptionTests)
    result = unittest.TextTestRunner(verbosity=0).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    print("OK — all web cache deception defences verified.")


if __name__ == "__main__":
    _run_self_tests()
