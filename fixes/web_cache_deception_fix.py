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
        # Content-Type does not match a known static asset type -- refuse
        # to advertise this response as publicly cacheable, even if the
        # request path looked like a static asset. Fail closed.
        headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        headers["Pragma"] = "no-cache"
    return headers


# ---------------------------------------------------------------------------
# CDN cache rule descriptor
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CDNCacheRule:
    """Declarative description of a single CDN caching decision.

    ``allowed_content_types`` defaults to :data:`STATIC_CONTENT_TYPES` and
    ``sensitive_prefixes`` defaults to :data:`SENSITIVE_PATH_PREFIXES` so
    callers can override the policy per-rule (e.g. for testing) without
    mutating the module-level constants.
    """

    path: str
    content_type: str
    allowed_content_types: FrozenSet[str] = field(default_factory=lambda: STATIC_CONTENT_TYPES)
    sensitive_prefixes: FrozenSet[str] = field(default_factory=lambda: SENSITIVE_PATH_PREFIXES)

    def evaluate(self) -> Tuple[bool, str]:
        """Return ``(cacheable, reason)`` for this rule."""
        p = _normalize_path(self.path)
        if p in SENSITIVE_EXACT_PATHS or any(p.startswith(prefix) for prefix in self.sensitive_prefixes):
            return False, "sensitive_path"
        if not _is_static_path(p):
            return False, "not_static_path"
        normalized_type = (self.content_type or "").split(";")[0].strip().lower()
        if normalized_type not in self.allowed_content_types:
            return False, "content_type_mismatch"
        return True, "ok"


def build_cdn_policy_table(rules: Mapping[str, str]) -> Tuple[CDNCacheRule, ...]:
    """Convenience builder: turn a ``{path: content_type}`` mapping into a
    tuple of :class:`CDNCacheRule` instances for bulk evaluation/testing.
    """
    return tuple(CDNCacheRule(path=p, content_type=ct) for p, ct in rules.items())


# ---------------------------------------------------------------------------
# Self-contained regression tests
# ---------------------------------------------------------------------------

class WebCacheDeceptionFixTests(unittest.TestCase):
    def test_static_css_under_assets_is_cacheable(self) -> None:
        self.assertTrue(is_cacheable("/assets/app.css", "text/css"))

    def test_deceptive_path_with_html_content_type_is_not_cacheable(self) -> None:
        # The classic attack: /account/settings/nonexistent.css but the
        # origin actually returns the HTML settings page.
        self.assertFalse(is_cacheable("/account/settings/nonexistent.css", "text/html"))

    def test_sensitive_path_never_cacheable_even_with_static_content_type(self) -> None:
        self.assertFalse(is_cacheable("/account/settings", "text/css"))

    def test_non_static_path_defaults_closed(self) -> None:
        self.assertFalse(is_cacheable("/whatever/thing.css", "text/css"))

    def test_cache_key_varies_by_content_type(self) -> None:
        key_css = build_cache_key("/assets/app.css", "", "text/css")
        key_html = build_cache_key("/assets/app.css", "", "text/html")
        self.assertNotEqual(key_css, key_html)

    def test_sensitive_headers_force_no_store(self) -> None:
        headers: MutableMapping[str, str] = {}
        apply_sensitive_page_headers(headers, path="/account/settings")
        self.assertIn("no-store", headers["Cache-Control"])
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_static_asset_headers_allow_caching_for_matching_type(self) -> None:
        headers: MutableMapping[str, str] = {}
        apply_static_asset_headers(headers, "text/css")
        self.assertIn("public", headers["Cache-Control"])
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_static_asset_headers_fail_closed_for_mismatched_type(self) -> None:
        headers: MutableMapping[str, str] = {}
        apply_static_asset_headers(headers, "text/html")
        self.assertIn("no-store", headers["Cache-Control"])

    def test_cdn_cache_rule_evaluate(self) -> None:
        rule = CDNCacheRule(path="/account/settings/nonexistent.css", content_type="text/html")
        cacheable, reason = rule.evaluate()
        self.assertFalse(cacheable)
        self.assertEqual(reason, "sensitive_path")


if __name__ == "__main__":
    unittest.main()
