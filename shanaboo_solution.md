```diff
--- a/fixes/host_header_injection_fix.py
+++ b/fixes/host_header_injection_fix.py
@@ -1,9 +1,9 @@
 """
-Fix for Issue #112 — Host Header Injection for Cache Poisoning
-==============================================================
+Fix for Issue #112 — Host Header Injection → Password Reset Poisoning
+=====================================================================
 
 Vulnerability
 -------------
 Web applications that trust the inbound ``Host`` header (or its proxy
 equivalents: ``X-Forwarded-Host``, ``X-Host``, ``X-Forwarded-Server``,
 ``Forwarded``) when building absolute URLs, password-reset links, OAuth
@@ -12,7 +12,7 @@
 1. **Host Header Injection** — an attacker rewrites the host used in
    server-generated links (e.g. ``https://evil.tld/reset?token=...``)
    to phish victims or hijack tokens.
-2. **Web-Cache Poisoning** — a CDN/proxy caches a response keyed on the
+2. **Password Reset Poisoning** — a CDN/proxy caches a response keyed on the
    path but with attacker-controlled content in the body (because the
    app reflected the bad host into a link or canonical tag), then
    serves that poisoned response to every subsequent visitor.
@@ -22,7 +22,7 @@
 intermediaries forward attacker-controlled ``X-Forwarded-*`` headers
 verbatim unless the app strips/validates them.
 
-Fix Strategy
+Fix Strategy (Password Reset Poisoning Focus)
 ------------
 1. Maintain an explicit allow-list of trusted hostnames (and optional
    ports) configured out-of-band — never inferred from the request.
@@ -32,7 +32,7 @@
    credentials, or non-ASCII bytes (defends against smuggling +
    header-injection chains).
 4. Provide a single ``safe_external_url()`` helper so application code
-   never concatenates ``request.host`` into URLs directly.
+   never concatenates ``request.host`` into password-reset URLs directly.
 5. Cache keys that vary on host MUST use the *validated* host, never
    the raw header.
 
@@ -40,7 +40,7 @@
 Django/aiohttp request objects.
 """
 
 from __future__ import annotations
 
 import ipaddress
@@ -48,7 +48,7 @@
 from dataclasses import dataclass, field
 from typing import Iterable, Mapping, Optional, Tuple
 from urllib.parse import quote, urlsplit, urlunsplit
 
 # RFC 3986 reg-name + optional :port. Disallows CR/LF, spaces, '@', '/'
@@ -56,7 +56,7 @@
 _HOST_RE = re.compile(
     r"^(?P<host>[A-Za-z0-9](?:[A-Za-z0-9\-\.]{0,253}[A-Za-z0-9])?)"
     r"(?::(?P<port>[0-9]{1,5}))?$"
 )
 
@@ -64,7 +64,7 @@
 # validated before use.
 _HOST_HEADERS = (
     "host",
     "x-forwarded-host",
     "x-forwarded-server",
@@ -72,7 +72,7 @@
     "x-original-host",
     "forwarded",  # RFC 7239
 )
 
 
 class HostValidationError(ValueError):
@@ -80,7 +80,7 @@
 
 
 @dataclass(frozen=True)
 class TrustedHost:
     """A single entry in the allow-list."""
@@ -88,7 +88,7 @@
     hostname: str
     port: Optional[int] = None  # None = any port
 
     def matches(self, host: str, port: Optional[int]) -> bool:
         if host.lower() != self.hostname.lower():
@@ -96,7 +96,7 @@
         if self.port is None:
             return True
         return port == self.port
 
 
 @dataclass(frozen=True)
@@ -104,7 +104,7 @@
     """Immutable allow-list policy. Construct once at app startup."""
 
     trusted: Tuple[TrustedHost, ...] = field(default_factory=tuple)
     allow_ip_literals: bool = False  # only enable for internal tools
 
@@ -112,7 +112,7 @@
     def from_iterable(cls, hosts: Iterable[str], *, allow_ip_literals: bool = False) -> "HostPolicy":
         parsed: list[TrustedHost] = []
         for raw in hosts:
             h, p = _parse_host_port(raw, allow_ip_literals=allow_ip_literals)
             parsed.append(TrustedHost(h.lower(), p))
@@ -120,7 +120,7 @@
             raise ValueError("HostPolicy requires at least one trusted host")
         return cls(tuple(parsed), allow_ip_literals)
 
     def is_allowed(self, host: str, port: Optional[int]) -> bool:
         return any(t.matches(host, port) for t in self.trusted)
@@ -128,7 +128,7 @@
 
 def _parse_host_port(raw: str,
                      *,
                      allow_ip_literals: bool = False) -> Tuple[str, Optional[int]]:
     """Parse a host[:port] string, validating format."""
@@ -136,7 +136,7 @@
     m = _HOST_RE.match(raw)
     if not m:
         raise HostValidationError(f"Invalid host format: {raw!r}")
     host = m.group("host")
@@ -144,7 +144,7 @@
     port_str = m.group("port")
     port = int(port_str) if port_str else None
     if port is not None and not (1 <= port <= 65535):
         raise HostValidationError(f"Port out of range: {port}")
@@ -152,7 +152,7 @@
     # Reject IP literals unless explicitly allowed
     if not allow_ip_literals:
         try:
             ipaddress.ip_address(host)
             raise HostValidationError(f"IP literals not allowed: {host!r}")
@@ -160,7 +160,7 @@
             pass  # not an IP, OK
     return host, port
 
 
 def validate_request_host(
@@ -168,7 +168,7 @@
     headers: Mapping[str, str],
     policy: HostPolicy,
     *,
     default_host: Optional[str] = None,
 ) -> str:
@@ -176,7 +176,7 @@
     """
     Validate the Host header (and proxy variants) against the allow-list.
 
     Returns the canonical hostname to use for URL generation.
@@ -184,7 +184,7 @@
     Raises HostValidationError if no valid host is found.
     """
     #