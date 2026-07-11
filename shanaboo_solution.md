```diff
--- a/fixes/host_header_injection_fix.py
+++ b/fixes/host_header_injection_fix.py
@@ -1,5 +1,5 @@
 """
-Fix for Issue #112 — Host Header Injection for Cache Poisoning
+Fix for Issue #112 — Host Header Injection → Password Reset Poisoning
 ==============================================================
 
 Vulnerability
@@ -8,7 +8,7 @@
 equivalents: ``X-Forwarded-Host``, ``X-Host``, ``X-Forwarded-Server``,
 ``Forwarded``) when building absolute URLs, password-reset links, OAuth
 redirect URIs, or cache keys are exposed to two related attacks:
-
+ 
 1. **Host Header Injection** — an attacker rewrites the host used in
    server-generated links (e.g. ``https://evil.tld/reset?token=...``)
    to phish victims or hijack tokens.
@@ -16,7 +16,7 @@
    path but with attacker-controlled content in the body (because the
    app reflected the bad host into a link or canonical tag), then
    serves that poisoned response to every subsequent visitor.
-
+ 
 Root cause: the application accepts whatever host the client sends.
 The HTTP/1.1 spec allows arbitrary text in the ``Host`` header, and
 intermediaries forward attacker-controlled ``X-Forwarded-*`` headers
@@ -24,7 +24,7 @@
 
 Fix Strategy
 ------------
-1. Maintain an explicit allow-list of trusted hostnames (and optional
+1. Maintain an explicit allow-list of trusted hostnames (and optional 
    ports) configured out-of-band — never inferred from the request.
 2. Validate every host-bearing header against the allow-list using a
    strict, case-insensitive, port-aware comparison.
@@ -33,7 +33,7 @@
    header-injection chains).
 4. Provide a single ``safe_external_url()`` helper so application code
    never concatenates ``request.host`` into URLs directly.
-5. Cache keys that vary on host MUST use the *validated* host, never
+5. Cache keys that vary on host MUST use the *validated* host, never 
    the raw header.
 
 This module is framework-agnostic — drop in next to Flask/FastAPI/
@@ -44,7 +44,7 @@
 
 import ipaddress
 import re
-from dataclasses import dataclass, field
+from dataclasses import dataclass, field, asdict
 from typing import Iterable, Mapping, Optional, Tuple
 from urllib.parse import quote, urlsplit, urlunsplit
 
@@ -52,7 +52,7 @@
 # (which would smuggle userinfo or path), and any non-ASCII byte.
 _HOST_RE = re.compile(
     r"^(?P<host>[A-Za-z0-9](?:[A-Za-z0-9\-\.]{0,253}[A-Za-z0-9])?)"
-    r"(?::(?P<port>[0-9]{1,5}))?$"
+    r"(?::(?P<port>[0-9]{1,5}))?$",
 )
 
 # Headers that can carry a client-supplied host. All are stripped or
@@ -66,6 +66,7 @@
 )
 
 
+
 class HostValidationError(ValueError):
     """Raised when an inbound host header fails validation."""
 
@@ -75,7 +76,7 @@
     """A single entry in the allow-list."""
 
     hostname: str
-    port: Optional[int] = None  # None = any port
+    port: Optional[int] = None  # None = any port matches
 
     def matches(self, host: str, port: Optional[int]) -> bool:
         if host.lower() != self.hostname.lower():
@@ -91,7 +92,7 @@
     trusted: Tuple[TrustedHost, ...] = field(default_factory=tuple)
     allow_ip_literals: bool = False  # only enable for internal tools
 
-    @classmethod
+    @classmethod 
     def from_iterable(cls, hosts: Iterable[str], *, allow_ip_literals: bool = False) -> "HostPolicy":
         parsed: list[TrustedHost] = []
         for raw in hosts:
@@ -104,4 +105,169 @@
     def is_allowed(self, host: str, port: Optional[int]) -> bool:
         return any(t.matches(host, port) for t in self.trusted)
 
+    def to_config_dict(self) -> dict:
+        """Serialize policy to a configuration dictionary."""
+        return {
+            "trusted_hosts": [
+                {"hostname": t.hostname, "port": t.port}
+                for t in self.trusted
+            ],
+            "allow_ip_literals": self.allow_ip_literals,
+        }
+
+    @classmethod
+    def from_config_dict(cls, config: dict) -> "HostPolicy":
+        """Load policy from a configuration dictionary."""
+        trusted = tuple(
+            TrustedHost(h["hostname"], h.get("port"))
+            for h in config["trusted_hosts"]
+        )
+        return cls(trusted, config.get("allow_ip_literals", False))
+
+
+# ---------------------------------------------------------------------------
+# Default trusted host configuration — edit this for your deployment
+# ---------------------------------------------------------------------------
+DEFAULT_TRUSTED_HOSTS = [
+    "localhost",
+    "localhost:8000",
+    "127.0.0.1",
+    "127.0.0.1:8000",
+    # Add your production domain(s) here:
+    # "example.com",
+    # "example.com:443",
+]
+
+_default_policy: Optional[HostPolicy] = None
+
+
+def get_default_policy() -> HostPolicy:
+    """Return the singleton HostPolicy built from DEFAULT_TRUSTED_HOSTS."""
+    global _default_policy
+    if _default_policy is None:
+        _default_policy = HostPolicy.from_iterable(DEFAULT_TRUSTED_HOSTS)
+    return _default_policy
+
+
+# ---------------------------------------------------------------------------
+# Header extraction & validation
+# ---------------------------------------------------------------------------
+
+def _extract_host_from_forwarded(forwarded: str) -> Optional[Tuple[str, Optional[int]]]:
+    """Parse RFC 7239 ``Forwarded`` header for the ``host=`` parameter."""
+    # Example: for=192.0.2.60;proto=http;host=example.com;by=203.0.113.43
+    for part in forwarded.split(";"):
+        part = part.strip()
+        if part.lower().startswith("host="):
+            raw = part[5:].strip('"')
+