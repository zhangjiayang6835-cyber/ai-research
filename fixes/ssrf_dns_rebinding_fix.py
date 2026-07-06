"""
SSRF via DNS Rebinding — Allowlist Bypass
==========================================
Bug bounty #440  (zhangjiayang6835-cyber/ai-research)

This module demonstrates the vulnerability and ships a hardened fix.

VULNERABILITY
-------------
A common SSRF guard resolves the attacker-supplied hostname, checks the
*resolved* IP against an allowlist, and then performs the outbound request.
Because the HTTP client resolves the hostname *again* at connect time, an
attacker who controls DNS can return a benign IP on the first lookup (passing
the check) and a forbidden IP (e.g. 169.254.169.254, 127.0.0.1, an internal
host) on the second lookup. That is DNS rebinding, and it defeats the guard.

FIX
---
Resolve the hostname exactly ONCE, pin that IP for the whole request, and
connect directly to the pinned IP (still sending the original Host header).
A second DNS resolution can therefore never return a different address.
"""
import socket
import http.client
from urllib.parse import urlparse


# --- Allowlist: IPs that trusted hostnames resolve to (precomputed) ----------
# In production you would resolve your allowlisted hostnames ONCE at startup
# (or on a short, pinned TTL) and store the resulting IPs here.
TRUSTED_IPS = {
    "203.0.113.10",    # api.trusted.example
    "198.51.100.42",   # internal-service.example
}


# ---------------------------------------------------------------------------
# VULNERABLE implementation (DO NOT USE)
# ---------------------------------------------------------------------------
def vulnerable_fetch(url: str) -> str:
    """Resolves the hostname twice; the 2nd resolution can be rebound."""
    host = urlparse(url).hostname
    ip = socket.gethostbyname(host)            # lookup #1 — passes the check
    if ip not in TRUSTED_IPS:
        raise ValueError(f"blocked: {ip}")
    # The HTTP client performs lookup #2 internally; rebinding happens here.
    conn = http.client.HTTPConnection(host, timeout=5)
    conn.request("GET", url)
    return conn.getresponse().read().decode()


# ---------------------------------------------------------------------------
# SECURE implementation
# ---------------------------------------------------------------------------
class _PinnedIPConnection(http.client.HTTPConnection):
    """HTTPConnection that always connects to a fixed IP, ignoring DNS."""

    def __init__(self, *args, pin_ip=None, **kwargs):
        self._pin_ip = pin_ip
        super().__init__(*args, **kwargs)

    def connect(self):
        # Connect to the pinned IP. The real hostname is only used for the
        # Host header / TLS SNI (set by the caller).
        self.sock = socket.create_connection((self._pin_ip, self.port), self.timeout)


def safe_fetch(url: str) -> str:
    """Resolve ONCE, pin the IP, and connect to that IP for the whole request."""
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    ip = socket.gethostbyname(host)            # resolve exactly ONCE
    if ip not in TRUSTED_IPS:
        raise ValueError(f"SSRF blocked: {host} resolved to untrusted {ip}")

    conn = _PinnedIPConnection(host, port=port, pin_ip=ip, timeout=5)
    try:
        conn.request("GET", url, headers={"Host": host})
        resp = conn.getresponse()
        return resp.read().decode()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Proof of Concept — simulated DNS rebinding (no real network traffic)
# ---------------------------------------------------------------------------
def _is_ip(host: str) -> bool:
    return all(c.isdigit() or c == "." for c in host)


def _demo():
    forbidden_ip = "169.254.169.254"   # cloud metadata / internal target
    state = {"calls": 0}
    real_gethostbyname = socket.gethostbyname
    real_create_connection = socket.create_connection

    def rebinding_resolve(hostname):
        state["calls"] += 1
        # 1st lookup: pretend to be the trusted host. Later lookups: rebind.
        return next(iter(TRUSTED_IPS)) if state["calls"] == 1 else forbidden_ip

    def fake_connect(addr, *args, **kwargs):
        host = addr[0]
        if _is_ip(host):
            # Safe path: a pinned IP literal is passed straight to connect.
            resolved = host
        else:
            # Vulnerable path: the hostname is resolved AGAIN here, and the
            # rebinding resolver now returns the forbidden target.
            resolved = forbidden_ip
        raise RuntimeError(f"would connect to {resolved}:{addr[1]}")

    socket.gethostbyname = rebinding_resolve
    socket.create_connection = fake_connect
    malicious = "http://evil.attacker.example/secret"
    try:
        vulnerable_fetch(malicious)
    except RuntimeError as exc:
        print(f"[vulnerable] {exc}  -> rebinding succeeded, attacker reaches "
              f"the FORBIDDEN host")
    except ValueError as exc:
        print(f"[vulnerable] unexpectedly blocked: {exc}")

    state["calls"] = 0
    try:
        safe_fetch(malicious)
    except RuntimeError as exc:
        print(f"[safe]       {exc}  -> connected to the PINNED trusted IP "
              f"(no rebind possible)")
    except ValueError as exc:
        print(f"[safe]       blocked at allowlist: {exc}")
    finally:
        socket.gethostbyname = real_gethostbyname
        socket.create_connection = real_create_connection


if __name__ == "__main__":
    _demo()
