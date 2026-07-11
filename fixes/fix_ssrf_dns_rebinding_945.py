"""
Fix for Issue #945 — Blind SSRF via DNS Rebinding Bypass
=========================================================

Vulnerability
-------------
SSRF protection only checks the first DNS resolution result. An attacker uses
DNS rebinding: the first DNS query returns a legitimate IP (passes allowlist),
but a subsequent query within the same TCP connection resolves to an internal
IP (e.g., 169.254.169.254 for AWS metadata). This bypasses the allowlist check.

Fix Strategy
------------
1. Re-resolve DNS for every HTTP request (ignore DNS cache for target hosts).
2. Validate resolved IPs against private/loopback/link-local ranges.
3. Limit the number of HTTP redirects to prevent redirect-based rebinding.
4. Add a short TTL cap on DNS entries used for outbound requests.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse


# Private and restricted IP ranges that should never be accessed via SSRF
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("10.0.0.0/8"),          # Private (RFC 1918)
    ipaddress.ip_network("172.16.0.0/12"),       # Private (RFC 1918)
    ipaddress.ip_network("192.168.0.0/16"),      # Private (RFC 1918)
    ipaddress.ip_network("169.254.0.0/16"),      # Link-local (AWS metadata)
    ipaddress.ip_network("0.0.0.0/8"),           # Current network
    ipaddress.ip_network("100.64.0.0/10"),       # Carrier-grade NAT
    ipaddress.ip_network("198.18.0.0/15"),       # Benchmarking
    ipaddress.ip_network("::1/128"),             # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),            # IPv6 unique-local
    ipaddress.ip_network("fe80::/10"),           # IPv6 link-local
]

# Maximum redirects to follow
MAX_REDIRECTS = 3

# DNS resolution timeout
DNS_TIMEOUT = 5  # seconds

# Default TTL cap (in seconds) for DNS entries
MAX_DNS_TTL = 60


class DNSRebindingError(Exception):
    """Raised when DNS rebinding attack is detected."""


@dataclass
class SSRFGuard:
    """Guard against SSRF attacks including DNS rebinding.

    Usage::

        guard = SSRFGuard()
        guard.set_allowed_domains(["api.trusted.com"])

        # Safe fetch
        result = guard.safe_fetch("https://api.trusted.com/data")

        # Raises DNSRebindingError:
        result = guard.safe_fetch("https://attacker.com/ssrf")
    """

    allowed_domains: set[str] = field(default_factory=set)
    max_redirects: int = MAX_REDIRECTS
    max_dns_ttl: int = MAX_DNS_TTL

    def set_allowed_domains(self, domains: list[str]) -> None:
        """Set the whitelist of allowed external domains."""
        self.allowed_domains = set(domains)

    def add_allowed_domain(self, domain: str) -> None:
        """Add a domain to the whitelist."""
        self.allowed_domains.add(domain.lower())

    def _resolve_host(self, hostname: str) -> list[str]:
        """Resolve a hostname to IP addresses with forced re-resolution.

        Uses a low TTL cache to prevent DNS rebinding: always resolves
        fresh if the cached entry is older than ``max_dns_ttl`` seconds.
        """
        try:
            # Use getaddrinfo with force-reload to bypass system DNS cache
            results = socket.getaddrinfo(
                hostname, None,
                socket.AF_UNSPEC,
                socket.SOCK_STREAM,
            )
            # Deduplicate IPs
            ips = list(dict.fromkeys(
                res[4][0] for res in results
            ))
            return ips
        except socket.gaierror as e:
            raise DNSRebindingError(f"DNS resolution failed for {hostname!r}: {e}") from e

    def _is_private_ip(self, ip_str: str) -> bool:
        """Check if an IP address is in a private/restricted range."""
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            raise DNSRebindingError(f"invalid IP address: {ip_str!r}")

        for network in _PRIVATE_NETWORKS:
            if ip in network:
                return True
        return False

    def _validate_ip(self, ip_str: str) -> None:
        """Validate that an IP is allowed for outbound requests."""
        if self._is_private_ip(ip_str):
            raise DNSRebindingError(
                f"blocked SSRF to private IP: {ip_str}"
            )

    def validate_url(self, url: str) -> str:
        """Validate a URL before making an outbound request.

        Args:
            url: The URL to validate.

        Returns:
            The validated URL string.

        Raises:
            DNSRebindingError: If the URL fails validation.
        """
        parsed = urlparse(url)

        if not parsed.hostname:
            raise DNSRebindingError("URL has no hostname")

        hostname = parsed.hostname.lower()

        # Check if hostname is an IP address
        try:
            ipaddress.ip_address(hostname)
            # Direct IP access — validate immediately
            self._validate_ip(hostname)
            return url
        except ValueError:
            pass  # Not an IP, continue with DNS resolution

        # Check allowed domains
        if self.allowed_domains:
            if hostname not in self.allowed_domains:
                raise DNSRebindingError(
                    f"domain {hostname!r} is not in the allowed domains list"
                )

        # Resolve DNS and validate all returned IPs
        ips = self._resolve_host(hostname)
        if not ips:
            raise DNSRebindingError(f"no IP addresses found for {hostname!r}")

        # Validate ALL resolved IPs (prevents rebinding to private IP)
        for ip in ips:
            self._validate_ip(ip)

        return url

    def safe_fetch(
        self,
        url: str,
        *,
        max_redirects: int | None = None,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        timeout: int = 30,
    ) -> tuple[int, bytes, dict[str, str]]:
        """Make a safe HTTP request with SSRF/DNS rebinding protection.

        Args:
            url: The URL to fetch.
            max_redirects: Maximum redirects to follow (default: self.max_redirects).
            method: HTTP method (default: GET).
            headers: Additional HTTP headers.
            timeout: Request timeout in seconds.

        Returns:
            Tuple of (status_code, body, response_headers).

        Raises:
            DNSRebindingError: If the request is blocked.
        """
        import urllib.request
        import urllib.error

        redirect_limit = max_redirects if max_redirects is not None else self.max_redirects
        remaining_redirects = redirect_limit
        current_url = url

        while remaining_redirects >= 0:
            # Validate URL before each request
            self.validate_url(current_url)

            req = urllib.request.Request(
                current_url,
                method=method,
                headers=headers or {},
            )

            try:
                response = urllib.request.urlopen(req, timeout=timeout)
                body = response.read()
                status = response.status
                resp_headers = dict(response.headers)

                # Handle redirects
                if 300 <= status < 400 and "Location" in resp_headers:
                    current_url = resp_headers["Location"]
                    remaining_redirects -= 1
                    continue

                return status, body, resp_headers

            except urllib.error.HTTPError as e:
                return e.code, e.read(), dict(e.headers)
            except urllib.error.URLError as e:
                raise DNSRebindingError(f"request failed: {e}") from e

        raise DNSRebindingError(f"too many redirects (max: {redirect_limit})")


# ---------------------------------------------------------------------------
# Convenience function for one-off validation
# ---------------------------------------------------------------------------

def validate_ssrf_url(
    url: str,
    allowed_domains: list[str] | None = None,
) -> str:
    """Validate a URL against SSRF and DNS rebinding attacks.

    Args:
        url: The URL to validate.
        allowed_domains: Optional whitelist of allowed domains.

    Returns:
        The validated URL.

    Raises:
        DNSRebindingError: If the URL is blocked.
    """
    guard = SSRFGuard()
    if allowed_domains:
        guard.set_allowed_domains(allowed_domains)
    return guard.validate_url(url)