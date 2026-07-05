"""
Fix for issue #202: SSRF via DNS rebinding bypassing an allowlist.

The vulnerable pattern validates a URL's hostname, then lets the HTTP client
resolve that hostname later. An attacker-controlled DNS name can answer with a
public IP during validation and rebind to 127.0.0.1, 169.254.169.254, or an RFC
1918 address when the real request is made.

This module prepares a request by resolving the hostname once, rejecting any
non-public result, and returning an IP-pinned connect URL plus the original
Host header/SNI name. Callers should connect to ``connect_url`` and preserve
``host_header``/``server_hostname`` rather than giving the user-supplied host
back to the HTTP client for another DNS lookup.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Callable, Iterable
from urllib.parse import SplitResult, urlsplit, urlunsplit


Resolver = Callable[[str, int | None], Iterable[str]]


class SSRFBlocked(ValueError):
    """Raised when a URL could reach a private or unsafe network target."""


class InvalidTargetURL(ValueError):
    """Raised when a URL is malformed or uses an unsupported scheme."""


@dataclass(frozen=True)
class SafeRequestTarget:
    """A DNS-rebinding-safe request target."""

    original_url: str
    connect_url: str
    host_header: str
    server_hostname: str
    vetted_ip: str
    scheme: str
    port: int


def default_resolver(hostname: str, port: int | None) -> tuple[str, ...]:
    """Resolve a host to unique textual IP addresses."""
    infos = socket.getaddrinfo(hostname, port or 0, type=socket.SOCK_STREAM)
    seen: list[str] = []
    for info in infos:
        address = info[4][0]
        if address not in seen:
            seen.append(address)
    return tuple(seen)


def is_public_ip(address: str) -> bool:
    """Return True only for globally routable unicast addresses."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError as exc:
        raise SSRFBlocked(f"resolver returned invalid address {address!r}") from exc

    return bool(
        ip.is_global
        and not ip.is_private
        and not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_multicast
        and not ip.is_reserved
        and not ip.is_unspecified
    )


def _default_port(scheme: str) -> int:
    if scheme == "https":
        return 443
    if scheme == "http":
        return 80
    raise InvalidTargetURL("only http and https URLs are allowed")


def _parse_target(url: str) -> tuple[SplitResult, str, int]:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise InvalidTargetURL("only http and https URLs are allowed")
    if not parsed.hostname:
        raise InvalidTargetURL("target URL must include a hostname")
    if parsed.username or parsed.password:
        raise InvalidTargetURL("userinfo in target URLs is not allowed")
    if any(ord(ch) < 32 for ch in parsed.hostname):
        raise InvalidTargetURL("hostname contains control characters")

    try:
        port = parsed.port or _default_port(scheme)
    except ValueError as exc:
        raise InvalidTargetURL("invalid port") from exc

    if port <= 0 or port > 65535:
        raise InvalidTargetURL("invalid port")

    return parsed, parsed.hostname.lower().rstrip("."), port


def _ip_netloc(address: str, port: int) -> str:
    ip = ipaddress.ip_address(address)
    host = f"[{address}]" if ip.version == 6 else address
    return f"{host}:{port}"


def _resolve_or_parse_ip(hostname: str, port: int, resolver: Resolver) -> tuple[str, ...]:
    try:
        ipaddress.ip_address(hostname)
        return (hostname,)
    except ValueError:
        pass

    addresses = tuple(resolver(hostname, port))
    if not addresses:
        raise SSRFBlocked("hostname did not resolve")
    return addresses


def prepare_safe_request_target(
    url: str,
    *,
    resolver: Resolver = default_resolver,
) -> SafeRequestTarget:
    """Validate and pin a URL target against DNS rebinding.

    The function rejects the entire hostname if any returned address is not
    public. This prevents attackers from hiding a private target behind a mixed
    response set and waiting for the HTTP client's address selection to choose
    the unsafe address.
    """
    parsed, hostname, port = _parse_target(url)
    addresses = _resolve_or_parse_ip(hostname, port, resolver)

    unsafe = [address for address in addresses if not is_public_ip(address)]
    if unsafe:
        raise SSRFBlocked(f"unsafe resolved address(es): {', '.join(unsafe)}")

    vetted_ip = addresses[0]
    connect_url = urlunsplit(
        (
            parsed.scheme.lower(),
            _ip_netloc(vetted_ip, port),
            parsed.path or "/",
            parsed.query,
            "",
        )
    )

    host_header = hostname if parsed.port is None else f"{hostname}:{port}"
    return SafeRequestTarget(
        original_url=url,
        connect_url=connect_url,
        host_header=host_header,
        server_hostname=hostname,
        vetted_ip=vetted_ip,
        scheme=parsed.scheme.lower(),
        port=port,
    )


def validate_redirect_chain(
    urls: Iterable[str],
    *,
    resolver: Resolver = default_resolver,
) -> tuple[SafeRequestTarget, ...]:
    """Validate every hop before following redirects."""
    return tuple(prepare_safe_request_target(url, resolver=resolver) for url in urls)


if __name__ == "__main__":
    target = prepare_safe_request_target(
        "https://example.com/api?q=1",
        resolver=lambda _host, _port: ("93.184.216.34",),
    )
    assert target.connect_url == "https://93.184.216.34:443/api?q=1"
    assert target.host_header == "example.com"
    print("ssrf_dns_rebinding_fix: self-check passed")
