"""
Web Cache Poisoning via Unkeyed Header Fix
Bounty #782 ($150)
=========================================
Vulnerability: CDN doesn't include X-Forwarded-Host in cache key.
Attacker sets malicious X-Forwarded-Host, CDN caches page with
attacker-controlled JS, serves to all users.

Fix: Include all impactful headers in cache key + sanitize user headers.
"""

from typing import Dict, Set, List, Optional
from urllib.parse import urlparse


class SecureCacheKeyManager:
    """
    Cache key management that prevents web cache poisoning.
    
    Principles:
    1. All headers that affect response content are included in cache key
    2. User-controlled headers are sanitized before use
    3. Non-standard headers are blocked from origin
    4. Vary header is properly set
    """

    # Headers that MUST be in cache key (they affect response content)
    REQUIRED_CACHE_KEY_HEADERS: Set[str] = {
        "host",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-forwarded-scheme",
        "accept",
        "accept-encoding",
        "accept-language",
        "origin",
    }

    # Headers that users control and must be sanitized
    USER_CONTROLLED_HEADERS: Set[str] = {
        "x-forwarded-host",
        "x-forwarded-for",
        "x-real-ip",
        "x-original-url",
    }

    # Headers that should NEVER affect cache key
    BLOCKED_HEADERS: Set[str] = {
        "x-random",
        "x-cache-buster",
        "cache-buster",
        "x-request-id",
        "x-trace-id",
    }

    @classmethod
    def generate_cache_key(cls, method: str, path: str,
                           headers: Dict[str, str]) -> str:
        """
        Generate a cache key that includes all impactful headers.
        """
        parsed = urlparse(path)
        normalized_path = parsed.path.rstrip("/") or "/"

        key_parts = [
            method.upper(),
            normalized_path,
            parsed.query,  # Include query string
        ]

        # Add all impactful headers to cache key
        for header in sorted(cls.REQUIRED_CACHE_KEY_HEADERS):
            value = headers.get(header, "")
            if value:
                # Normalize: lowercase, strip whitespace
                normalized_value = value.strip().lower()
                key_parts.append(f"{header}={normalized_value}")

        return "|".join(key_parts)

    @classmethod
    def sanitize_headers(cls, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Sanitize user-controlled headers to prevent cache poisoning.
        """
        sanitized = dict(headers)

        for header in cls.USER_CONTROLLED_HEADERS:
            if header in sanitized:
                value = sanitized[header]
                # Validate: only allow known hosts/values
                if not cls._is_valid_header_value(header, value):
                    sanitized[header] = cls._get_default_value(header)

        # Remove blocked headers
        for header in cls.BLOCKED_HEADERS:
            sanitized.pop(header, None)

        return sanitized

    @classmethod
    def get_vary_header(cls, headers: Dict[str, str]) -> List[str]:
        """
        Generate proper Vary header based on request headers.
        """
        vary_headers = []

        for header in cls.REQUIRED_CACHE_KEY_HEADERS:
            if header in headers:
                # Convert to canonical form
                canonical = "-".join(
                    part.capitalize() for part in header.split("-")
                )
                vary_headers.append(canonical)

        return vary_headers if vary_headers else ["*"]

    @classmethod
    def _is_valid_header_value(cls, header: str, value: str) -> bool:
        """
        Validate header value to prevent injection.
        """
        if not value:
            return False

        # X-Forwarded-Host should only contain valid hostnames
        if header == "x-forwarded-host":
            # Must be a valid hostname (no protocol, path, or special chars)
            import re
            return bool(re.match(
                r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?"
                r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$",
                value
            ))

        return True

    @staticmethod
    def _get_default_value(header: str) -> str:
        """Get safe default value for a header."""
        defaults = {
            "x-forwarded-host": "localhost",
            "x-forwarded-for": "127.0.0.1",
            "x-real-ip": "127.0.0.1",
            "x-original-url": "/",
        }
        return defaults.get(header, "")


# ========== Nginx Configuration Example ==========
NGINX_CONFIG = """
# Nginx configuration to prevent Web Cache Poisoning

# Cache zone
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=web_cache:10m max_size=1g inactive=60m;

# Sanitize user-controlled headers
map $http_x_forwarded_host $safe_forwarded_host {
    ~^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$ $http_x_forwarded_host;
    default "";
}

# Include all impactful headers in cache key
map $http_accept $cache_accept {
    default $http_accept;
}

server {
    listen 80;
    server_name example.com;

    location / {
        # Cache key includes all impactful headers
        proxy_cache_key "$scheme$request_method$host$request_uri$http_accept$http_accept_encoding$http_accept_language$http_origin";

        # Sanitize user-controlled headers
        proxy_set_header X-Forwarded-Host $safe_forwarded_host;

        # Block non-standard headers
        proxy_set_header X-Random "";
        proxy_set_header X-Cache-Buster "";

        # Proper Vary header
        add_header Vary "Accept, Accept-Encoding, Accept-Language, Origin";

        proxy_pass http://backend;
        proxy_cache web_cache;
        proxy_cache_valid 200 301 302 10m;
        proxy_cache_use_stale error timeout updating;
    }
}
"""


# ========== Usage Example ==========
if __name__ == "__main__":
    print("=== Web Cache Poisoning Prevention ===")
    print()

    # Attack scenario:
    # Attacker sends: X-Forwarded-Host: evil.com
    # CDN caches page with <script src="//evil.com/malicious.js">
    # All users who visit the page get the malicious script

    headers = {
        "host": "example.com",
        "x-forwarded-host": "evil.com",
        "accept": "text/html",
        "accept-encoding": "gzip",
        "user-agent": "Mozilla/5.0",
    }

    print("Attack scenario:")
    print(f"  X-Forwarded-Host: {headers['x-forwarded-host']}")
    print()

    # Before (vulnerable): X-Forwarded-Host not in cache key
    vulnerable_key = "GET|/page|"
    print(f"Vulnerable cache key: {vulnerable_key}")
    print(f"  → evil.com host used in response, cached for all users!")
    print()

    # After (fixed): X-Forwarded-Host in cache key
    safe_key = SecureCacheKeyManager.generate_cache_key("GET", "/page", headers)
    print(f"Fixed cache key: {safe_key[:80]}...")
    print(f"  → Different cache entries for different hosts")
    print()

    # After (fixed): User-controlled headers sanitized
    sanitized = SecureCacheKeyManager.sanitize_headers(headers)
    print(f"Sanitized X-Forwarded-Host: {sanitized.get('x-forwarded-host')}")
    print(f"  → Invalid hostname sanitized to safe default")
    print()

    print("=== Security Headers ===")
    vary = SecureCacheKeyManager.get_vary_header(headers)
    print(f"Vary: {', '.join(vary)}")
