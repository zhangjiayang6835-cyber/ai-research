"""
Web Cache Deception Fix
Bounty #679 ($150)
=========================================
Vulnerability: Web Cache Deception leading to Session Token Leak.
Static files CDN is configured to cache `/assets/*.css`. An attacker tricks
an authenticated user into visiting `/account/settings/nonexistent.css`.
The CDN caches the page because of the `.css` suffix, allowing the attacker
to read the cached response and steal session tokens or sensitive data.

Fix Implementation:
1. Force `X-Content-Type-Options: nosniff` on all responses.
2. Ensure the cache key includes `Content-Type` by injecting `Vary: Content-Type, Cookie, Authorization`.
3. Force `Cache-Control: no-store` on sensitive or authenticated routes.
4. Only allow caching if the Content-Type explicitly matches a safe static asset type.
"""

import re
from typing import Dict, Any

class SecureCachePolicy:
    """
    Middleware policy to prevent Web Cache Deception (WCD).
    
    This policy strictly enforces caching rules based on Content-Type rather
    than URL extensions. It guarantees that sensitive endpoints or authenticated
    state responses are never stored in shared CDNs.
    """

    # Allowed MIME types for public shared caching
    SAFE_CACHE_TYPES = {
        "text/css",
        "application/javascript",
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/svg+xml",
        "image/webp",
        "font/woff",
        "font/woff2"
    }

    # Paths that contain sensitive PII or session state
    SENSITIVE_PREFIXES = (
        "/account",
        "/profile",
        "/settings",
        "/admin",
        "/api/auth",
        "/api/user"
    )

    @classmethod
    def apply_security_headers(cls, request: Dict[str, Any], response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates the request and response to apply robust anti-WCD headers.
        
        Args:
            request: Dict containing 'path', 'headers' and 'cookies'.
            response: Dict containing 'status_code', 'headers', and 'content_type'.
            
        Returns:
            The modified response dictionary with injected security headers.
        """
        
        path = request.get("path", "")
        content_type = response.get("content_type", "").split(";")[0].strip().lower()
        req_headers = request.get("headers", {})
        
        # 1. ALWAYS enforce nosniff to prevent MIME confusion
        response["headers"]["X-Content-Type-Options"] = "nosniff"
        
        # 2. ALWAYS append Vary to ensure caches split entries by authentication and content-type
        vary_header = response["headers"].get("Vary", "")
        required_vary = ["Content-Type", "Cookie", "Authorization"]
        current_vary = [v.strip().lower() for v in vary_header.split(",")] if vary_header else []
        
        for req_v in required_vary:
            if req_v.lower() not in current_vary:
                current_vary.append(req_v)
        response["headers"]["Vary"] = ", ".join(current_vary)

        # 3. Check for sensitive routes or authenticated states
        is_sensitive_path = any(path.startswith(prefix) for prefix in cls.SENSITIVE_PREFIXES)
        is_authenticated = bool(request.get("cookies", {}).get("session_id") or req_headers.get("Authorization"))
        
        if is_sensitive_path or is_authenticated:
            # Force no-store for anything sensitive or tied to a user session
            response["headers"]["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response["headers"]["Pragma"] = "no-cache"
            return response
            
        # 4. Content-Type based caching (NOT extension-based)
        if content_type in cls.SAFE_CACHE_TYPES:
            # Safe static asset, allow caching
            response["headers"]["Cache-Control"] = "public, max-age=86400, immutable"
        else:
            # Default fallback for unauthenticated non-static content
            response["headers"]["Cache-Control"] = "private, no-cache, max-age=0"
            
        return response

# --- Test Cases ---
def test_cache_deception_prevention():
    # Scenario 1: Attacker attempts WCD by appending .css to a sensitive route
    request = {"path": "/account/settings/avatar.css", "cookies": {"session_id": "xyz123"}}
    response = {"headers": {}, "content_type": "text/html"}
    
    secured = SecureCachePolicy.apply_security_headers(request, response)
    
    assert "no-store" in secured["headers"]["Cache-Control"], "Failed: Sensitive page was allowed to cache!"
    assert secured["headers"]["X-Content-Type-Options"] == "nosniff", "Failed: Missing nosniff header."
    assert "Content-Type" in secured["headers"]["Vary"], "Failed: Missing Content-Type in Vary."
    
    # Scenario 2: Legitimate static asset request
    request_static = {"path": "/assets/style.css", "cookies": {}}
    response_static = {"headers": {}, "content_type": "text/css"}
    
    secured_static = SecureCachePolicy.apply_security_headers(request_static, response_static)
    
    assert "public" in secured_static["headers"]["Cache-Control"], "Failed: Legitimate static asset not cached."
    assert secured_static["headers"]["X-Content-Type-Options"] == "nosniff"

if __name__ == "__main__":
    test_cache_deception_prevention()
    print("All SecureCachePolicy tests passed successfully.")
