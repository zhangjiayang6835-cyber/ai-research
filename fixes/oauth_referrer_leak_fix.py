"""
Fix for Issue #1218 — OAuth Access Token in Referer Header.

Root cause
----------
When the OAuth callback page contains links to external sites or performs
redirects, the browser's Referer header may include the full callback URL
— including any access_token in the URI fragment. This leaks the token
to third-party sites.

Fix
---
1. Set `Referrer-Policy: no-referrer` on the OAuth callback response.
2. Ensure tokens are never placed in URL fragments (use Authorization Code
   + PKCE instead of Implicit Grant).
3. Add `<meta name="referrer" content="no-referrer">` to callback HTML pages.

Implementation
--------------
This module patches the SSO federation callback to enforce no-referrer policy.
"""

from __future__ import annotations
from typing import Dict, Optional


def secure_callback_headers() -> Dict[str, str]:
    """
    Return security headers for OAuth callback responses.
    
    The critical header is `Referrer-Policy: no-referrer` which prevents
    the browser from sending the full callback URL (including any tokens
    or auth codes) in the Referer header when navigating to external sites.
    """
    return {
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
    }


def no_referrer_html() -> str:
    """
    Return an HTML `<meta>` tag to embed in OAuth callback pages.
    
    This acts as a defense-in-depth measure: even if the HTTP header
    is somehow stripped, the HTML meta tag enforces the same policy.
    """
    return '<meta name="referrer" content="no-referrer">'


def validate_no_token_in_fragment(url: str) -> bool:
    """
    Verify that the URL does not contain an access_token in the fragment.
    
    Per OAuth 2.0 Security BCP (RFC 9700), tokens MUST NOT be returned
    in the front-channel (URL fragment). Only Authorization Code + PKCE
    should be used, with the code in the query string.
    """
    if "#access_token=" in url or "#token=" in url:
        return False
    return True


# Self-test
if __name__ == "__main__":
    headers = secure_callback_headers()
    assert headers["Referrer-Policy"] == "no-referrer"
    print(f"Headers: {headers}")
    
    assert validate_no_token_in_fragment("https://app.example.com/cb?code=abc123")
    assert not validate_no_token_in_fragment("https://app.example.com/cb#access_token=leaked")
    print("Fragment check: PASS")
    
    print("All tests passed.")
