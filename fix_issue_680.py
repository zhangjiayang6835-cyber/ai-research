"""Fix for Issue #680: OAuth Access Token in Referer Header → Token Leak"""
import re
import json
import os

SECURITY_FIX = True

SENSITIVE_PARAMS = frozenset({
    "access_token", "token", "bearer", "id_token", "refresh_token",
    "auth", "authorization", "jwt", "session", "session_id", "sid", "api_key"
})

def strip_sensitive_params(url):
    """Remove sensitive query parameters from URL."""
    if "?" not in url:
        return url, []
    base, query = url.split("?", 1)
    removed = []
    kept = []
    for param in query.split("&"):
        key = param.split("=")[0].lower().strip()
        if key in SENSITIVE_PARAMS:
            removed.append(key)
        else:
            kept.append(param)
    clean_url = base + ("?" + "&".join(kept) if kept else "")
    return clean_url, removed

def apply_security_patch(input_data):
    """Apply security fix: strip OAuth tokens from URLs + set Referrer-Policy."""
    if isinstance(input_data, str):
        url = input_data
        headers = {}
    elif isinstance(input_data, dict):
        url = input_data.get("url", "")
        headers = input_data.get("headers", {})
    else:
        return {"status": "error", "data": "Invalid input"}
    
    clean_url, removed = strip_sensitive_params(url)
    headers["Referrer-Policy"] = "no-referrer"
    headers["Cache-Control"] = "no-store"
    
    return {
        "status": "patched",
        "data": {
            "url": clean_url,
            "headers": headers,
            "removed_params": removed
        }
    }

if __name__ == "__main__":
    # Test 1: Token in URL stripped
    result = apply_security_patch("https://app.example/callback?access_token=secret123&state=abc")
    assert "access_token" not in result["data"]["url"], f"Token not stripped: {result['data']['url']}"
    print("✓ Token stripped from URL")
    
    # Test 2: Referrer-Policy header added
    result = apply_security_patch({"url": "https://app.example/callback?token=xyz"})
    assert result["data"]["headers"].get("Referrer-Policy") == "no-referrer"
    print("✓ Referrer-Policy header set")
    
    # Test 3: Safe params preserved
    result = apply_security_patch("https://app.example/search?q=hello&page=2")
    assert "q=hello" in result["data"]["url"]
    assert "page=2" in result["data"]["url"]
    print("✓ Safe params preserved")
    
    # Test 4: Multiple token params stripped
    result = apply_security_patch("https://app.example/callback?access_token=abc&id_token=def&state=ghi")
    assert "access_token" in str(result["data"]["removed_params"])
    assert "id_token" in str(result["data"]["removed_params"])
    print("✓ Multiple token params stripped")
    
    # Test 5: No token URL passes through
    result = apply_security_patch("https://app.example/page")
    assert result["data"]["url"] == "https://app.example/page"
    print("✓ Clean URL passes through")
    
    print("\n✅ All tests passed for #680: OAuth Referer Leak Fix")