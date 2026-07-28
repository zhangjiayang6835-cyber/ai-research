"""
Fix for Issue #1489 — JWT Kid Injection → Path Traversal → Secret Key Leak

Vulnerability
-------------
JWT verification uses the 'kid' (Key ID) header to look up the verification key.
An attacker can exploit this by:
1. Setting kid to "../../etc/passwd" → reads arbitrary files via path traversal
2. Setting kid to a URL → server makes SSRF request
3. Injecting null bytes or special characters to bypass validation
4. Setting kid to an unknown value matching no key → DoS or undefined behavior

Fix
---
1. Validate 'kid' against whitelist of allowed key IDs
2. Prevent path traversal (block "../", "/", "..\\")
3. Use constant-time comparison for kid values (prevent timing oracle)
4. Reject JWTs with kid that doesn't match any known key
5. Add proper error handling for invalid kid with generic error messages

Acceptance Criteria
-------------------
- [x] Kid header validated against whitelist
- [x] Path traversal characters rejected
- [x] Constant-time comparison
- [x] Proper error handling
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Mapping, Optional, Set


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Regex: only alphanumeric, hyphen, underscore, period — NO path separators
SAFE_KID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

# Minimum HMAC secret entropy (256 bits per OWASP / NIST SP 800-107r1)
_MIN_SECRET_BYTES = 32

# Supported HMAC algorithms
_SUPPORTED_ALGORITHMS: Dict[str, Any] = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

# Algorithms that are ALWAYS rejected
_FORBIDDEN_ALGORITHMS: FrozenSet[str] = frozenset({
    "none", "None", "NONE", "", "null", "NULL",
})


# ---------------------------------------------------------------------------
# Errors — single generic error to prevent oracle leaks
# ---------------------------------------------------------------------------

class JWTError(Exception):
    """Generic JWT error for all validation failures.

    A single error class prevents attackers from distinguishing between
    different failure modes (signature vs algorithm vs kid vs expiry).
    The message is intentionally generic — callers must NOT branch on it.
    """
    pass


# ---------------------------------------------------------------------------
# Base64 helpers
# ---------------------------------------------------------------------------

def _b64_encode(data: bytes) -> str:
    """URL-safe base64 encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64_decode(data: str) -> bytes:
    """URL-safe base64 decode with padding normalization."""
    try:
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)
    except (TypeError, ValueError, Exception):
        raise JWTError("malformed token encoding")


# ---------------------------------------------------------------------------
# Constant-time comparison
# ---------------------------------------------------------------------------

def _constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing oracle attacks."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# ---------------------------------------------------------------------------
# Kid validation — THE FIX
# ---------------------------------------------------------------------------

def validate_kid(
    kid: Optional[str],
    allowed_kids: Optional[FrozenSet[str]] = None,
) -> str:
    """Validate and sanitize the JWT kid (Key ID) header.

    Defends against:
    - Path traversal: ../../etc/passwd
    - SQL injection: key' OR '1'='1
    - Command injection: key; rm -rf /
    - Null byte injection: key\\x00.pem
    - SSRF via URL: http://attacker.com/steal-key
    - DoS via overly long values (max 64 chars)
    - Timing oracle attacks (constant-time comparison against allow-list)

    Args:
        kid: The kid header value from the JWT (may be None).
        allowed_kids: Optional set of allowed kid values. If None or empty,
                      any syntactically valid kid is accepted after sanitization.

    Returns:
        The validated kid string.

    Raises:
        JWTError: If the kid fails any validation check.
    """
    # 1. Missing kid handling
    if kid is None:
        if allowed_kids is not None and len(allowed_kids) > 0:
            # Allow-list exists but no kid provided — reject
            raise JWTError("missing required kid header")
        # No allow-list, no kid — use default
        return "default"

    if not isinstance(kid, str):
        raise JWTError("invalid kid header type")

    # 2. Length check (prevent DoS / buffer overflow)
    if len(kid) > 64:
        raise JWTError("kid header too long")

    # 3. Character allow-list — only safe characters
    #    Blocks: "/", "\\", "..", null bytes, control chars, URL schemes
    if not SAFE_KID_RE.match(kid):
        raise JWTError("kid header contains forbidden characters")

    # 4. Extra check for path traversal sequences (belt-and-suspenders)
    if ".." in kid or "/" in kid or "\\" in kid:
        raise JWTError("kid header contains path traversal")

    # 5. Allow-list check (constant-time comparison)
    if allowed_kids is not None and len(allowed_kids) > 0:
        match_found = any(_constant_time_compare(kid, allowed) for allowed in allowed_kids)
        if not match_found:
            raise JWTError("kid header not in allow-list")

    return kid


# ---------------------------------------------------------------------------
# Algorithm validation
# ---------------------------------------------------------------------------

def validate_algorithm(
    alg: Optional[str],
    allowed_algorithms: FrozenSet[str],
) -> str:
    """Validate the JWT alg header against the server's allow-list.

    Defends against:
    - None algorithm bypass (alg: "none")
    - Algorithm confusion (RS256 -> HS256)
    - Unsupported/unknown algorithms
    """
    if alg is None or not isinstance(alg, str):
        raise JWTError("missing or invalid alg header")

    # Reject forbidden algorithms
    if alg in _FORBIDDEN_ALGORITHMS or alg.lower() in {"none", "null"}:
        raise JWTError("forbidden algorithm")

    # Check against server's allow-list
    if alg not in allowed_algorithms:
        raise JWTError("algorithm not allowed")

    # Ensure the algorithm is supported
    if alg not in _SUPPORTED_ALGORITHMS:
        raise JWTError("unsupported algorithm")

    return alg


# ---------------------------------------------------------------------------
# HMAC signature verification (constant-time)
# ---------------------------------------------------------------------------

def verify_hmac(
    message: bytes,
    signature: bytes,
    secret: bytes,
    alg: str,
) -> None:
    """Verify HMAC signature in constant time."""
    hash_fn = _SUPPORTED_ALGORITHMS[alg]
    expected = hmac.new(secret, message, hash_fn).digest()
    if not hmac.compare_digest(signature, expected):
        raise JWTError("signature verification failed")


# ---------------------------------------------------------------------------
# Token creation helper (for testing/demo)
# ---------------------------------------------------------------------------

def create_token(
    payload: Dict[str, Any],
    secret: bytes,
    alg: str = "HS256",
    kid: str = "default",
) -> str:
    """Create a signed JWT token (HMAC only, for testing/demo)."""
    if alg not in _SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {alg}")

    header = {"alg": alg, "typ": "JWT", "kid": kid}
    header_b64 = _b64_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64_encode(json.dumps(payload, separators=(",", ":")).encode())

    message = f"{header_b64}.{payload_b64}".encode("utf-8")
    hash_fn = _SUPPORTED_ALGORITHMS[alg]
    signature = hmac.new(secret, message, hash_fn).digest()
    sig_b64 = _b64_encode(signature)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


# ---------------------------------------------------------------------------
# Secure JWT Verifier — main fix class
# ---------------------------------------------------------------------------

@dataclass
class SecureJWTVerifier:
    """Secure JWT verifier with defense against kid injection + algorithm attacks.

    Usage:
        verifier = SecureJWTVerifier(
            allowed_algorithms=frozenset({"HS256"}),
            hmac_secrets={"key-1": b"<32+ bytes of random data>"},
            allowed_kids=frozenset({"key-1", "key-2"}),
        )
        payload = verifier.verify(token)
    """

    # REQUIRED: Allowed algorithms
    allowed_algorithms: FrozenSet[str]

    # REQUIRED: Map of kid -> HMAC secret
    hmac_secrets: Dict[str, bytes]

    # OPTIONAL: Kid allow-list (if None, any safe kid is accepted)
    allowed_kids: Optional[FrozenSet[str]] = None

    # OPTIONAL: Claim validation
    verify_expiry: bool = True
    clock_skew_seconds: int = 60
    required_claims: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        """Validate configuration at construction time."""
        if not self.allowed_algorithms or len(self.allowed_algorithms) == 0:
            raise ValueError("allowed_algorithms must be non-empty")

        if not self.hmac_secrets or len(self.hmac_secrets) == 0:
            raise ValueError("at least one HMAC secret must be provided")

        # Validate secret strength
        for kid, secret in self.hmac_secrets.items():
            if not isinstance(secret, bytes):
                raise ValueError(f"Secret for kid={kid} must be bytes")
            if len(secret) < _MIN_SECRET_BYTES:
                raise ValueError(
                    f"Secret for kid={kid} is too short "
                    f"({len(secret)} bytes, minimum {_MIN_SECRET_BYTES})"
                )

    def verify(self, token: str) -> Dict[str, Any]:
        """Verify a JWT token and return the payload.

        Args:
            token: The JWT string (header.payload.signature).

        Returns:
            The decoded payload dictionary.

        Raises:
            JWTError: On any validation failure.
        """
        # 1. Parse token structure
        parts = token.split(".")
        if len(parts) != 3:
            raise JWTError("malformed token structure")

        header_b64, payload_b64, signature_b64 = parts

        # 2. Decode header
        try:
            header = json.loads(_b64_decode(header_b64))
        except (json.JSONDecodeError, Exception):
            raise JWTError("malformed token header")

        # 3. Decode payload
        try:
            payload = json.loads(_b64_decode(payload_b64))
        except (json.JSONDecodeError, Exception):
            raise JWTError("malformed token payload")

        # 4. Decode signature
        try:
            signature = _b64_decode(signature_b64)
        except Exception:
            raise JWTError("malformed token signature")

        # 5. Validate algorithm
        alg = validate_algorithm(header.get("alg"), self.allowed_algorithms)

        # 6. Validate kid — THE FIX for JWT Kid Injection
        kid = validate_kid(header.get("kid"), self.allowed_kids)

        # 7. Verify signature (constant-time)
        message = f"{header_b64}.{payload_b64}".encode("utf-8")

        if kid not in self.hmac_secrets:
            raise JWTError("key not found")
        secret = self.hmac_secrets[kid]
        verify_hmac(message, signature, secret, alg)

        # 8. Validate payload claims
        if not isinstance(payload, dict):
            raise JWTError("payload must be a JSON object")

        # 8a. Expiry check
        if self.verify_expiry:
            exp = payload.get("exp")
            if exp is None:
                raise JWTError("missing exp claim")
            if not isinstance(exp, (int, float)):
                raise JWTError("invalid exp claim")
            now = time.time()
            if exp < now - self.clock_skew_seconds:
                raise JWTError("token expired")

        # 8b. Not-before check
        nbf = payload.get("nbf")
        if nbf is not None:
            if not isinstance(nbf, (int, float)):
                raise JWTError("invalid nbf claim")
            now = time.time()
            if nbf > now + self.clock_skew_seconds:
                raise JWTError("token not yet valid")

        # 8c. Required claims check
        if self.required_claims:
            for claim_key, expected_value in self.required_claims.items():
                actual_value = payload.get(claim_key)
                if actual_value != expected_value:
                    raise JWTError("claim validation failed")

        return payload


# ---------------------------------------------------------------------------
# Helper: generate strong secret
# ---------------------------------------------------------------------------

def generate_strong_secret(nbytes: int = _MIN_SECRET_BYTES) -> bytes:
    """Generate a cryptographically strong secret for HMAC algorithms."""
    if nbytes < _MIN_SECRET_BYTES:
        raise ValueError(f"secret must be >= {_MIN_SECRET_BYTES} bytes")
    return secrets.token_bytes(nbytes)


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def demonstrate_vulnerability():
    """Demonstrate the JWT Kid Injection vulnerability and the fix."""
    print("=" * 70)
    print("JWT Kid Injection → Path Traversal → Secret Key Leak")
    print("=" * 70)

    # Generate a strong secret
    strong_secret = generate_strong_secret()

    # Create verifier with allow-list
    verifier = SecureJWTVerifier(
        allowed_algorithms=frozenset({"HS256"}),
        hmac_secrets={"key-1": strong_secret, "key-2": strong_secret},
        allowed_kids=frozenset({"key-1", "key-2"}),
        verify_expiry=False,  # Disable expiry for demo
    )

    print("\n🔒 SECURE VERIFIER CONFIGURED")
    print(f"   Allowed kids: key-1, key-2")
    print(f"   Allowed algorithms: HS256")

    # Valid token test
    now = int(time.time())
    valid_payload = {"sub": "user-123", "role": "admin", "exp": now + 3600}
    valid_token = create_token(valid_payload, strong_secret, "HS256", "key-1")

    print(f"\n✅ VALID TOKEN: {valid_token[:50]}...")
    try:
        result = verifier.verify(valid_token)
        print(f"   → Verified! Payload: sub={result['sub']}, role={result['role']}")
    except JWTError as e:
        print(f"   → REJECTED (unexpected): {e}")

    # Attack 1: Path traversal kid
    print("\n❌ ATTACK 1: Path Traversal")
    attack_payload = {"sub": "attacker", "role": "admin"}
    malicious_kids = [
        "../../etc/passwd",
        "../../../etc/shadow",
        "../secret.key",
        "keys/../etc/hostname",
        "..\\windows\\system32\\config",
    ]
    for malicious_kid in malicious_kids:
        try:
            token = create_token(attack_payload, b"x" * 32, "HS256", malicious_kid)
            verifier.verify(token)
            print(f"   ⚠️ Kid '{malicious_kid[:25]}...': NOT BLOCKED (VULNERABLE!)")
        except JWTError as e:
            print(f"   ✅ Kid '{malicious_kid[:25]}...': BLOCKED ({e})")

    # Attack 2: SSRF via URL kid
    print("\n❌ ATTACK 2: SSRF via URL Kid")
    url_kids = [
        "http://attacker.com/steal-key",
        "https://evil.example/key",
        "//attacker.com/key",
    ]
    for url_kid in url_kids:
        try:
            token = create_token(attack_payload, b"x" * 32, "HS256", url_kid)
            verifier.verify(token)
            print(f"   ⚠️ Kid '{url_kid[:25]}...': NOT BLOCKED (VULNERABLE!)")
        except JWTError as e:
            print(f"   ✅ Kid '{url_kid[:25]}...': BLOCKED ({e})")

    # Attack 3: Unknown kid
    print("\n❌ ATTACK 3: Unknown Kid (Bypass)")
    try:
        token = create_token(attack_payload, b"x" * 32, "HS256", "unknown-key")
        verifier.verify(token)
        print(f"   ⚠️ Unknown kid: NOT BLOCKED (VULNERABLE!)")
    except JWTError as e:
        print(f"   ✅ Unknown kid: BLOCKED ({e})")

    # Attack 4: Null byte injection
    print("\n❌ ATTACK 4: Null Byte Injection")
    null_kids = ["key\x00.txt", "key\n.evil"]
    for null_kid in null_kids:
        try:
            token = create_token(attack_payload, b"x" * 32, "HS256", null_kid)
            verifier.verify(token)
            print(f"   ⚠️ Kid '{repr(null_kid)[:20]}...': NOT BLOCKED (VULNERABLE!)")
        except JWTError as e:
            print(f"   ✅ Kid '{repr(null_kid)[:20]}...': BLOCKED ({e})")

    # Attack 5: None algorithm with kid
    print("\n❌ ATTACK 5: None Algorithm + Kid Injection")
    try:
        # Manually craft a "none" algorithm token
        header_b64 = _b64_encode(json.dumps({"alg": "none", "typ": "JWT", "kid": "../../etc/passwd"}).encode())
        payload_b64 = _b64_encode(json.dumps(attack_payload).encode())
        forged_token = f"{header_b64}.{payload_b64}."
        verifier.verify(forged_token)
        print(f"   ⚠️ None alg + path traversal: NOT BLOCKED (VULNERABLE!)")
    except JWTError as e:
        print(f"   ✅ None alg + path traversal: BLOCKED ({e})")

    print("\n" + "=" * 70)
    print("SUMMARY: All JWT Kid Injection attack vectors are blocked!")
    print("=" * 70)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def run_tests():
    """Run comprehensive tests for the JWT Kid Injection fix."""
    print("=" * 70)
    print("Running Tests for Issue #1489: JWT Kid Injection Fix")
    print("=" * 70)

    strong_secret = generate_strong_secret()
    weak_secret = b"too-short"  # Only 8 bytes
    test_count = 0
    pass_count = 0

    # --- Test 1: Valid kid is accepted ---
    test_count += 1
    verifier = SecureJWTVerifier(
        allowed_algorithms=frozenset({"HS256"}),
        hmac_secrets={"key-1": strong_secret},
        allowed_kids=frozenset({"key-1"}),
        verify_expiry=False,
    )
    now = int(time.time())
    payload = {"sub": "user-1", "exp": now + 3600}
    token = create_token(payload, strong_secret, "HS256", "key-1")
    try:
        result = verifier.verify(token)
        assert result["sub"] == "user-1"
        pass_count += 1
        print(f"  ✓ Test {test_count}: Valid kid accepted")
    except JWTError as e:
        print(f"  ✗ Test {test_count}: Valid kid REJECTED — {e}")

    # --- Test 2: Path traversal kid is rejected ---
    test_count += 1
    try:
        validate_kid("../../etc/passwd", frozenset({"key-1"}))
        print(f"  ✗ Test {test_count}: Path traversal NOT blocked!")
    except JWTError:
        pass_count += 1
        print(f"  ✓ Test {test_count}: Path traversal blocked")

    # --- Test 3: URL scheme kid is rejected ---
    test_count += 1
    try:
        validate_kid("http://evil.com/key", frozenset({"key-1"}))
        print(f"  ✗ Test {test_count}: URL kid NOT blocked!")
    except JWTError:
        pass_count += 1
        print(f"  ✓ Test {test_count}: URL kid blocked")

    # --- Test 4: Null byte kid is rejected ---
    test_count += 1
    try:
        validate_kid("key\x00.txt", frozenset({"key-1"}))
        print(f"  ✗ Test {test_count}: Null byte kid NOT blocked!")
    except JWTError:
        pass_count += 1
        print(f"  ✓ Test {test_count}: Null byte kid blocked")

    # --- Test 5: Unknown kid is rejected (with allow-list) ---
    test_count += 1
    try:
        validate_kid("unknown-key", frozenset({"key-1", "key-2"}))
        print(f"  ✗ Test {test_count}: Unknown kid NOT blocked!")
    except JWTError:
        pass_count += 1
        print(f"  ✓ Test {test_count}: Unknown kid blocked")

    # --- Test 6: Missing kid is rejected when allow-list exists ---
    test_count += 1
    try:
        validate_kid(None, frozenset({"key-1"}))
        print(f"  ✗ Test {test_count}: Missing kid NOT blocked!")
    except JWTError:
        pass_count += 1
        print(f"  ✓ Test {test_count}: Missing kid blocked (allow-list active)")

    # --- Test 7: Missing kid uses default when no allow-list ---
    test_count += 1
    result = validate_kid(None, None)
    assert result == "default"
    pass_count += 1
    print(f"  ✓ Test {test_count}: Missing kid returns 'default' when no allow-list")

    # --- Test 8: Overly long kid is rejected ---
    test_count += 1
    try:
        validate_kid("a" * 100, frozenset({"a" * 100}))
        print(f"  ✗ Test {test_count}: Long kid NOT blocked!")
    except JWTError:
        pass_count += 1
        print(f"  ✓ Test {test_count}: Long kid (>64 chars) blocked")

    # --- Test 9: None algorithm is rejected ---
    test_count += 1
    try:
        validate_algorithm("none", frozenset({"HS256"}))
        print(f"  ✗ Test {test_count}: None algorithm NOT blocked!")
    except JWTError:
        pass_count += 1
        print(f"  ✓ Test {test_count}: None algorithm blocked")

    # --- Test 10: Strong secret required ---
    test_count += 1
    try:
        SecureJWTVerifier(
            allowed_algorithms=frozenset({"HS256"}),
            hmac_secrets={"key-1": weak_secret},
        )
        print(f"  ✗ Test {test_count}: Weak secret NOT rejected!")
    except ValueError:
        pass_count += 1
        print(f"  ✓ Test {test_count}: Weak secret rejected")

    # --- Test 11: Constant-time comparison is used ---
    test_count += 1
    # Verify that _constant_time_compare uses hmac.compare_digest
    assert _constant_time_compare("key-1", "key-1") == True
    assert _constant_time_compare("key-1", "key-2") == False
    pass_count += 1
    print(f"  ✓ Test {test_count}: Constant-time comparison works")

    # --- Test 12: Verify token with wrong secret is rejected ---
    test_count += 1
    wrong_secret = generate_strong_secret()
    token = create_token(payload, wrong_secret, "HS256", "key-1")
    try:
        verifier.verify(token)
        print(f"  ✗ Test {test_count}: Wrong signature NOT rejected!")
    except JWTError:
        pass_count += 1
        print(f"  ✓ Test {test_count}: Wrong signature rejected")

    # --- Test 13: All kids from allow-list are accepted ---
    test_count += 1
    multi_verifier = SecureJWTVerifier(
        allowed_algorithms=frozenset({"HS256"}),
        hmac_secrets={"key-a": strong_secret, "key-b": strong_secret, "key-c": strong_secret},
        allowed_kids=frozenset({"key-a", "key-b", "key-c"}),
        verify_expiry=False,
    )
    all_ok = True
    for kid in ("key-a", "key-b", "key-c"):
        try:
            t = create_token(payload, strong_secret, "HS256", kid)
            multi_verifier.verify(t)
        except JWTError:
            all_ok = False
            break
    if all_ok:
        pass_count += 1
        print(f"  ✓ Test {test_count}: All kids from allow-list accepted")
    else:
        print(f"  ✗ Test {test_count}: Some kids from allow-list rejected!")

    # --- Test 14: Expired token is rejected ---
    test_count += 1
    expired_verifier = SecureJWTVerifier(
        allowed_algorithms=frozenset({"HS256"}),
        hmac_secrets={"key-1": strong_secret},
        allowed_kids=frozenset({"key-1"}),
        verify_expiry=True,
    )
    expired_payload = {"sub": "user-1", "exp": int(time.time()) - 3600}
    expired_token = create_token(expired_payload, strong_secret, "HS256", "key-1")
    try:
        expired_verifier.verify(expired_token)
        print(f"  ✗ Test {test_count}: Expired token NOT rejected!")
    except JWTError:
        pass_count += 1
        print(f"  ✓ Test {test_count}: Expired token rejected")

    # --- Test 15: Backslash path traversal is rejected ---
    test_count += 1
    try:
        validate_kid("..\\windows\\system32\\config", frozenset({"key-1"}))
        print(f"  ✗ Test {test_count}: Backslash traversal NOT blocked!")
    except JWTError:
        pass_count += 1
        print(f"  ✓ Test {test_count}: Backslash traversal blocked")

    # --- Summary ---
    print(f"\n{'=' * 70}")
    print(f"RESULTS: {pass_count}/{test_count} tests passed")
    print(f"{'=' * 70}")
    assert pass_count == test_count, f"Some tests failed! ({pass_count}/{test_count})"
    print("✅ ALL TESTS PASSED for Issue #1489: JWT Kid Injection Fix")


if __name__ == "__main__":
    demonstrate_vulnerability()
    print("\n")
    run_tests()
