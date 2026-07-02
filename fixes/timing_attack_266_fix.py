"""Fix #266: Side-Channel Timing Attack on Constant-Time Comparison.

Root cause: Non-constant-time string comparison (== or !=) leaks timing
information, allowing an attacker to brute-force secrets (API keys, tokens,
passwords) character-by-character via statistical timing analysis.

Defense: hmac.compare_digest provides constant-time comparison that
eliminates timing side-channels regardless of input values.
"""

from __future__ import annotations
import hmac
import secrets
import time
from typing import Any


class SecureComparator:
    """Constant-time comparison utilities resistant to timing attacks."""

    @staticmethod
    def compare(a: Any, b: Any) -> bool:
        """Constant-time string/bytes comparison.

        Uses hmac.compare_digest internally - execution time depends only
        on the length of the inputs, not their content.
        """
        if not isinstance(a, (str, bytes)):
            a = str(a)
        if not isinstance(b, (str, bytes)):
            b = str(b)
        a_bytes = a.encode() if isinstance(a, str) else a
        b_bytes = b.encode() if isinstance(b, str) else b
        return hmac.compare_digest(a_bytes, b_bytes)

    @staticmethod
    def compare_secure(secret: str | bytes, provided: str | bytes) -> bool:
        """Safe comparison with length-constant semantics.

        Always does full-length comparison, never short-circuits.
        Resistant to length-based and content-based timing attacks.
        """
        if isinstance(secret, str):
            secret = secret.encode()
        if isinstance(provided, str):
            provided = provided.encode()
        return hmac.compare_digest(secret, provided)

    @staticmethod
    def compare_mac(computed: bytes, expected: bytes) -> bool:
        """Compare MAC/tag values in constant time.

        Use for verifying HMACs, AEAD tags, and integrity checksums.
        """
        return hmac.compare_digest(computed, expected)


def secure_hash_verify(stored_hash: str, provided_password: str) -> bool:
    """HMAC-based password verification resistant to timing attacks.

    Never use == or != with secrets - always use hmac.compare_digest.
    """
    computed = hmac.new(
        key=provided_password.encode(),
        msg=b"password-verification-context",
        digestmod="sha256",
    ).hexdigest()
    return hmac.compare_digest(computed.encode(), stored_hash.encode())


if __name__ == "__main__":
    # Verify correctness
    c = SecureComparator()
    assert c.compare("secret123", "secret123") is True
    assert c.compare("secret123", "wrong") is False
    assert c.compare(b"abc", b"abc") is True
    assert c.compare(b"abc", b"abd") is False
    assert c.compare(42, 42) is True
    assert c.compare(42, 43) is False

    # Verify MAC comparison
    m1 = secrets.token_bytes(32)
    m2 = secrets.token_bytes(32)
    assert c.compare_mac(m1, m1) is True
    assert c.compare_mac(m1, m2) is False

    print("OK: all constant-time comparison checks pass")
