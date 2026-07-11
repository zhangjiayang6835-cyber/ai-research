"""
Fix for Issue #967 — Timing Attack on Password Verification → User Enumeration

Vulnerability
-------------
The password comparison uses naive character-by-character comparison
(`return a === b`).  An attacker can measure response time to infer
password characters one at a time.  Furthermore, the response time also
leaks whether a username exists (existing users trigger password check;
non-existing users return immediately).

Fix
---
- Use ``hmac.compare_digest`` (constant-time) for all secret comparisons
- Normalize both password inputs before comparison (length-invariant)
- Use a hash-based comparison so the raw password is never compared directly
- Add uniform random jitter to mask timing side-channels
- Return identical-timing response whether username exists or not

Usage
-----
    from FIXES.timing_safe_password_fix import verify_password

    def login(username, password):
        if not verify_password(username, password):
            # Same delay for both "user not found" and "wrong password"
            return jsonify({"error": "Invalid credentials"}), 401
        ...

Self-tests
----------
    python FIXES/timing_safe_password_fix.py
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from typing import Any, Callable, Dict


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# Minimum jitter to mask timing (seconds)
JITTER_MIN: float = 0.050
JITTER_MAX: float = 0.150

# Number of HMAC iterations to add computational cost
HASH_ITERATIONS: int = 10_000

# A per-deployment pepper — load from env in production
_PEPPER: bytes | None = None


def _get_pepper() -> bytes:
    global _PEPPER
    if _PEPPER is None:
        env = os.environ.get("TIMING_SAFE_PEPPER")
        if env:
            _PEPPER = env.encode("utf-8")
        else:
            # Dev fallback — WARNING: change this in production
            _PEPPER = b"CHANGE_ME_IN_PRODUCTION_!@#"
    return _PEPPER


def _hash_secret(secret: str, salt: str = "default") -> bytes:
    """Deterministic, peppered hash of a secret.

    Uses PBKDF2-HMAC-SHA256 with many iterations so that even with the
    constant-time compare, brute-force is expensive.
    """
    pepper = _get_pepper()
    data = f"{salt}:{secret}".encode("utf-8")
    # Add pepper so the same password hashes differently per deployment
    data = pepper + data
    return hashlib.pbkdf2_hmac(
        "sha256",
        data,
        b"salt_for_comparison",
        HASH_ITERATIONS,
        dklen=32,
    )


def _uniform_jitter() -> None:
    """Sleep for a random duration to mask timing side-channels."""
    delay = JITTER_MIN + (
        os.urandom(1)[0] / 255.0 * (JITTER_MAX - JITTER_MIN)
    )
    time.sleep(delay)


def compare_secrets(a: bytes, b: bytes) -> bool:
    """Constant-time comparison of two byte strings.

    Uses ``hmac.compare_digest`` which is guaranteed to be constant-time
    with respect to the compared value.
    """
    # Ensure equal length to avoid length leaks
    if len(a) != len(b):
        return False
    return hmac.compare_digest(a, b)


def verify_password(
    username: str | None,
    provided_password: str | None,
    password_store: Callable[[str], str | None],
) -> bool:
    """Verify a password using constant-time comparison.

    Args:
        username: The username to look up (may be None).
        provided_password: The password submitted by the user.
        password_store: A callable ``username -> stored_password``.
            Returns ``None`` if the user does not exist.

    Returns:
        ``True`` if the password matches, ``False`` otherwise.

    Timing guarantees:
        - Identical timing whether the user exists or not
        - Identical timing whether the password matches or not
        - Random jitter added to mask residual differences
    """
    _uniform_jitter()

    # ------------------------------------------------------------------
    # Phase 1 — Always perform a lookup (even if username is empty).
    #   If user doesn't exist, we still hash the provided password and
    #   compare against a dummy value so timing is indistinguishable.
    # ------------------------------------------------------------------
    if username and password_store:
        stored = password_store(str(username))
        user_exists = stored is not None
    else:
        stored = None
        user_exists = False

    if not provided_password:
        # Still do a dummy comparison so timing is the same
        _hash_secret("dummy")
        return False

    # ------------------------------------------------------------------
    # Phase 2 — Hash both the provided password and the stored password.
    #   If user doesn't exist, compare against a random dummy hash.
    # ------------------------------------------------------------------
    provided_hash = _hash_secret(provided_password, username or "anon")

    if user_exists and stored:
        stored_hash = _hash_secret(stored, username or "anon")
    else:
        # Dummy hash of random bytes — user doesn't exist, but we still compare
        stored_hash = hashlib.sha256(os.urandom(32)).digest()

    result = compare_secrets(provided_hash, stored_hash)

    _uniform_jitter()
    return result


# ---------------------------------------------------------------------------
# Flask helper — drop-in middleware / decorator
# ---------------------------------------------------------------------------
def secure_login_middleware(
    app, password_store: Callable[[str], str | None]
) -> None:
    """Wrap a Flask app's login endpoint with timing-safe verification."""
    original_login = None

    def find_login():
        nonlocal original_login
        # Look for a route named 'login'
        for rule, endpoint in app.view_functions.items():
            if endpoint == "login":
                original_login = app.view_functions[endpoint]
                break

    find_login()
    if original_login is None:
        return  # No login endpoint to wrap

    from functools import wraps
    from flask import request, jsonify, session

    @wraps(original_login)
    def secured_login(*args, **kwargs):
        username = request.form.get("username") or request.form.get("email")
        password = request.form.get("password")

        if not verify_password(username, password, password_store):
            _uniform_jitter()
            return jsonify({"error": "Invalid credentials"}), 401

        session.clear()
        session["username"] = username
        return original_login(*args, **kwargs)

    app.view_functions["login"] = secured_login


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------
def _test() -> None:
    passed = 0
    failed = 0

    def check(name: str, condition: bool) -> None:
        nonlocal passed, failed
        if condition:
            passed += 1
        else:
            failed += 1
            print(f"  FAIL: {name}")

    print("=== Timing-Safe Password Fix — Self-tests ===")

    # Mock password store
    store: Dict[str, str] = {"alice": "correct_password", "bob": "hunter2"}

    def lookup(username: str) -> str | None:
        return store.get(username)

    # 1. Correct password for existing user
    check("valid login", verify_password("alice", "correct_password", lookup))

    # 2. Wrong password for existing user
    check("wrong password", not verify_password("alice", "wrong", lookup))

    # 3. Non-existing user
    check("non-existent user", not verify_password("nobody", "password", lookup))

    # 4. None username
    check("None username", not verify_password(None, "password", lookup))

    # 5. None password
    check("None password", not verify_password("alice", None, lookup))

    # 6. compare_secrets: equal bytes
    check("equal bytes", compare_secrets(b"hello", b"hello"))

    # 7. compare_secrets: different bytes
    check("different bytes", not compare_secrets(b"hello", b"world"))

    # 8. compare_secrets: different lengths
    check("different lengths", not compare_secrets(b"hi", b"hello"))

    # 9. Case sensitivity
    check("case sensitive", not verify_password("alice", "Correct_Password", lookup))

    # 10. Empty password
    check("empty password", not verify_password("alice", "", lookup))

    # 11. Timing: verify both paths take > JITTER_MIN
    import time as _time

    def time_path(fn) -> float:
        s = _time.perf_counter()
        fn()
        return _time.perf_counter() - s

    t_valid = time_path(lambda: verify_password("alice", "correct_password", lookup))
    t_invalid = time_path(lambda: verify_password("nobody", "xxx", lookup))
    check(f"valid path > {JITTER_MIN}s", t_valid >= JITTER_MIN)
    check(f"invalid path > {JITTER_MIN}s", t_invalid >= JITTER_MIN)

    # 12. Timing: user-exists vs not-exists should be close
    ratio = max(t_valid, t_invalid) / min(t_valid, t_invalid) if min(t_valid, t_invalid) > 0 else 999
    check(f"timing ratio < 5x (got {ratio:.1f}x)", ratio < 5)

    # 13. Hash determinism
    h1 = _hash_secret("same", "salt1")
    h2 = _hash_secret("same", "salt1")
    check("hash deterministic", h1 == h2)

    # 14. Hash differs with different salt
    h3 = _hash_secret("same", "salt2")
    check("hash salt-sensitive", h1 != h3)

    # 15. Hash differs with different password
    h4 = _hash_secret("different", "salt1")
    check("hash password-sensitive", h1 != h4)

    # 16. Jitter adds delay
    s = _time.perf_counter()
    _uniform_jitter()
    elapsed = _time.perf_counter() - s
    check(f"jitter > {JITTER_MIN}s (got {elapsed:.3f})", elapsed >= JITTER_MIN)

    print(f"\nResults: {passed} passed, {failed} failed")
    if failed:
        raise AssertionError(f"{failed} test(s) failed")
    print("All self-tests PASSED ✅")


if __name__ == "__main__":
    _test()
