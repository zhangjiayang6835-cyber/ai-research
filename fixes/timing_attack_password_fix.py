"""
Fix for Issue #44: Timing Attack on Password Verification -> User Enumeration

Vulnerability
-------------
Password comparison was implemented with a naive equality check
(``return a === b`` / ``a == b``). String equality in most languages
short-circuits on the first mismatched byte, so the time taken to reject a
guess leaks information about how many leading characters were correct.
By measuring response latency an attacker can recover a password (or a
password hash) byte-by-byte.

A second, related leak: many login endpoints look the username up first and
return immediately (fast path) if the username does not exist, but perform a
slow password hash + comparison when the username DOES exist. The difference
in response time between "unknown user" and "known user, wrong password"
allows an attacker to enumerate valid usernames without ever guessing a
password.

Fix strategy (defense in depth)
--------------------------------
1. Never compare secrets with ``==``/``in``. Use ``hmac.compare_digest``,
   which performs a constant-time comparison over its entire length
   regardless of where the first difference occurs.
2. Always execute the *same* expensive code path (password hashing +
   constant-time compare) whether or not the username exists, by comparing
   against a deterministic, locally-generated dummy hash when the user is
   unknown. This removes the fast-path / slow-path timing distinguisher.
3. Apply a minimum floor time plus small random jitter to every
   authentication response so that any remaining variance (GC pauses,
   scheduler noise, cache effects) is masked and cannot be reliably
   correlated with correctness by a remote attacker.
4. Return one generic result/message for every failure mode (wrong
   password, unknown user, locked account) — never a distinguishable
   error per case.

The module is dependency-light (stdlib ``hmac``/``hashlib``/``secrets``
only) so it can be dropped into any Python auth service.

Refs: CWE-208 (Observable Timing Discrepancy), CWE-204 (Response
Discrepancy Info Exposure), OWASP ASVS V2.1 / V2.2.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import random
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Floor + jitter applied to EVERY auth attempt so total latency is
# statistically indistinguishable across success / wrong-password /
# unknown-user outcomes.
_FLOOR_SECONDS = 0.15
_JITTER_MAX_SECONDS = 0.05

# A fixed, process-wide "pepper" used only to derive a stable dummy hash for
# unknown usernames, so the unknown-user path performs real hashing work
# (not a shortcut) but never authenticates.
_DUMMY_PEPPER = os.urandom(32)


def _hash_password(password: str, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256. Deliberately expensive so real and dummy paths
    cost the same amount of CPU time."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)


def _dummy_hash_for(username: str) -> Tuple[bytes, bytes]:
    """Deterministic (salt, hash) pair for a username that does not exist.

    Deterministic per-username so repeated attempts against the same
    unknown username behave identically, but the hash never matches any
    real password because it is derived from a secret pepper the caller
    can never supply as a password.
    """
    salt = hashlib.sha256(_DUMMY_PEPPER + username.encode("utf-8")).digest()[:16]
    dummy_secret = hmac.new(_DUMMY_PEPPER, username.encode("utf-8"), hashlib.sha256).hexdigest()
    return salt, _hash_password(dummy_secret, salt)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time byte comparison.

    Wraps ``hmac.compare_digest`` (implemented in C, guaranteed constant
    time for equal-length inputs) instead of ``a == b`` / ``a in b``, which
    short-circuit on the first differing byte and leak timing information.
    """
    if not isinstance(a, (bytes, bytearray)) or not isinstance(b, (bytes, bytearray)):
        raise TypeError("constant_time_compare requires bytes-like arguments")
    return hmac.compare_digest(bytes(a), bytes(b))


@dataclass
class StoredUser:
    username: str
    salt: bytes
    password_hash: bytes
    locked: bool = False


@dataclass
class UserStore:
    """Minimal in-memory user store used by the self-tests / example wiring.

    Replace with your real user repository (DB, LDAP, etc.) — the important
    part is that ``verify_password`` below never branches on "user exists"
    before doing the same amount of work as the "user exists" path.
    """

    users: Dict[str, StoredUser] = field(default_factory=dict)

    def add_user(self, username: str, password: str) -> None:
        salt = os.urandom(16)
        self.users[username.lower()] = StoredUser(
            username=username,
            salt=salt,
            password_hash=_hash_password(password, salt),
        )

    def get(self, username: str) -> Optional[StoredUser]:
        return self.users.get(username.lower())


def _sleep_with_floor_and_jitter(elapsed: float) -> None:
    """Sleep so that total time since the call started is at least
    ``_FLOOR_SECONDS``, plus a small random jitter, regardless of outcome.
    """
    remaining = _FLOOR_SECONDS - elapsed
    jitter = random.uniform(0, _JITTER_MAX_SECONDS)
    delay = max(remaining, 0.0) + jitter
    if delay > 0:
        time.sleep(delay)


def verify_password(store: UserStore, username: str, password: str) -> bool:
    """Authenticate ``username``/``password`` against ``store``.

    Always performs the same hashing + constant-time comparison work
    whether the username exists or not, and always applies the same
    floor+jitter delay, so neither branch nor response time leaks whether
    the username is valid or whether the password was close to correct.
    """
    t0 = time.perf_counter()
    try:
        user = store.get(username)
        if user is not None:
            salt = user.salt
            expected_hash = user.password_hash
        else:
            # Unknown username: still hash + compare against a deterministic
            # dummy value so the code path and CPU cost match the "known
            # user" branch exactly. This removes the fast-reject shortcut
            # that would otherwise leak account existence via timing.
            salt, expected_hash = _dummy_hash_for(username)

        candidate_hash = _hash_password(password, salt)
        match = constant_time_compare(candidate_hash, expected_hash)

        # Never authenticate against the dummy path, even if by some
        # astronomically unlikely coincidence the hashes matched, and never
        # authenticate a locked account.
        if user is None:
            return False
        if user.locked:
            return False
        return match
    finally:
        elapsed = time.perf_counter() - t0
        _sleep_with_floor_and_jitter(elapsed)


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

def _run_self_tests() -> None:  # pragma: no cover - executed via __main__
    tests: Dict[str, bool] = {}

    store = UserStore()
    store.add_user("alice", "correct-horse-battery-staple")

    # 1. Correct credentials succeed.
    tests["correct_password_ok"] = verify_password(store, "alice", "correct-horse-battery-staple")

    # 2. Wrong password fails.
    tests["wrong_password_fails"] = not verify_password(store, "alice", "wrong-password")

    # 3. Unknown username fails (same generic False, no exception, no distinct
    #    return type).
    tests["unknown_user_fails"] = not verify_password(store, "bob", "anything")

    # 4. constant_time_compare never uses == internally — verify it detects
    #    both length and content mismatches without raising.
    tests["ct_compare_equal"] = constant_time_compare(b"secret123", b"secret123")
    tests["ct_compare_diff_content"] = not constant_time_compare(b"secret123", b"secret124")
    tests["ct_compare_diff_length"] = not constant_time_compare(b"short", b"much-longer-value")

    # 5. Locked accounts never authenticate even with correct password.
    store.users["alice"].locked = True
    tests["locked_account_fails"] = not verify_password(store, "alice", "correct-horse-battery-staple")
    store.users["alice"].locked = False

    # 6. Statistical timing sanity check: average latency for "known user,
    #    wrong password" vs "unknown user" should be close (within a
    #    generous tolerance — this is a smoke test, not a formal proof,
    #    since CI machines are noisy).
    trials = 8

    def _avg(fn) -> float:
        total = 0.0
        for _ in range(trials):
            t0 = time.perf_counter()
            fn()
            total += time.perf_counter() - t0
        return total / trials

    avg_known_wrong = _avg(lambda: verify_password(store, "alice", "nope"))
    avg_unknown = _avg(lambda: verify_password(store, "someone-who-does-not-exist", "nope"))
    # Both should be close to the floor; allow generous tolerance for CI jitter.
    tests["timing_close_known_vs_unknown"] = abs(avg_known_wrong - avg_unknown) < (_FLOOR_SECONDS)

    for name, ok in tests.items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    assert all(tests.values()), "self-tests failed"
    print(f"\n  {len(tests)} / {len(tests)} passed")


if __name__ == "__main__":  # pragma: no cover
    print("timing_attack_password_fix — self-tests")
    _run_self_tests()
