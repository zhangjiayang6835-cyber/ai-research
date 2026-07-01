"""
Fix #201: Padding Oracle Attack on Encrypted Session Cookies.

Root cause
----------
Legacy session cookies were encrypted with unauthenticated AES-CBC. A padding
oracle attack (Vaudenay 2002) lets a network attacker recover plaintext — and
often forge arbitrary session state — by observing whether the server returns
a distinct error / timing signal for "bad padding" vs. "bad content".

Any of the following creates the oracle:
    * different HTTP status / body for PaddingError vs. deserialization error
    * different response time (padding check is fast, downstream parse is slow)
    * decrypting first and *then* validating a MAC (MAC-then-Encrypt / no MAC)
    * catching cryptography exceptions and logging a class-specific message

Defense
-------
1. Use authenticated encryption (AES-256-GCM). GCM's tag is verified before
   any plaintext is released, so there is no padding step to probe.
2. Bind the ciphertext to context (cookie name, user id, purpose) via GCM's
   AAD channel — a stolen cookie cannot be replayed as a different cookie.
3. Use hkdf-derived per-purpose subkeys from a single master secret so key
   rotation is atomic across all cookie types.
4. Constant-time equality for any auxiliary comparisons, and a *single*
   generic "invalid session" error for every failure mode (bad tag, wrong
   key id, expired, malformed base64, decode failure) so no oracle leaks.
5. Include a monotonic issued-at + max-age so replayed valid ciphertexts
   still expire.
6. Support versioned key ids ("kid") for zero-downtime rotation.

This module is dependency-light: it uses only the `cryptography` package,
which is already the standard for Python server-side crypto.

Refs: CWE-310, CWE-347, OWASP ASVS V6, RFC 5116 (AEAD), NIST SP 800-38D.
"""

from __future__ import annotations

import base64
import hmac
import os
import secrets
import struct
import time
from dataclasses import dataclass
from typing import Dict, Mapping, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAGIC = b"SC1"                     # session-cookie v1 header
_HDR_STRUCT = ">3sBBQ"              # magic, version, kid, issued_at
_HDR_LEN = struct.calcsize(_HDR_STRUCT)
_NONCE_LEN = 12                     # GCM standard nonce length
_KEY_LEN = 32                       # AES-256
_MAX_COOKIE_BYTES = 4096            # RFC 6265 practical cap
_MIN_MASTER_KEY_BYTES = 32


class InvalidSession(Exception):
    """Single generic error for every decryption failure mode.

    Callers MUST NOT branch on the exception message or introduce
    subclasses that would let an attacker distinguish failure causes
    over the wire. Timing is also equalized inside ``decrypt_cookie``.
    """


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CookieKeyring:
    """Versioned symmetric keys for cookie encryption.

    ``master_keys`` maps a small integer key-id (0..255) to a >=32-byte
    master secret loaded from a KMS / secret store. ``active_kid`` picks
    which key is used for *new* cookies. All keys stay available for
    decryption so rotation is instant and non-disruptive.
    """

    master_keys: Mapping[int, bytes]
    active_kid: int

    def __post_init__(self) -> None:
        if self.active_kid not in self.master_keys:
            raise ValueError("active_kid missing from master_keys")
        for kid, mk in self.master_keys.items():
            if not (0 <= kid <= 255):
                raise ValueError("kid must fit in one byte")
            if not isinstance(mk, (bytes, bytearray)) or len(mk) < _MIN_MASTER_KEY_BYTES:
                raise ValueError(f"master key kid={kid} must be >= 32 bytes")

    def derive(self, kid: int, purpose: bytes) -> bytes:
        """HKDF-SHA256 derivation: distinct subkey per (kid, purpose)."""
        if kid not in self.master_keys:
            raise InvalidSession()  # unknown kid = generic failure
        return HKDF(
            algorithm=hashes.SHA256(),
            length=_KEY_LEN,
            salt=b"session-cookie/v1",
            info=purpose,
        ).derive(bytes(self.master_keys[kid]))


# ---------------------------------------------------------------------------
# Encode / decode
# ---------------------------------------------------------------------------

def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    # add padding back; reject non-ascii and oversized inputs early
    if len(s) > _MAX_COOKIE_BYTES:
        raise InvalidSession()
    try:
        pad = "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s.encode("ascii") + pad.encode("ascii"))
    except Exception:  # noqa: BLE001 - collapse to generic
        raise InvalidSession()


def encrypt_cookie(
    keyring: CookieKeyring,
    payload: bytes,
    *,
    purpose: bytes,
    issued_at: Optional[int] = None,
) -> str:
    """Return an AEAD-protected, URL-safe cookie string.

    ``purpose`` binds the ciphertext to a specific cookie (e.g. b"auth",
    b"csrf"). Decrypting with the wrong purpose yields InvalidSession.
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes")
    if not isinstance(purpose, (bytes, bytearray)) or not purpose:
        raise ValueError("purpose must be non-empty bytes")

    kid = keyring.active_kid
    ts = int(issued_at if issued_at is not None else time.time())
    if ts < 0 or ts >> 63:
        raise ValueError("issued_at out of range")

    header = struct.pack(_HDR_STRUCT, _MAGIC, 1, kid, ts)
    key = keyring.derive(kid, purpose)
    nonce = os.urandom(_NONCE_LEN)
    # AAD = header + purpose → binds context into the tag
    aad = header + b"|" + bytes(purpose)
    ct = AESGCM(key).encrypt(nonce, bytes(payload), aad)
    return _b64e(header + nonce + ct)


def decrypt_cookie(
    keyring: CookieKeyring,
    cookie: str,
    *,
    purpose: bytes,
    max_age_seconds: int,
    now: Optional[int] = None,
) -> bytes:
    """Return the original payload, or raise InvalidSession.

    Every failure — malformed base64, wrong magic, unknown kid, wrong
    purpose, tag mismatch, expired — raises the exact same exception
    class with no message discrimination. A constant floor time is
    applied so that "fast rejects" (bad header) are indistinguishable
    from "slow rejects" (full AEAD verification) to a remote attacker.
    """
    t0 = time.perf_counter_ns()
    try:
        return _decrypt_inner(keyring, cookie, purpose, max_age_seconds, now)
    except InvalidSession:
        raise
    except Exception:  # noqa: BLE001 - never leak a distinct exception
        raise InvalidSession()
    finally:
        # Equalize timing: sleep-spin until >= 500µs elapsed. Cheap enough
        # for a cookie path, dwarfs the actual AEAD/HKDF cost variance.
        _floor_ns = 500_000
        while time.perf_counter_ns() - t0 < _floor_ns:
            pass


def _decrypt_inner(
    keyring: CookieKeyring,
    cookie: str,
    purpose: bytes,
    max_age_seconds: int,
    now: Optional[int],
) -> bytes:
    if not isinstance(cookie, str) or not cookie:
        raise InvalidSession()
    if not isinstance(purpose, (bytes, bytearray)) or not purpose:
        raise InvalidSession()
    if max_age_seconds <= 0:
        raise InvalidSession()

    raw = _b64d(cookie)
    if len(raw) < _HDR_LEN + _NONCE_LEN + 16:  # 16 = GCM tag
        raise InvalidSession()

    magic, version, kid, issued_at = struct.unpack(_HDR_STRUCT, raw[:_HDR_LEN])
    # Constant-time compare on the fixed magic to avoid short-circuit signal
    if not hmac.compare_digest(magic, _MAGIC) or version != 1:
        raise InvalidSession()

    now_ts = int(now if now is not None else time.time())
    if issued_at > now_ts + 60:            # future-dated → reject (with slack)
        raise InvalidSession()
    if now_ts - issued_at > max_age_seconds:
        raise InvalidSession()

    nonce = raw[_HDR_LEN:_HDR_LEN + _NONCE_LEN]
    ct = raw[_HDR_LEN + _NONCE_LEN:]

    key = keyring.derive(kid, purpose)
    aad = raw[:_HDR_LEN] + b"|" + bytes(purpose)
    # AESGCM.decrypt raises InvalidTag on any bit flip / wrong AAD / wrong key.
    # There is NO padding step and no separate "bad content" path, so no
    # oracle can be constructed.
    return AESGCM(key).decrypt(nonce, ct, aad)


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

def _fresh_keyring() -> CookieKeyring:
    return CookieKeyring(
        master_keys={
            1: secrets.token_bytes(32),
            2: secrets.token_bytes(32),
        },
        active_kid=2,
    )


def _run_self_tests() -> None:  # pragma: no cover - executed via __main__
    tests: Dict[str, bool] = {}

    kr = _fresh_keyring()
    payload = b'{"uid":42,"role":"user"}'

    # 1. round-trip
    c = encrypt_cookie(kr, payload, purpose=b"auth")
    tests["roundtrip"] = decrypt_cookie(kr, c, purpose=b"auth", max_age_seconds=3600) == payload

    # 2. tampered ciphertext → InvalidSession (no padding oracle)
    raw = bytearray(_b64d(c))
    raw[-1] ^= 0x01
    tampered = _b64e(bytes(raw))
    try:
        decrypt_cookie(kr, tampered, purpose=b"auth", max_age_seconds=3600)
        tests["tag_tamper_rejected"] = False
    except InvalidSession:
        tests["tag_tamper_rejected"] = True

    # 3. flipping bytes across the ciphertext yields ONLY InvalidSession —
    #    i.e. the exception class is identical for every corruption offset
    #    (this is the property that kills a padding oracle).
    consistent = True
    for offset in range(_HDR_LEN + _NONCE_LEN, len(raw)):
        mutated = bytearray(_b64d(c))
        mutated[offset] ^= 0x5A
        try:
            decrypt_cookie(kr, _b64e(bytes(mutated)),
                           purpose=b"auth", max_age_seconds=3600)
            consistent = False
            break
        except InvalidSession:
            pass
        except Exception:
            consistent = False
            break
    tests["no_oracle_class_leak"] = consistent

    # 4. wrong purpose → reject (AAD binding)
    try:
        decrypt_cookie(kr, c, purpose=b"csrf", max_age_seconds=3600)
        tests["purpose_binding"] = False
    except InvalidSession:
        tests["purpose_binding"] = True

    # 5. expired cookie
    old = encrypt_cookie(kr, payload, purpose=b"auth",
                        issued_at=int(time.time()) - 10_000)
    try:
        decrypt_cookie(kr, old, purpose=b"auth", max_age_seconds=60)
        tests["expiry"] = False
    except InvalidSession:
        tests["expiry"] = True

    # 6. future-dated cookie
    fut = encrypt_cookie(kr, payload, purpose=b"auth",
                        issued_at=int(time.time()) + 10_000)
    try:
        decrypt_cookie(kr, fut, purpose=b"auth", max_age_seconds=3600)
        tests["future_dated"] = False
    except InvalidSession:
        tests["future_dated"] = True

    # 7. unknown kid → reject
    kr2 = CookieKeyring(master_keys={9: secrets.token_bytes(32)}, active_kid=9)
    try:
        decrypt_cookie(kr2, c, purpose=b"auth", max_age_seconds=3600)
        tests["unknown_kid"] = False
    except InvalidSession:
        tests["unknown_kid"] = True

    # 8. key rotation: old kid still decrypts, new cookies use new kid
    old_kid_cookie = encrypt_cookie(
        CookieKeyring(master_keys=kr.master_keys, active_kid=1),
        payload, purpose=b"auth")
    tests["rotation_backward_compat"] = decrypt_cookie(
        kr, old_kid_cookie, purpose=b"auth", max_age_seconds=3600) == payload

    # 9. garbage input
    for junk in ("", "!!!", "A" * 5000, "not-base64!@#$"):
        try:
            decrypt_cookie(kr, junk, purpose=b"auth", max_age_seconds=3600)
            tests[f"garbage[{junk[:6]!r}]"] = False
            break
        except InvalidSession:
            continue
    else:
        tests["garbage_rejected"] = True

    # 10. truncated ciphertext
    trunc = _b64e(_b64d(c)[:_HDR_LEN + _NONCE_LEN + 4])
    try:
        decrypt_cookie(kr, trunc, purpose=b"auth", max_age_seconds=3600)
        tests["truncation"] = False
    except InvalidSession:
        tests["truncation"] = True

    # 11. header magic mismatch → reject via constant-time compare
    bad_header = bytearray(_b64d(c))
    bad_header[0] = ord("X")
    try:
        decrypt_cookie(kr, _b64e(bytes(bad_header)),
                       purpose=b"auth", max_age_seconds=3600)
        tests["magic_mismatch"] = False
    except InvalidSession:
        tests["magic_mismatch"] = True

    # 12. weak master key rejected at construction time
    try:
        CookieKeyring(master_keys={1: b"short"}, active_kid=1)
        tests["weak_key_rejected"] = False
    except ValueError:
        tests["weak_key_rejected"] = True

    for name, ok in tests.items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    assert all(tests.values()), "self-tests failed"
    print(f"\n  {len(tests)} / {len(tests)} passed")


if __name__ == "__main__":  # pragma: no cover
    print("padding_oracle_cookie_fix — self-tests")
    _run_self_tests()
