# Fix: JWT Algorithm Confusion (RS256 → HS256 Downgrade) — Issue #1362

**Difficulty:** Hard · **Bounty:** $150 · **Labels:** security, bug, hard

## Vulnerability

The service issues JWTs signed with **RS256** (asymmetric). The IdP signs with
its RSA *private* key; verifiers check the signature with the RSA *public* key,
which is not secret.

A verifier that picks its verification algorithm from the token's own `alg`
header is exploitable. An attacker:

1. Changes the header `alg` from `RS256` to `HS256`.
2. Re-signs the token with **HMAC-SHA256 using the RSA public key bytes as the
   HMAC secret** (the public key is known to everyone).
3. Submits it. The verifier runs its HMAC branch with the same public-key bytes,
   the signature matches, and an arbitrary forged token (e.g. `role: admin`) is
   accepted.

The `none` algorithm (no signature) is a related trivial-forgery variant.

## Fix

Implemented in [`fix_1362.py`](./fix_1362.py) as `SecureRS256Verifier`:

1. **Algorithm is server policy, not token input.** Accepted algorithms are
   pinned at construction (`RS256` by default). `HS256/HS384/HS512` and `none`
   are rejected *before* any signature check.
2. **No HMAC code path exists.** The verifier only ever performs RSA
   verification, so the public key can never be used as an HMAC secret.
3. **Header key-injection blocked.** `jwk`/`jku`/`x5u`/`x5c`/`x5t` headers are
   rejected (sibling key-confusion vector).
4. **Constant-time RSA PKCS#1 v1.5** verification with the hash matching the
   pinned algorithm.
5. **Claim validation** (`exp`, `nbf`, `iss`, `aud`) after the signature is
   trusted, with optional clock `leeway`.
6. Non-RSA public keys (EC/DSA/OKP) are refused at construction.

## Verification

`tests/test_jwt_algorithm_confusion_downgrade_1362_fix.py` (8 tests, all pass)
reproduces the real exploit — forging an HS256 token whose HMAC secret is the
RSA public key — and asserts it is rejected, plus `none`, tampered payloads,
header-embedded keys, expiry, and issuer/audience enforcement.

## References

- CWE-347: Improper Verification of Cryptographic Signature
- CWE-757: Selection of Less-Secure Algorithm During Negotiation ('Downgrade')
- Auth0 / "Critical vulnerabilities in JSON Web Token libraries" (2015)
