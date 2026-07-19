# Fix: JWT Kid Injection → Path Traversal → Secret Key Leak — Issue #1346

**Difficulty:** Hard · **Bounty:** $150 · **Labels:** security, bug, hard

## Vulnerability

The JWT verifier loads the signing key from a filesystem path built out of the
attacker-controlled `kid` (Key ID) header:

```python
kid = decode(token).header["kid"]            # attacker-controlled
key = open("/etc/app/keys/" + kid).read()    # path traversal
verify(token, key)
```

Consequences:

1. **Path traversal / secret-key leak.** `kid = "../../../../etc/passwd"` (or any
   readable file) makes the server use arbitrary file contents as the
   verification key. If the attacker knows or controls that file's contents (a
   world-readable file, an uploaded file, a predictable public key), they can
   forge a token that verifies — and probe/exfiltrate key files on disk.
2. **Algorithm/key confusion.** With an attacker-chosen `alg`, the loaded bytes
   become an HMAC secret, turning any known file into a forgery oracle.

CWE-22 (Path Traversal), CWE-73 (External Control of File Name/Path),
CWE-347 (Improper Verification of Cryptographic Signature).

## Fix

Implemented in [`fix_1346.py`](./fix_1346.py) as `SecureKidJWTVerifier`:

1. **Registry lookup, not filesystem.** Keys are resolved by `kid` from an
   in-memory registry. There is no `open()`/path construction anywhere, so path
   traversal has nothing to traverse. (A test asserts `open` is never called
   even for a traversal `kid`.)
2. **Strict `kid` charset.** `kid` must match `^[A-Za-z0-9_-]{1,64}$`, rejecting
   `/`, `\`, `..`, NUL bytes, newlines, and URL-like values *before* any lookup.
3. **Unknown kids rejected** — no dynamic or remote key loading.
4. **Header key-injection and `none` rejected** (`jwk`/`jku`/`x5u`/`x5c`).
5. **Algorithm pinned per kid** and signature verified with constant-time
   comparison.

## Verification

`tests/test_jwt_kid_injection_1346_fix.py` (9 tests, all pass): traversal /
absolute / newline / NUL / URL kids rejected; **verifier never touches the
filesystem** (guarded `open`); unknown kid, header-embedded key, and `none`
rejected; algorithm-pin enforced; valid registry token verifies; tampered
payload fails signature.

## References

- CWE-22, CWE-73, CWE-347
- Auth0 — "Critical vulnerabilities in JSON Web Token libraries"
