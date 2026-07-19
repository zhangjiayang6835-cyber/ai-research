# Fix: TOTP Secret Leaked via QR Code in Logs — Issue #1353

**Difficulty:** Hard · **Bounty:** $150 · **Labels:** security, bug, hard

## Vulnerability

During 2FA setup the server builds an `otpauth://` provisioning URI and renders
it as a QR code. That URI embeds the raw base32 TOTP shared secret:

```
otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example
```

The QR-code generation step is logged (tracing / debug / access / exception
logs), so the full URI — including `secret=...` — lands in logs. Anyone with log
access (SIEM, aggregator, backups, on-call) can read the secret and mint valid
TOTP codes indefinitely, bypassing 2FA. (CWE-532: Insertion of Sensitive
Information into Log File.)

## Fix

Implemented in [`fix_1353.py`](./fix_1353.py) with two layers:

1. **`SensitiveDataRedactor` (`logging.Filter`)** — scrubs `otpauth://` URIs and
   sensitive `key=value` pairs (`secret`, `token`, `password`, ...) from every
   log record's message and `%` args before emission. The secret is removed
   **entirely** — no prefix characters are left behind. For dict-style args it
   also redacts by sensitive *field name*, catching a bare secret value with no
   surrounding context. Install app-wide with `install_redaction()`.
2. **`SecureTOTPProvisioner`** — builds the provisioning URI for QR rendering but
   logs only non-sensitive metadata (issuer + account); the secret and URI are
   returned to the caller and never passed to a logging call.

`redact()` is also exposed for sanitising arbitrary strings (audit trails, etc.).

## Contrast with the naive patch

A regex "masker" that replaces `secret=JBSWY...` with `group()[:10] + "MASKED"`
still leaks the first characters of the secret (`secret=` is 7 chars, so 3 secret
characters survive), and a scanner that records `match[:30]` copies the secret
into its own findings. This fix removes the value in full and never stores it.

## Verification

`tests/test_totp_secret_leak_1353_fix.py` (8 tests, all pass): secret redacted
from log message, `%`-args, and dict-args; full URI removed; no prefix leak;
non-sensitive text preserved; and the provisioner's returned URI contains the
secret while its logs do not.

## References

- CWE-532: Insertion of Sensitive Information into Log File
- CWE-312: Cleartext Storage of Sensitive Information
- OWASP ASVS V7 (Logging) — no secrets in logs
