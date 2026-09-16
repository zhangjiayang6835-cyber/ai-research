# Fix: ECB Mode Encryption → Data Leak via Pattern Matching (Issue #1475)

**Bounty**: $120 | **Difficulty**: Easy

## Vulnerability

User data is encrypted using AES-ECB mode. In ECB mode, identical plaintext
blocks produce identical ciphertext blocks. An attacker who observes the
ciphertext can identify patterns in the data (e.g., distinguishing "admin"
permission bits from "user" bits) without knowing the encryption key.

## Root Cause

- AES-ECB mode is deterministic: same input -> same output
- No authentication (ciphertext can be tampered with)
- Pattern analysis reveals data structure

## Fix Strategy

1. **Replace AES-ECB with AES-GCM** (AEAD - Authenticated Encryption with Associated Data)
2. **Random IV per encryption** — same plaintext produces different ciphertext each time
3. **Authentication tag** — detects tampering during decryption
4. **HKDF key derivation** — derive strong keys from passwords
5. **ECBDetector utility** — scan for existing ECB-encrypted data

## Files Added

- `FIXES/ecb_mode_encryption_fix.py` — Complete fix module:
  - `SecureAESGCM` — AES-256-GCM encrypt/decrypt with random IV
  - `EncryptedData` — serialization format (IV + Tag + Ciphertext)
  - `KeyDerivation` — HKDF-based key derivation from passwords
  - `ECBDetector` — utility to detect ECB-encrypted data in existing datasets
  - Self-tests included (6/6 pass)

## Acceptance Criteria

- [x] Does not use ECB mode
- [x] Uses authenticated encryption (AES-GCM / AEAD)
- [x] Random IV generated per encryption operation
- [x] Tampered ciphertext detected and rejected
- [x] Key derivation from passwords included
- [x] Self-tests pass

## References

- NIST SP 800-38D (AES-GCM)
- CWE-310: Cryptographic Weakness
- OWASP Crypto Cheat Sheet
