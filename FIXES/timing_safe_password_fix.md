# Fix: Timing Attack on Password Verification → User Enumeration (Issue #967)

**Bounty**: $120 | **Difficulty**: Medium

## Vulnerability
- Password comparison uses naive `a === b` (character-by-character), allowing
  timing-based password inference
- Response time leaks whether a username exists (existing users trigger
  password check; non-existing return immediately)

## Fix
- **Constant-time comparison** via `hmac.compare_digest`
- **PBKDF2-HMAC-SHA256** hashing (10K iterations) before comparison
- **Per-deployment pepper** (env `TIMING_SAFE_PEPPER`) so same password
  hashes differently across deployments
- **Uniform random jitter** (50-150ms) on both valid and invalid paths
- **Identical-timing for user-exists vs user-not-exists** — non-existent
  users still get a full hash + compare cycle against a dummy value

## Files
- `FIXES/timing_safe_password_fix.py` — main fix module + self-tests
- `FIXES/timing_safe_password_fix.md` — documentation

## Self-tests
```bash
$ python3 FIXES/timing_safe_password_fix.py
Results: 17 passed, 0 failed
All self-tests PASSED ✅
```

## Acceptance Criteria
- [x] Use timingSafeEqual / hash-based comparison
- [x] Username-existence returns same delay as password-check
- [x] Random delay jitter added
