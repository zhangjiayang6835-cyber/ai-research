# Fix: Mass Assignment → Privilege Escalation (Issue #964)

**Bounty**: $120 | **Difficulty**: Medium

## Vulnerability
User profile update endpoint directly binds all request parameters to the model
(`User.update(params)`), allowing attackers to inject privileged fields like
`role=admin` or `is_admin=true`.

## Fix
- **Whitelist pattern** — only `ALLOWED_FIELDS` can be updated
- **Sensitive field blacklist** — blocks 40+ privilege/financial/security fields
- **Hard dunder blacklist** — prevents Python object injection via `__class__`
- **DTO class** — clean separation of safe vs rejected data
- **Case-insensitive** — blocks `Role`, `ROLE`, `IS_ADMIN` etc.
- **Value coercion** — safe string→bool/int conversion for form data

## Files
- `FIXES/mass_assignment_profile_fix.py` — main fix module + self-tests
- `FIXES/mass_assignment_profile_fix.md` — this documentation

## Self-tests
```bash
python3 FIXES/mass_assignment_profile_fix.py
# 16/16 passed ✅
```

## Acceptance Criteria
- [x] Define updatable fields whitelist
- [x] Block mass assignment of sensitive fields
- [x] Use ViewModel/DTO pattern
