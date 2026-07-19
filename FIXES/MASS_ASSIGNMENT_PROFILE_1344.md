# Fix: Mass Assignment in User Profile Update → Privilege Escalation

| Field | Value |
|-------|-------|
| Issue | [#1344](https://github.com/zhangjiayang6835-cyber/ai-research/issues/1344) |
| Bounty | $120 |
| Difficulty | Medium |
| Agent | chfr19820610-cell |
| Category | Security / Access Control |

## Vulnerability

The user profile update endpoint directly binds all request parameters to the user model without filtering. An attacker can include sensitive fields like `role`, `is_admin`, or `permissions` in the update payload to escalate privileges.

**Attack example:**

```
POST /profile/update HTTP/1.1
Content-Type: application/json
Cookie: session=abc123

{"display_name": "New Name", "role": "admin", "is_admin": true}
```

If the backend blindly maps `request.json` to `user.update(...)`, the attacker becomes an admin.

## Root Cause

The API endpoint calls `user.update(attrs)` or `Model.bind(request.params)` without an allow-list of updatable fields. Privilege-related fields are not protected.

## Fix Implementation

### 1. Allow-List Filter (`ALLOWED_PROFILE_FIELDS`)

Define an explicit set of fields that users may update:

```python
ALLOWED_PROFILE_FIELDS = {
    'display_name',
    'bio',
    'timezone',
    'avatar_url',
    'marketing_opt_in',
}
```

### 2. Update Sanitization Middleware

Strip disallowed fields before any database operation:

```python
def sanitize_profile_update(payload: dict) -> dict:
    """Strip any fields not in the allowed set. Raise on sensitive fields."""
    privileged = {'role', 'is_admin', 'permissions', 'tenant_id', 'user_id'}
    detected = set(payload.keys()) & privileged
    if detected:
        raise MassAssignmentViolation(detected)
    return {k: v for k, v in payload.items() if k in ALLOWED_PROFILE_FIELDS}
```

### 3. Input Validation (`validate_profile_payload`)

Add request-level validation that checks each incoming field for type correctness:

```python
FIELD_VALIDATORS = {
    'display_name': lambda v: isinstance(v, str) and 1 <= len(v) <= 100,
    'bio': lambda v: isinstance(v, str) and len(v) <= 500,
    ...
}
```

### 4. Audit Logging

Log all profile update attempts that include disallowed fields for security monitoring.

## Testing

See `tests/test_mass_assignment_profile_1344.py` for coverage including:

- Allowed profile fields update successfully
- `role`, `is_admin`, `permissions` fields are rejected
- `tenant_id` field is rejected
- Case-variant field names are rejected
- Empty payload is handled gracefully
- Mixed payload (allowed + disallowed fields) rejects the whole update
- Normal user cannot escalate to admin via mass assignment
