# Fix: MongoDB NoSQL Injection → Authentication Bypass (#660)

## Vulnerability

MongoDB queries that accept user-supplied input directly as query field values are vulnerable to NoSQL injection. An attacker can supply values containing MongoDB operators (`$gt`, `$ne`, `$where`, etc.) which get interpreted as query modifiers rather than literal values, enabling authentication bypass or arbitrary data access.

### Example Attacks

```python
# Authentication bypass
{"username": {"$ne": null}, "password": {"$ne": null}}

# User enumeration
{"username": {"$regex": "^admin"}}

# Remote code execution via $where
{"email": {"$where": "this.password === 'admin123'"}}

# Field injection via dot notation
{"user.role": "admin"}  # injected into query
```

### Root Cause
The application passes raw request parameters into MongoDB query documents without sanitizing or type-checking them. Because MongoDB's query language accepts operator keys starting with `$`, any user-controlled string containing a `$` prefix can hijack the query.

## Fix

- **Input type enforcement**: Only accept strings/numbers for query fields; reject dicts, lists, or non-primitive types
- **Operator key rejection**: Strip/reject any field whose name starts with `$` or `_`
- **Dot notation prevention**: Reject keys containing `.` to prevent sub-field injection
- **Null byte rejection**: Strip control characters including `\x00`
- **Parameterized query helper**: `safe_query()` function builds queries using only validated inputs
- **Request body middleware**: `validate_request_body()` catches nested objects and arrays before DB calls

## Implementation

- `FIXES/nosql_injection_660_fix.py` — Complete fix module with:
  - `safe_login_query()` — Safe authentication query builder
  - `safe_user_lookup()` — Safe single-field lookup
  - `safe_query()` — General safe query builder
  - `validate_request_body()` — Request-level middleware hook
  - `_sanitize_value()` — Per-value type checking

## Verification Checklist

- [x] Operator keys ($ne, $gt, $regex, $where) rejected
- [x] Nested objects rejected in query values
- [x] Arrays rejected in query values
- [x] Dot notation in keys rejected
- [x] Null bytes and control characters rejected
- [x] Empty username/password rejected
- [x] Request body validation catches injection patterns
- [x] Self-tests verify all attack vectors are blocked

## References

- [OWASP NoSQL Injection](https://owasp.org/www-community/vulnerabilities/No_SQL_Injection)
- [MongoDB Security Guide](https://www.mongodb.com/docs/manual/security/)
- [NodeGoat NoSQL Injection Lab](https://github.com/OWASP/NodeGoat)
