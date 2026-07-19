# Mass Assignment in User Profile Update

## Description
The user profile update endpoint binds all request body fields directly to the user model without filtering. An attacker can include a role field to escalate privileges.

## Attack Vector
Send a PUT/PATCH request with additional fields:
  PUT /api/profile { "name": "new", "role": "admin" }
The server binds role to the model and saves it.

## Impact
Privilege escalation from regular user to admin, full account takeover.

## Remediation
1. Use DTOs to whitelist allowed fields
2. Never bind raw request body to model
3. Use mass assignment protection in framework (e.g. fillable in Laravel, attr_accessible in Rails)
4. Explicitly map fields: user.name = body.name (only)
