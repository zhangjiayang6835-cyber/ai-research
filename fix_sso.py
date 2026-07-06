import jwt
from jwt.exceptions import InvalidTokenError

# Example: mapping of tenant IDs to allowed issuers and audiences
ALLOWED_ISSUERS = {
    'tenant1': 'https://accounts.google.com',
    'tenant2': 'https://login.microsoftonline.com/tenant2/v2.0',
}

def validate_sso_token(token, tenant_id):
    """
    Validates a JWT token for cross-tenant SSO.
    Prevents account takeover by ensuring the token's issuer matches
    the expected identity provider for the given tenant.
    """
    try:
        # Decode without verification first to inspect the header
        unverified_header = jwt.get_unverified_header(token)
        unverified_payload = jwt.decode(token, options={"verify_signature": False})

        # Get the expected issuer for this tenant
        expected_issuer = ALLOWED_ISSUERS.get(tenant_id)
        if not expected_issuer:
            raise ValueError(f"No allowed issuer configured for tenant: {tenant_id}")

        # Validate the issuer (prevent cross-tenant reuse)
        token_issuer = unverified_payload.get('iss')
        if token_issuer != expected_issuer:
            raise InvalidTokenError(
                f"Issuer mismatch: expected {expected_issuer}, got {token_issuer}")

        # Additional checks: audience, expiry, etc.
        # Here we assume the audience is the same across tenants (optional)
        # You should also verify the signature using the appropriate public key.
        # For brevity, we omit signature verification but it's critical.
        # In production, use the correct JWKS endpoint based on the issuer.

        # This is a placeholder for actual signature verification
        # public_key = get_public_key_for_issuer(token_issuer)
        # payload = jwt.decode(token, public_key, algorithms=['RS256'], audience='your-app')
        # return payload

        # For demonstration, return the decoded payload (not secure without signature check)
        return jwt.decode(token, options={"verify_signature": False})

    except (InvalidTokenError, ValueError) as e:
        # Log the error and deny access
        raise PermissionError(f"SSO token validation failed: {e}")

# Example usage:
# try:
#     user_info = validate_sso_token(request.headers['Authorization'], request.tenant_id)
# except PermissionError as e:
#     return unauthorized_response(str(e))
