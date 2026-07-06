import jwt
from flask import request, abort

def validate_sso_token(token, expected_issuer, expected_tenant_id):
    """
    Validates a federated SSO token and ensures it matches the expected tenant.
    This prevents cross-tenant account takeover by verifying the token's issuer.
    """
    try:
        # Decode the JWT (without verification first to get header)
        unverified = jwt.decode(token, options={"verify_signature": False})
        # Check the issuer claim against expected
        if unverified.get("iss") != expected_issuer:
            abort(401, description="Invalid token issuer")
        # Check tenant claim (custom claim like 'tid' or 'tenant')
        if unverified.get("tid") != expected_tenant_id and unverified.get("tenant") != expected_tenant_id:
            abort(401, description="Invalid tenant")
        # Now verify signature (get public keys from issuer's JWKS endpoint)
        # This is a placeholder - in production, fetch keys dynamically
        jwks_client = jwt.PyJWKClient(f"{expected_issuer}/.well-known/jwks.json")
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        data = jwt.decode(token, signing_key, algorithms=["RS256"], audience=expected_issuer)
        return data
    except jwt.PyJWTError as e:
        abort(401, description=str(e))

# Example usage in a Flask route
@app.route('/sso/callback')
def sso_callback():
    token = request.args.get('token')
    if not token:
        abort(400)
    # Expected values should be from secure configuration
    expected_issuer = "https://your-idp.com/"
    expected_tenant_id = "your-tenant-id"
    user_info = validate_sso_token(token, expected_issuer, expected_tenant_id)
    # Proceed with login
    return f"Welcome {user_info['sub']}"
