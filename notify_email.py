# sso_federation.py

def handle_oauth_callback(state, code):
    stored_state = get_session_state()
    if state != stored_state:
        raise ValueError("Invalid state parameter")
    
    # PKCE validation
    expected_code_verifier = get_code_verifier_from_session()
    actual_code_verifier = request.args.get('code_verifier')
    if not verify_code_challenge(expected_code_verifier, actual_code_verifier):
        raise ValueError("Invalid code verifier")

    # Proceed with OAuth flow...