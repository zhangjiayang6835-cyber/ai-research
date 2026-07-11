def handle_oauth_callback(state, code):
    stored_state = get_session_state()
    if state != stored_state:
        raise ValueError("State parameter mismatch")
    
    # Proceed with OAuth flow and PKCE validation
    verify_pkce(code)
    bind_user_session(user_id)