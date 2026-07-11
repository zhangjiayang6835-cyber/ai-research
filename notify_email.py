# /home/l/Desktop/AxiomTree/axiom_horizon/.axiom_state/submissions/ai-research_780/login_handler.py

def handle_login(request):
    session_id = request.cookies.get('sessionid')
    if not session_id:
        # Generate new session ID on login
        session_id = generate_new_session_id()
    
    # Reject session ID from URL
    session_id_from_url = request.params.get('sessionid', None)
    if session_id_from_url:
        raise ValueError("Session ID from URL is not allowed")

    # Set Secure + HttpOnly cookie
    response.set_cookie('sessionid', session_id, secure=True, httponly=True)

    return session_id