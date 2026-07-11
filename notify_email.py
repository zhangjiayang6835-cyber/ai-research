# /home/l/Desktop/AxiomTree/axiom_horizon/.axiom_state/submissions/ai-research_670/login_handler.py

def handle_login(request):
    session_id = request.cookies.get('sessionid')
    if not session_id:
        session_id = generate_new_session()
    
    # Reject session ID from URL
    session_id_from_url = request.params.get('sessionid', None)
    if session_id_from_url:
        return "Session ID in URL is rejected.", 400
    
    # Use cookie-based session management
    request.session['sessionid'] = session_id
    return "Login successful", 200

def generate_new_session():
    # Generate a new session ID securely
    return os.urandom(32).hex()