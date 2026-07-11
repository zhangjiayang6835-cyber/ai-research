# sso_federation.py

def handle_oauth_callback(request):
    # Ensure no fragment with access token
    callback_url = request.build_absolute_uri()
    if '#access_token=' in callback_url:
        callback_url = callback_url.split('#', 1)[0]
    
    response = make_response(redirect('https://external-site.com'))
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response