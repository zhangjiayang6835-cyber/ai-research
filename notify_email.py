# sso_federation.py

def handle_oauth_callback(request):
    # Ensure no fragment is present in the URL
    url = request.build_absolute_uri()
    if '#' in url:
        url = url.split('#', 1)[0]
    
    # Set Referrer-Policy header to no-referrer
    response = HttpResponse(...)
    response['Referrer-Policy'] = 'no-referrer'
    return response