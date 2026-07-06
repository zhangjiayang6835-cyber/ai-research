import re
from urllib.parse import urlparse

ALLOWED_HOSTS = {'example.com', 'www.example.com'}
ALLOWED_PATHS = {'/dashboard', '/profile'}

def validate_redirect_url(url):
    """
    Validate that redirect URL is safe and allowed.
    Returns the validated URL or raises ValueError.
    """
    if not url:
        raise ValueError('Redirect URL is empty')
    parsed = urlparse(url)
    # If no host, it's a relative path
    if not parsed.netloc:
        # Allow only whitelisted paths
        path = parsed.path
        for allowed in ALLOWED_PATHS:
            if path.startswith(allowed):
                return url
        raise ValueError('Relative path not allowed')
    # Absolute URL: check host
    host = parsed.netloc.split(':')[0]
    if host in ALLOWED_HOSTS:
        return url
    else:
        raise ValueError('Redirect host not allowed')

# Example usage in a Flask login handler:
# from flask import request, redirect, url_for
# @app.route('/login')
# def login():
#     next_url = request.args.get('next')
#     if next_url:
#         try:
#             safe_url = validate_redirect_url(next_url)
#             return redirect(safe_url)
#         except ValueError:
#             return redirect(url_for('home'))
#     return render_template('login.html')
