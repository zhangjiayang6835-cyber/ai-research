import os
from flask import request, url_for

def get_trusted_host():
    """Return the trusted base URL for the application."""
    allowed_hosts = os.environ.get('ALLOWED_HOSTS', 'example.com').split(',')
    host = request.headers.get('Host', '').strip()
    # Remove port if present
    if ':' in host:
        host = host.split(':')[0]
    if host in allowed_hosts:
        return request.scheme + '://' + host
    else:
        # Fallback to configured base URL
        return os.environ.get('BASE_URL', 'https://example.com')

def send_password_reset(user_email):
    # Old vulnerable code:
    # reset_link = request.scheme + '://' + request.host + '/reset?token=' + token
    
    # Fixed code:
    token = generate_reset_token(user_email)
    base_url = get_trusted_host()
    reset_link = base_url + '/reset?token=' + token
    send_email(user_email, 'Password Reset', f'Click here: {reset_link}')
