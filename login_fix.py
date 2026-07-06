# Fix for Unvalidated Redirect in Login Page
# Assumes Flask framework

from urllib.parse import urlparse, urljoin
from flask import request, redirect, url_for, flash

def is_safe_url(target):
    """
    Ensures that a redirect target is safe to redirect to.
    Validates that the URL is relative (does not have a hostname or scheme)
    and belongs to the same site.
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # authentication logic ...
        # after successful login:
        next_page = request.args.get('next')
        if not next_page or not is_safe_url(next_page):
            next_page = url_for('index')
        return redirect(next_page)
    else:
        return render_template('login.html')