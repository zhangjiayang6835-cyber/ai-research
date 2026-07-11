```python
import os
from flask import Flask, request, session, redirect, url_for, abort
from requests_oauthlib import OAuth2Session

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Use a secret key for sessions

# Configuration for the OAuth provider (replace with actual values)
oauth_client_id = 'your-client-id'
oauth_client_secret = 'your-client-secret'
authorization_base_url = 'https://github.com/login/oauth/authorize'
token_url = 'https://github.com/login/oauth/access_token'

def get_state():
    return os.urandom(16).hex()

@app.route('/')
def index():
    # Generate state and nonce for PKCE
    state = get_state()
    nonce = os.urandom(32).hex()
    
    session['oauth_state'] = state  # Bind state to user's session
    
    oauth = OAuth2Session(
        client_id=oauth_client_id,
        state=state,
        scope=['user'],
        redirect_uri=url_for('callback', _external=True),
        auto_refresh_url='https://github.com/login/oauth/access_token',
        auto_refresh_kwargs={
            'client_id': oauth_client_id,
            'client_secret': oauth_client_secret
        },
        token_endpoint_auth_method='client_secret_post'
    )
    
    authorization_url, state = oauth.authorization_url(
        authorization_base_url,
        nonce=nonce  # Include nonce in the OAuth request
    )

    if session['oauth_state'] != state:
        abort(403)  # CSRF protection failure
    
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    # Verify that the state parameter is correct and matches the one stored in the session
    oauth_state = request.args.get('state')
    if 'oauth_state' not in session or session['oauth_state'] != oauth_state:
        abort(403)  # CSRF protection failure
    
    code = request.args.get('code')
    
    oauth = OAuth2Session(
        client_id=oauth_client_id,
        state=session['oauth_state'],
        redirect_uri=url_for('callback', _external=True),
    )
    
    token = oauth.fetch_token(
        token_url=token_url,
        client_secret=oauth_client_secret,
        authorization_response=request.url
    )

    # Use the token to make requests and bind user information (simplified for example)
    user_info = {'username': 'user123'}  # Replace with actual user info retrieval logic
    
    session['user'] = user_info  # Store user info in session
    
    return redirect(url_for('profile'))

@app.route('/profile')
def profile():
    if 'user' not in session:
        abort(401)  # Unauthorized access
    return f"Welcome, {session['user']['username']}"

if __name__ == '__main__':
    app.run(debug=True)
```
```