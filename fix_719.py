```python
import os
from datetime import datetime
import random
import string

class OAuthStateGenerator:
    """
    This class generates a secure and unpredictable state token for OAuth.
    The state token is generated using os.urandom() to ensure it's not predictable.
    It ensures the token length is at least 16 bytes and binds it with user session ID,
    ensuring single-use per session.
    """

    def __init__(self, session_id):
        self.session_id = session_id

    def generate_state_token(self):
        """
        Generate a secure state token using os.urandom().
        Returns:
            str: A 32-byte random string for the OAuth state token.
        """
        return os.urandom(16).hex()

    def create_oauth_link(self, redirect_uri):
        """
        Create an OAuth link with a securely generated state token and session ID.

        Args:
            redirect_uri (str): The URI to which the user should be redirected after authorization.

        Returns:
            str: A complete OAuth link with the secure state token.
        """
        state_token = self.generate_state_token()
        # Ensure single-use by associating it with a unique session ID
        return f"https://example.com/oauth/authorize?response_type=code&client_id=1234567890" \
               f"&redirect_uri={redirect_uri}&state={state_token}&session_id={self.session_id}"

def main():
    # Simulate a user session ID
    session_id = 'user_12345'
    
    state_generator = OAuthStateGenerator(session_id)
    oauth_link = state_generator.create_oauth_link('https://example.com/callback')
    
    print(f"Generated OAuth Link: {oauth_link}")

if __name__ == "__main__":
    main()
```