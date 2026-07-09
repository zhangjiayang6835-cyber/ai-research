Based on the issue description, I need to fix an OAuth token leak vulnerability. The issue mentions using Authorization Code + PKCE flow, not passing tokens in URL fragments, and setting Referrer-Policy: no-referrer. 

Looking at the repo structure, I see `fix-oauth2-pkce-interception.py` which is likely the file that needs to be fixed. Let me also check if there's a web server configuration file that needs the Referrer-Policy header.

Since I can only see the file listings and README, I'll create the fix based on the existing `fix-oauth2-pkce-interception.py` file and add proper OAuth2 PKCE implementation with security headers.

```diff
--- a/fix-oauth2-pkce-interception.py
+++ b/fix-oauth2-pkce-interception.py
@@ -1,3 +1,180 @@
-# OAuth2 PKCE Interception Fix
-# This file needs to be updated with proper PKCE implementation
-# to prevent token leakage via Referer headers
+# OAuth2 PKCE Interception Fix - Complete Implementation
+# Fixes: Token leakage via Referer header (fragment-based access_token)
+# Solution: Authorization Code + PKCE flow with server-side token handling
+# Security: Referrer-Policy: no-referrer header on all responses
+
+import hashlib
+import secrets
+import base64
+import urllib.parse
+import json
+from http.server import HTTPServer, BaseHTTPRequestHandler
+from typing import Dict, Optional, Tuple
+import ssl
+
+
+class PKCEHelper:
+    """PKCE (Proof Key for Code Exchange) utilities for OAuth2 secure flow."""
+    
+    @staticmethod
+    def generate_code_verifier(length: int = 64) -> str:
+        """Generate a cryptographically random code verifier.
+        
+        Per RFC 7636, the code verifier MUST be generated with
+        sufficient entropy (minimum 256 bits).
+        """
+        # Generate random bytes and encode as URL-safe base64
+        random_bytes = secrets.token_bytes(length)
+        code_verifier = base64.urlsafe_b64encode(random_bytes).decode('utf-8')
+        # Remove padding characters
+        code_verifier = code_verifier.rstrip('=')
+        # Ensure minimum length of 43 characters per RFC 7636
+        if len(code_verifier) < 43:
+            code_verifier = PKCEHelper.generate_code_verifier(96)
+        return code_verifier[:128]  # Max length 128 per RFC 7636
+    
+    @staticmethod
+    def generate_code_challenge(code_verifier: str) -> str:
+        """Generate S256 code challenge from code verifier.
+        
+        Uses SHA-256 hashing as recommended by RFC 7636 for
+        maximum security (S256 method).
+        """
+        sha256_hash = hashlib.sha256(code_verifier.encode('utf-8')).digest()
+        code_challenge = base64.urlsafe_b64encode(sha256_hash).decode('utf-8')
+        # Remove padding characters
+        code_challenge = code_challenge.rstrip('=')
+        return code_challenge
+    
+    @staticmethod
+    def generate_state() -> str:
+        """Generate a random state parameter to prevent CSRF attacks."""
+        return secrets.token_urlsafe(32)
+
+
+class SecureOAuth2Handler:
+    """Secure OAuth2 handler implementing Authorization Code + PKCE flow.
+    
+    This implementation ensures:
+    1. Tokens are NEVER passed in URL fragments (prevents Referer leakage)
+    2. PKCE prevents authorization code interception
+    3. State parameter prevents CSRF attacks
+    4. Referrer-Policy: no-referrer on all responses
+    5. Server-side token storage (no client-side exposure)
+    """
+    
+    def __init__(self, client_id: str, redirect_uri: str, 
+                 authorization_endpoint: str, token_endpoint: str):
+        self.client_id = client_id
+        self.redirect_uri = redirect_uri
+        self.authorization_endpoint = authorization_endpoint
+        self.token_endpoint = token_endpoint
+        
+        # Server-side session storage (in production, use Redis or DB)
+        self._sessions: Dict[str, dict] = {}
+        self._token_store: Dict[str, dict] = {}
+    
+    def initiate_authorization(self) -> Tuple[str, str, str]:
+        """Initiate the OAuth2 Authorization Code + PKCE flow.
+        
+        Returns:
+            Tuple of (authorization_url, state, code_verifier)
+        """
+        # Generate PKCE parameters
+        code_verifier = PKCEHelper.generate_code_verifier()
+        code_challenge = PKCEHelper.generate_code_challenge(code_verifier)
+        state = PKCEHelper.generate_state()
+        
+        # Store code_verifier server-side (associated with state)
+        self._sessions[state] = {
+            'code_verifier': code_verifier,
+            'created_at': secrets.token_hex(16)  # timestamp placeholder
+        }
+        
+        # Build authorization URL with query parameters (NOT fragments!)
+        params = {
+            'response_type': 'code',  # Authorization Code flow
+            'client_id': self.client_id,
+            'redirect_uri': self.redirect_uri,
+            'code_challenge': code_challenge,
+            'code_challenge_method': 'S256',
+            'state': state,
+            'scope': 'openid profile email'
+        }
+        
+        authorization_url = (
+            f"{self.authorization_endpoint}?"
+            f"{urllib.parse.urlencode(params)}"
+        )
+        
+        return authorization_url, state, code_verifier
+    
+    def handle_callback(self, callback_params: dict) -> Optional[dict]:
+        """Handle the OAuth2 callback with authorization code.
+        
+        This receives the authorization code via query parameters
+        (NOT fragments), exchanges it for tokens server-side, and
+        stores tokens securely without exposing them to the client.
+        
+        Args:
+            callback_params: Dict containing 'code' and 'state' from query string
+            
+        Returns:
+            Session token for the authenticated user, or None if validation fails
+        """
+        code = callback_params.get('code')
+        state = callback_params.get('state')
+        
+        # Validate state parameter to prevent CSRF
+        if not state or state not in self._sessions:
+            return None
+        
+        session_data =