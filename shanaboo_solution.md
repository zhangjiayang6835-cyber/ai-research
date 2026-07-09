Based on the issue description, I need to fix an OAuth token leak vulnerability. The issue mentions implementing Authorization Code + PKCE flow, not passing tokens in URL fragments, and setting Referrer-Policy: no-referrer. Let me examine the existing fix file and create a proper solution.

Looking at the repo structure, I see `fix-oauth2-pkce-interception.py` which is likely the file that needs to be fixed. Let me create a comprehensive solution that addresses all three requirements.

```diff
--- a/fix-oauth2-pkce-interception.py
+++ b/fix-oauth2-pkce-interception.py
@@ -1,3 +1,175 @@
-# OAuth2 PKCE Interception Fix
-# This file needs to be updated with proper PKCE implementation
-# TODO: Implement Authorization Code + PKCE flow
+"""
+OAuth2 PKCE Interception Fix - Secure OAuth Implementation
+
+This module implements a secure OAuth2 Authorization Code + PKCE flow
+that prevents token leakage via Referer headers.
+
+Key security features:
+1. Authorization Code + PKCE flow (no implicit grant)
+2. Tokens never appear in URL fragments
+3. Referrer-Policy: no-referrer header on all responses
+4. State parameter for CSRF protection
+5. Server-side token exchange
+"""
+
+import hashlib
+import base64
+import os
+import secrets
+import urllib.parse
+from typing import Dict, Optional, Tuple
+import requests
+
+
+class SecureOAuth2Client:
+    """
+    Secure OAuth2 client implementing Authorization Code + PKCE flow.
+    
+    This implementation ensures:
+    - No tokens in URL fragments (prevents Referer leakage)
+    - PKCE for authorization code interception protection
+    - State parameter for CSRF protection
+    - Server-side token exchange
+    """
+    
+    def __init__(
+        self,
+        client_id: str,
+        client_secret: str,
+        authorization_endpoint: str,
+        token_endpoint: str,
+        redirect_uri: str,
+        scopes: list = None
+    ):
+        self.client_id = client_id
+        self.client_secret = client_secret
+        self.authorization_endpoint = authorization_endpoint
+        self.token_endpoint = token_endpoint
+        self.redirect_uri = redirect_uri
+        self.scopes = scopes or ["openid", "profile", "email"]
+        
+        # In-memory state store (use Redis/DB in production)
+        self._state_store: Dict[str, dict] = {}
+    
+    def generate_pkce_pair(self) -> Tuple[str, str]:
+        """
+        Generate PKCE code_verifier and code_challenge pair.
+        
+        Returns:
+            Tuple of (code_verifier, code_challenge)
+        """
+        # Generate cryptographically random code_verifier (43-128 chars)
+        code_verifier = base64.urlsafe_b64encode(
+            secrets.token_bytes(32)
+        ).rstrip(b'=').decode('ascii')
+        
+        # Create code_challenge using S256 method
+        code_challenge = base64.urlsafe_b64encode(
+            hashlib.sha256(code_verifier.encode('ascii')).digest()
+        ).rstrip(b'=').decode('ascii')
+        
+        return code_verifier, code_challenge
+    
+    def generate_state(self) -> str:
+        """
+        Generate cryptographically secure state parameter for CSRF protection.
+        """
+        return secrets.token_urlsafe(32)
+    
+    def build_authorization_url(self) -> Tuple[str, str, str]:
+        """
+        Build the authorization URL with PKCE and state parameters.
+        
+        Returns:
+            Tuple of (authorization_url, state, code_verifier)
+        """
+        code_verifier, code_challenge = self.generate_pkce_pair()
+        state = self.generate_state()
+        
+        # Store state and code_verifier for later verification
+        self._state_store[state] = {
+            "code_verifier": code_verifier,
+            "created_at": secrets.token_bytes(16).hex()  # timestamp placeholder
+        }
+        
+        params = {
+            "response_type": "code",  # Authorization Code flow (NOT token)
+            "client_id": self.client_id,
+            "redirect_uri": self.redirect_uri,
+            "scope": " ".join(self.scopes),
+            "state": state,
+            "code_challenge": code_challenge,
+            "code_challenge_method": "S256"
+        }
+        
+        authorization_url = f"{self.authorization_endpoint}?{urllib.parse.urlencode(params)}"
+        
+        return authorization_url, state, code_verifier
+    
+    def exchange_code_for_tokens(self, authorization_code: str, code_verifier: str) -> dict:
+        """
+        Exchange authorization code for tokens server-side.
+        
+        This is done server-to-server, so tokens never appear in browser URLs.
+        
+        Args:
+            authorization_code: The authorization code from the callback
+            code_verifier: The PKCE code verifier
+            
+        Returns:
+            Token response dictionary
+        """
+        token_data = {
+            "grant_type": "authorization_code",
+            "code": authorization_code,
+            "redirect_uri": self.redirect_uri,
+            "client_id": self.client_id,
+            "client_secret": self.client_secret,
+            "code_verifier": code_verifier
+        }
+        
+        response = requests.post(
+            self.token_endpoint,
+            data=token_data,
+            headers={
+                "Content-Type": "application/x-www-form-urlencoded",
+                "Accept": "application/json"
+            }
+        )
+        
+        if response.status_code != 200:
+            raise ValueError(f"Token exchange failed: {response.text}")
+        
+        return response.json()
+    
+    def handle_callback(self, callback_params: dict) -> Optional[dict]:
+        """
+        Handle the OAuth callback securely.
+        
+        Validates state parameter and exchanges code for tokens server-side.
+        Tokens are NEVER returned in URL fragments or redirects.
+        
+        Args:
+            callback_params: Dictionary of callback query parameters
+            
+        Returns:
+            Token response or None if validation fails
+        """
+        state = callback_params.get("state")
+        code = callback_params.get("code")
+        error = callback_params.get("error")
+        
