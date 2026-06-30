 ```diff
--- a/honeycode-honeypot
+++ b/honeycode-honeypot
@@ -0,0 +1,1 @@
+ 
\ No newline at end of file
--- a/eval-engine
+++ b/eval-engine
@@ -0,0 +1,1 @@
+ 
\ No newline at end of file
--- a/ai-training-gym
+++ b/ai-training-gym
@@ -0,0 +1,1 @@
+ 
\ No newline at end of file
--- /dev/null
+++ b/honeycode-honeypot/auth.py
@@ -0,0 +1,120 @@
+"""
+Authentication module with secure email normalization.
+Fixes Zero-Click Account Takeover via Email Normalization vulnerability.
+"""
+
+import re
+import hashlib
+import hmac
+import secrets
+from typing import Optional, Tuple
+
+
+def normalize_email(email: str) -> str:
+    """
+    Securely normalize an email address to prevent account takeover attacks.
+    
+    Security considerations:
+    - Converts to lowercase to prevent case-based collisions
+    - Removes dots from local part for Gmail (dots are ignored by Gmail)
+    - Handles plus-addressing properly (removes everything after +)
+    - Prevents Unicode normalization attacks
+    - Validates email format before normalization
+    
+    Args:
+        email: The email address to normalize
+        
+    Returns:
+        Normalized email address
+        
+    Raises:
+        ValueError: If email format is invalid
+    """
+    if not email or not isinstance(email, str):
+        raise ValueError("Email must be a non-empty string")
+    
+    # Strip whitespace
+    email = email.strip()
+    
+    # Basic email validation
+    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
+    if not re.match(email_pattern, email):
+        raise ValueError("Invalid email format")
+    
+    # Split local and domain parts
+    try:
+        local, domain = email.rsplit('@', 1)
+    except ValueError:
+        raise ValueError("Invalid email format: missing @ symbol")
+    
+    # Normalize domain to lowercase
+    domain = domain.lower().strip()
+    
+    # Normalize local part based on email provider rules
+    local = local.lower().strip()
+    
+    # Remove everything after + (plus addressing)
+    local = local.split('+')[0]
+    
+    # Gmail-specific normalization: remove dots from local part
+    # This prevents: user.name@gmail.com == username@gmail.com takeover
+    if domain in ('gmail.com', 'googlemail.com'):
+        local = local.replace('.', '')
+    
+    # Reconstruct normalized email
+    normalized = f"{local}@{domain}"
+    
+    return normalized
+
+
+def verify_email_ownership(email: str, token: str, secret: str) -> bool:
+    """
+    Verify email ownership using HMAC to prevent token forgery.
+    
+    Args:
+        email: The email address to verify
+        token: The verification token provided by user
+        secret: Server-side secret for HMAC
+        
+    Returns:
+        True if token is valid for the email
+    """
+    normalized = normalize_email(email)
+    expected_token = hmac.new(
+        secret.encode(),
+        JSON.dumps({'email': normalized, 'nonce': token.split(':')[0] if ':' in token else token}).encode(),
+        hashlib.sha256
+    ).hexdigest()
+    return hmac.compare_digest(token, expected_token)
+
+
+def generate_secure_token() -> str:
+    """Generate a cryptographically secure random token."""
+    return secrets.token_urlsafe(32)
+
+
+def check_email_collision(email1: str, email2: str) -> bool:
+    """
+    Check if two emails refer to the same account after normalization.
+    Used to prevent account takeover via email normalization differences.
+    
+    Args:
+        email1: First email address
+        email2: Second email address
+        
+    Returns:
+        True if emails are equivalent after normalization
+    """
+    try:
+        return normalize_email(email1) == normalize_email(email2)
+    except ValueError:
+        return False
+
+
+class SecureUserManager:
+    """
+    Secure user manager that prevents email normalization attacks.
+    """
+    
+    def __init__(self):
+        self._users = {}  # normalized_email -> user_data
+        self._secret = secrets.token_hex(64)
+    
+    def register(self, email: str, password: str) -> dict:
+        """
+        Register a new user with secure email normalization.
+        
+        Args:
+            email: User's email address
+            password: User's password (should be hashed in production)
+            
+        Returns:
+            User data dictionary
+            
+        Raises:
+            ValueError: If email is already registered
+        """
+        normalized = normalize_email(email)
+        
+        # Check for existing account to prevent takeover
+        if normalized in self._users:
+            raise ValueError("Account already exists with this email")
+        
+        user_id = generate_secure_token()
+        user_data = {
+            'user_id': user_id,
+            'email': normalized,  # Store normalized email
+            'original_email': email,  # Keep original for display
+            'password_hash': hashlib.sha256(password.encode()).hexdigest(),  # Use proper hashing in production
+        }
+        
+        self._users[normalized] = user_data
+        return user_data
+    
+    def authenticate(self, email: str, password: str) -> Optional[dict]:
+        """
+        Authenticate a user with secure email normalization.
+        
+        Args:
+            email: User's email address
+            password: User's password
+            
+        Returns:
+            User data if authentication succeeds, None otherwise
+        """
+        try:
+            normalized = normalize_email(email)
+        except ValueError:
+            return None
+        
+        user = self._users.get(normalized)
+        if not user:
+            return None
+        
+        password_hash = hashlib.sha256(password.encode()).hexdigest()
+        if hmac.compare_digest(user['password_hash'], password_hash):
+            return user
+        return None
+    
+    def reset_password(self, email: str, new_password: str, verification_token: str) -> bool:
+        """
+        Secure password reset with token verification.
+        
+        Args:
+            email: User's email address
+            new_password