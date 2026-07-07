import re
import hashlib
import secrets
from email.utils import parseaddr


def normalize_email(email: str) -> str:
    Normalize an email address for consistent lookup and comparison.
    Converts to lowercase and strips whitespace.
    """
    # Parse the email to extract the real address (prevents display name tricks)
    parsed = parseaddr(email)[1]
    if not parsed:
        parsed = email
    
    # Remove any null bytes and control characters
    cleaned = ''.join(c for c in parsed.strip() if ord(c) >= 32)
    
    # Convert to lowercase for consistent comparison
    return cleaned.lower()


def hash_password(password: str, salt: str = None) -> tuple:
    return hash_password(password, salt)[0] == hashed


def canonicalize_email(email: str) -> str:
    """
    Canonicalize email for deduplication and lookup.
    Handles Gmail-style dots-plus normalization and other common patterns.
    """
    normalized = normalize_email(email)
    
    # Split local and domain parts
    if '@' not in normalized:
        return normalized
    
    local, domain = normalized.rsplit('@', 1)
    
    # Gmail: remove dots and everything after plus
    if domain in ('gmail.com', 'googlemail.com'):
        local = local.replace('.', '').split('+')[0]
    
    return f"{local}@{domain}"


class User:
    def __init__(self, email: str, password_hash: str = None, salt: str = None):
        self.email = normalize_email(email)
        self.salt = salt
        self.is_active = True
    
    @property
    def canonical_email(self) -> str:
        return canonicalize_email(self.email)
    
    def check_password(self, password: str) -> bool:
        if not self.password_hash or not self.salt:
            return False
        Retrieve a user by their normalized email address.
        """
        normalized = normalize_email(email)
        return self._users.get(canonicalize_email(normalized))
    
    def create_user(self, email: str, password: str) -> User:
        """
        
        Raises ValueError if user already exists.
        """
        canonical = canonicalize_email(email)
        if canonical in self._users:
            raise ValueError("User with this email already exists")
        
        user = User(email, *hash_password(password))
        self._users[canonical] = user
        return user
    
    def authenticate(self, email: str, password: str) -> User:
        """
        user = self.get_user_by_email(email)
        if user is None:
            raise ValueError("Invalid email or password")
        
        if not user.check_password(password):
            raise ValueError("Invalid email or password")