"""
User service with secure email handling to prevent 
zero-click account takeover via email normalization.
"""

from typing import Optional
from .auth import normalize_email


class UserService:
    def __init__(self, db):
        self.db = db
    
    def get_user_by_email(self, email: str) -> Optional[dict]:
        """
        Look up user by email with secure normalization.
        Prevents ATO via normalization differences.
        """
        try:
            normalized = normalize_email(email)
        except ValueError:
            return None
        
        # Query using normalized email
        return self.db.users.find_one({"email": normalized})
    
    def create_user(self, email: str, **kwargs) -> dict:
        """
        Create user with normalized email.
        Raises if email already exists or is invalid.
        """
        normalized = normalize_email(email)
        
        # Check for existing user with same normalized email
        if self.db.users.find_one({"email": normalized}):
            raise ValueError("User with this email already exists")
        
        user = {
            "email": normalized,
            **kwargs
        }
        self.db.users.insert_one(user)
        return user
    
    def update_email(self, user_id: str, new_email: str) -> dict:
        """
        Update user email with secure normalization.
        Prevents changing to an email that would normalize to existing account.
        """
        normalized = normalize_email(new_email)
        
        # Check if another user already has this normalized email
        existing = self.db.users.find_one({
            "email": normalized,
            "_id": {"$ne": user_id}
        })
        if existing:
            raise ValueError("Email already in use by another account")
        
        self.db.users.update_one(
            {"_id": user_id},
            {"$set": {"email": normalized}}
        )
        return {"email": normalized}