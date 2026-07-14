class User:
    # Whitelist of fields allowed for self-update via profile endpoint
    ALLOWED_UPDATE_FIELDS = {
        'username',
        'email',
        'display_name',
        'bio',
        'avatar_url',
        'phone',
        'location',
        'website',
        'timezone',
        'language',
        'notification_preferences',
    }
    
    # Sensitive fields that must NEVER be mass-assigned
    PROTECTED_FIELDS = {
        'role',
        'is_admin',
        'is_superuser',
        'permissions',
        'account_status',
        'credit_score',
        'bounty_balance',
        'api_key',
        'password_hash',
        'email_verified',
        'two_factor_enabled',
    }
    
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        # ... existing update logic ...
        pass

    def safe_update(self, data: dict) -> None:
        """
        Securely update user profile fields using a whitelist.
        Only fields in ALLOWED_UPDATE_FIELDS are permitted.
        """
        for field, value in data.items():
            if field in self.ALLOWED_UPDATE_FIELDS:
                setattr(self, field, value)
            elif field in self.PROTECTED_FIELDS:
                # Silently ignore or log attempt to modify protected fields
                import logging
                logging.warning(f"Attempted mass assignment to protected field: {field}")
        self.save()