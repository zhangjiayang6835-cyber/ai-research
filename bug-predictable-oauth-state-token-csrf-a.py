#!/usr/bin/env python3
"""
Secure OAuth State Token Management Module

This module provides a secure implementation for generating, validating, and 
managing OAuth state parameters to prevent CSRF attacks and account takeover.

The implementation addresses the critical vulnerability where predictable state
tokens (auto-incrementing integers or timestamps) allowed attackers to:
1. Predict the next state value
2. Construct malicious OAuth authorization links
3. Trick victims into binding attacker-controlled accounts

Security measures implemented:
- Cryptographically secure random state generation (crypto.randomBytes equivalent)
- Minimum 16-byte state tokens (128 bits of entropy)
- State tokens bound to user session
- Single-use enforcement (tokens invalidated after one use)
- Expiration mechanism for unused tokens
- Constant-time comparison to prevent timing attacks

Author: Security Engineering Team
Issue: #1476 - Predictable OAuth State Token → CSRF Account Takeover
"""

import os
import hmac
import hashlib
import secrets
import time
import json
import logging
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from abc import ABC, abstractmethod
import threading
import base64


# Configure logging for security events
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('OAuthStateSecurity')


class OAuthStateError(Exception):
    """Base exception for OAuth state-related errors."""
    pass


class StateGenerationError(OAuthStateError):
    """Raised when state token generation fails."""
    pass


class StateValidationError(OAuthStateError):
    """Raised when state token validation fails."""
    pass


class StateExpiredError(OAuthStateError):
    """Raised when state token has expired."""
    pass


class StateReuseError(OAuthStateError):
    """Raised when a state token is used more than once."""
    pass


class SessionMismatchError(OAuthStateError):
    """Raised when state token doesn't match the session."""
    pass


@dataclass
class OAuthStateEntry:
    """
    Represents a stored OAuth state token with associated metadata.
    
    Attributes:
        state: The state token string (base64-encoded random bytes)
        session_id: The user session ID this state is bound to
        user_id: The user ID initiating the OAuth flow (if authenticated)
        provider: The OAuth provider name (e.g., 'google', 'github')
        created_at: Unix timestamp of creation time
        expires_at: Unix timestamp of expiration time
        used: Whether this state has been consumed
        redirect_uri: The intended redirect URI after OAuth completion
        pkce_code_challenge: Optional PKCE code challenge for additional security
    """
    state: str
    session_id: str
    user_id: Optional[str] = None
    provider: str = ""
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 600)  # 10 min default
    used: bool = False
    redirect_uri: str = ""
    pkce_code_challenge: Optional[str] = None


class StateStorageBackend(ABC):
    """
    Abstract base class for OAuth state token storage backends.
    
    Implementations can use in-memory storage, Redis, database, etc.
    The storage must support atomic operations for single-use enforcement.
    """
    
    @abstractmethod
    def store(self, state_entry: OAuthStateEntry) -> bool:
        """Store a new state entry."""
        pass
    
    @abstractmethod
    def retrieve(self, state: str) -> Optional[OAuthStateEntry]:
        """Retrieve a state entry by state token."""
        pass
    
    @abstractmethod
    def mark_used(self, state: str) -> bool:
        """Mark a state token as used (consumed)."""
        pass
    
    @abstractmethod
    def delete(self, state: str) -> bool:
        """Delete a state entry."""
        pass
    
    @abstractmethod
    def cleanup_expired(self) -> int:
        """Remove all expired state entries. Returns count of removed entries."""
        pass
    
    @abstractmethod
    def exists(self, state: str) -> bool:
        """Check if a state token exists in storage."""
        pass


class InMemoryStateStorage(StateStorageBackend):
    """
    Thread-safe in-memory storage for OAuth state tokens.
    
    This implementation is suitable for single-process applications.
    For distributed deployments, use RedisStateStorage or DatabaseStateStorage.
    
    Thread Safety:
        All operations are protected by a reentrant lock to ensure
        atomic read-modify-write operations for single-use enforcement.
    """
    
    def __init__(self):
        self._store: Dict[str, OAuthStateEntry] = {}
        self._lock = threading.RLock()
        logger.info("Initialized InMemoryStateStorage for OAuth state tokens")
    
    def store(self, state_entry: OAuthStateEntry) -> bool:
        """
        Store a new state entry.
        
        Args:
            state_entry: The OAuthStateEntry to store
            
        Returns:
            True if stored successfully, False if state already exists
            
        Raises:
            StateGenerationError: If storage fails
        """
        try:
            with self._lock:
                if state_entry.state in self._store:
                    logger.warning(
                        f"State token collision detected during storage: "
                        f"{state_entry.state[:8]}..."
                    )
                    return False
                
                self._store[state_entry.state] = state_entry
                logger.debug(
                    f"Stored OAuth state for session {state_entry.session_id}, "
                    f"provider: {state_entry.provider}"
                )
                return True
        except Exception as e:
            logger.error(f"Failed to store OAuth state: {e}")
            raise StateGenerationError(f"Storage failure: {e}")
    
    def retrieve(self, state: str) -> Optional[OAuthStateEntry]:
        """
        Retrieve a state entry by state token.
        
        Args:
            state: The state token to look up
            
        Returns:
            OAuthStateEntry if found, None otherwise
        """
        with self._lock:
            return self._store.get(state)
    
    def mark_used(self, state: str) -> bool:
        """
        Atomically mark a state token as used.
        
        This operation is atomic to prevent race conditions where
        multiple requests try to use the same state token simultaneously.
        
        Args:
            state: The state token to mark as used
            
        Returns:
            True if successfully marked as used, False if already used or not found
        """
        with self._lock:
            entry = self._store.get(state)
            if entry is None:
                logger.warning(f"Attempted to mark unknown state as used: {state[:8]}...")
                return False
            
            if entry.used:
                logger.warning(
                    f"State reuse attempt detected for token: {state[:8]}... "
                    f"(session: {entry.session_id})"
                )
                return False
            
            entry.used = True
            logger.debug(f"Marked OAuth state as used for session {entry.session_id}")
            return True
    
    def delete(self, state: str) -> bool:
        """
        Delete a state entry from storage.
        
        Args:
            state: The state token to delete
            
        Returns:
            True if deleted, False if not found
        """
        with self._lock:
            if state in self._store:
                del self._store[state]
                logger.debug(f"Deleted OAuth state: {state[:8]}...")
                return True
            return False
    
    def cleanup_expired(self) -> int:
        """
        Remove all expired state entries from storage.
        
        This should be called periodically to prevent memory leaks
        from abandoned OAuth flows.
        
        Returns:
            Number of expired entries removed
        """
        current_time = time.time()
        expired_keys = []
        
        with self._lock:
            for key, entry in self._store.items():
                if entry.expires_at < current_time:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self._store[key]
        
        if expired_keys:
            logger.info(f"Cleaned up {len(expired_keys)} expired OAuth state entries")
        
        return len(expired_keys)
    
    def exists(self, state: str) -> bool:
        """
        Check if a state token exists in storage.
        
        Args:
            state: The state token to check
            
        Returns:
            True if exists, False otherwise
        """
        with self._lock:
            return state in self._store


class RedisStateStorage(StateStorageBackend):
    """
    Redis-based storage for OAuth state tokens.
    
    This implementation is suitable for distributed deployments where
    multiple application instances need to share state token storage.
    
    Redis provides atomic operations via SETNX and EXPIRE which ensure
    single-use enforcement even in concurrent scenarios.
    
    Note:
        Requires redis-py package: pip install redis
    """
    
    def __init__(self, redis_client, key_prefix: str = "oauth_state:", 
                 default_ttl: int = 600):
        """
        Initialize Redis state storage.
        
        Args:
            redis_client: Redis client instance
            key_prefix: Prefix for state token keys in Redis
            default_ttl: Default time-to-live in seconds (10 minutes)
        """
        self._redis = redis_client
        self._prefix = key_prefix
        self._default_ttl = default_ttl
        logger.info(f"Initialized RedisStateStorage with prefix: {key_prefix}")
    
    def _make_key(self, state: str) ->