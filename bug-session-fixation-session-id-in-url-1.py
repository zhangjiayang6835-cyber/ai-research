"""
bug-session-fixation-session-id-in-url-1.py

Mitigates Session Fixation vulnerabilities caused by accepting session IDs in URLs.

This script provides:
1. A Flask application with secure session configuration that rejects session IDs
   passed via URL query parameters or path segments.
2. Middleware to strip and block session identifiers from URLs.
3. Session regeneration on authentication to prevent session fixation.
4. Utility functions and tests to validate the mitigation.

Security measures implemented:
- Reject session cookies delivered via URL parameters
- Regenerate session ID after login (privilege change)
- Set secure cookie flags: HttpOnly, Secure, SameSite
- Enforce server-side session ID generation only
- Block common session ID parameter names in URLs
"""

import os
import re
import hashlib
import secrets
import time
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Set
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

try:
    from flask import Flask, request, session, redirect, url_for, jsonify, abort
except ImportError:
    Flask = None  # type: ignore

try:
    import requests
except ImportError:
    requests = None  # type: ignore


# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("SessionFixationGuard")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Session ID parameter names commonly abused in URL-based session fixation attacks.
# These are checked in query strings and path segments.
SESSION_ID_PARAM_NAMES: Set[str] = {
    'sessionid', 'session_id', 'sid', 'sessid', 'sess_id',
    'phpsessid', 'jsessionid', 'asp.net_sessionid',
    'csrfmiddlewaretoken', 'token', 'auth', 'auth_token',
    'access_token', 'id', 'session', 'sessionkey', 'session_key',
}

# Pattern to detect session-like values in URL paths (hex, base64-like, long tokens)
SESSION_ID_PATH_PATTERN = re.compile(
    r'/(?:session|sid|sess)[a-z0-9_\-]{8,}',
    re.IGNORECASE
)

# Minimum session ID length to consider as a potential fixation attempt
MIN_SESSION_ID_LENGTH = 16


# ---------------------------------------------------------------------------
# Session Store (server-side session management)
# ---------------------------------------------------------------------------

class SessionStore:
    """
    Thread-safe in-memory session store for demonstration purposes.
    In production, use Redis, Memcached, or a database-backed store.
    """

    def __init__(self) -> None:
        self._store: Dict[str, Dict[str, Any]] = {}
        self._expiry_seconds: int = 3600  # 1 hour default

    def create_session(self, user_data: Dict[str, Any]) -> str:
        """Create a new server-side session and return its ID."""
        session_id = secrets.token_urlsafe(32)
        self._store[session_id] = {
            'data': user_data,
            'created_at': time.time(),
            'last_accessed': time.time(),
        }
        logger.info("Created new session: %s", session_id[:8] + "...")
        return session_id

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve session data if valid and not expired."""
        if not session_id or session_id not in self._store:
            return None

        session_record = self._store[session_id]
        now = time.time()

        if now - session_record['last_accessed'] > self._expiry_seconds:
            self.destroy_session(session_id)
            logger.warning("Expired session accessed and destroyed: %s", session_id[:8] + "...")
            return None

        session_record['last_accessed'] = now
        return session_record['data']

    def destroy_session(self, session_id: str) -> None:
        """Remove a session from the store."""
        if session_id in self._store:
            del self._store[session_id]
            logger.info("Destroyed session: %s", session_id[:8] + "...")

    def regenerate_session(self, old_session_id: str, user_data: Dict[str, Any]) -> str:
        """
        Destroy the old session and create a new one with a fresh ID.
        This is critical for preventing session fixation after login.
        """
        self.destroy_session(old_session_id)
        return self.create_session(user_data)

    def cleanup_expired(self) -> int:
        """Remove all expired sessions. Returns count of removed sessions."""
        now = time.time()
        expired_ids = [
            sid for sid, record in self._store.items()
            if now - record['last_accessed'] > self._expiry_seconds
        ]
        for sid in expired_ids:
            del self._store[sid]
        if expired_ids:
            logger.info("Cleaned up %d expired sessions", len(expired_ids))
        return len(expired_ids)


# ---------------------------------------------------------------------------
# URL Session ID Detection Utilities
# ---------------------------------------------------------------------------

class SessionFixationDetector:
    """
    Detects session fixation attempts via URL parameters and path segments.
    """

    def __init__(self, extra_params: Optional[Set[str]] = None) -> None:
        self.session_params = SESSION_ID_PARAM_NAMES.copy()
        if extra_params:
            self.session_params.update(extra_params)

    def detect_in_query_string(self, query_string: str) -> list:
        """
        Detect session ID parameters in a raw query string.
        Returns a list of detected parameter names.
        """
        if not query_string:
            return []

        detected = []
        try:
            params = parse_qs(query_string, keep_blank_values=True)
            for key in params:
                lower_key = key.lower()
                if lower_key in self.session_params:
                    detected.append(key)
                    continue
                # Check if parameter value looks like a session token
                for value in params[key]:
                    if self._looks_like_session_id(value):
                        detected.append(key)
                        break
        except Exception as e:
            logger.error("Error parsing query string '%s': %s", query_string, e)

        return detected

    def detect_in_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze a full URL for session fixation indicators.
        Returns a dict with detection results.
        """
        result: Dict[str, Any] = {
            'url': url,
            'is_vulnerable': False,
            'detected_params': [],
            'detected_path_segments': [],
            'reasons': [],
        }

        if not url:
            result['reasons'].append("Empty URL provided")
            return result

        try:
            parsed = urlparse(url)
        except Exception as e:
            result['reasons'].append(f"URL parse error: {e}")
            return result

        # Check query parameters
        if parsed.query:
            detected_params = self.detect_in_query_string(parsed.query)
            if detected_params:
                result['is_vulnerable'] = True
                result['detected_params'] = detected_params
                result['reasons'].append(
                    f"Session ID parameter(s) found in URL query: {detected_params}"
                )

        # Check path segments
        if parsed.path:
            path_segments = parsed.path.strip('/').split('/')
            for segment in path_segments:
                if segment.lower() in self.session_params:
                    result['is_vulnerable'] = True
                    result['detected_path_segments'].append(segment)
                    result['reasons'].append(
                        f"Session ID found in URL path segment: {segment}"
                    )
                elif SESSION_ID_PATH_PATTERN.search(f"/{segment}"):
                    result['is_vulnerable'] = True
                    result['detected_path_segments'].append(segment)
                    result['reasons'].append(
                        f"Session-like pattern in URL path: {segment}"
                    )

        # Check fragment
        if parsed.fragment:
            fragment_params = self.detect_in_query_string(parsed.fragment)
            if fragment_params:
                result['is_vulnerable'] = True
                result['detected_params'].extend(fragment_params)
                result['reasons'].append(
                    f"Session ID parameter(s) in URL fragment: {fragment_params}"
                )

        return result

    def sanitize_url(self, url: str) -> str:
        """
        Remove session ID parameters from a URL and return the cleaned URL.
        """
        if not url:
            return url

        try:
            parsed = urlparse(url)

            # Clean query parameters
            if parsed.query:
                params = parse_qs(parsed.query, keep_blank_values=True)
                cleaned_params = {
                    k: v for k, v in params.items()
                    if k.lower() not in self.session_params
                    and not any(self._looks_like_session_id(val) for val in v)
                }
                new_query = urlencode(cleaned_params, doseq=True)
            else:
                new_query = ''

            # Clean path segments
            if parsed.path:
                segments = parsed.path.split('/')
                cleaned_segments = []
                for seg in segments:
                    if seg.lower() not in self.session_params and \
                       not SESSION_ID_PATH_PATTERN.search(f"/{seg}"):
                        cleaned_segments.append(seg)
                    else:
                        logger.warning(
                            "Stripped session ID from URL path segment: %s", seg
                        )
                new_path = '/'.join(cleaned_segments)
            else:
                new_path = parsed.path

            # Clean fragment
            new_fragment = ''
            if parsed.fragment: