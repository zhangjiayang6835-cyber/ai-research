"""
Secure search module with XS-Search protection.
Implements constant-time responses and rate limiting to prevent
Cross-Site Search (XS-Search) user data enumeration attacks.
"""

import hashlib
import hmac
import time
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from collections import defaultdict
import threading


@dataclass
class SearchResult:
    """Search result with timing-safe metadata."""
    items: List[Dict[str, Any]]
    total_count: int
    query_hash: str


class SecureSearchEngine:
    """
    Search engine with built-in XS-Search protections:
    1. Constant-time response padding to prevent timing attacks
    2. Rate limiting per user/session to prevent enumeration
    3. Result count obfuscation to prevent data leakage
    4. HMAC-based query validation to prevent cross-origin exploitation
    """

    def __init__(
        self,
        min_response_time_ms: float = 200.0,
        max_requests_per_window: int = 30,
        rate_limit_window_seconds: int = 60,
        secret_key: Optional[str] = None,
    ):
        self.min_response_time_ms = min_response_time_ms
        self.max_requests_per_window = max_requests_per_window
        self.rate_limit_window_seconds = rate_limit_window_seconds
        self.secret_key = secret_key or hashlib.sha256(
            str(time.time()).encode()
        ).hexdigest()

        # Rate limiting state
        self._request_counts: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def _check_rate_limit(self, user_id: str) -> bool:
        """Check if user has exceeded rate limit."""
        now = time.time()
        window_start = now - self.rate_limit_window_seconds

        with self._lock:
            # Clean old entries
            self._request_counts[user_id] = [
                ts for ts in self._request_counts[user_id]
                if ts > window_start
            ]

            if len(self._request_counts[user_id]) >= self.max_requests_per_window:
                return False

            self._request_counts[user_id].append(now)
            return True

    def _constant_time_pad(self, start_time: float) -> None:
        """Ensure response takes at least min_response_time_ms."""
        elapsed = (time.time() - start_time) * 1000
        remaining = self.min_response_time_ms - elapsed
        if remaining > 0:
            time.sleep(remaining / 1000.0)

    def _generate_query_token(self, query: str, user_id: str) -> str:
        """Generate HMAC token to bind query to user session."""
        message = f"{user_id}:{query}:{int(time.time() / 300)}"
        return hmac.new(
            self.secret_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()[:16]

    def search(
        self,
        query: str,
        user_id: str,
        data_source: List[Dict[str, Any]],
        max_results: int = 10,
    ) -> Optional[SearchResult]:
        """
        Perform a secure search with XS-Search protections.

        Args:
            query: Search query string
            user_id: Authenticated user identifier
            data_source: List of data records to search
            max_results: Maximum results to return

        Returns:
            SearchResult or None if rate limited
        """
        start_time = time.time()

        # Rate limit check
        if not self._check_rate_limit(user_id):
            # Return generic error with constant timing
            self._constant_time_pad(start_time)
            return None

        # Perform actual search
        query_lower = query.lower()
        results = []
        for record in data_source:
            if len(results) >= max_results:
                break
            # Search across all string fields
            for value in record.values():
                if isinstance(value, str) and query_lower in value.lower():
                    results.append(record)
                    break

        # Obfuscate total count to prevent exact enumeration
        # Return a rounded count to prevent binary search attacks
        actual_count = len(results)
        if actual_count == 0:
            obfuscated_count = 0
        elif actual_count <= 5:
            obfuscated_count = actual_count
        else:
            # Round to nearest 5 to prevent precise enumeration
            obfuscated_count = ((actual_count + 2) // 5) * 5

        # Generate query token for CSRF/XS-Search protection
        query_token = self._generate_query_token(query, user_id)

        # Constant-time response padding
        self._constant_time_pad(start_time)

        return SearchResult(
            items=results[:max_results],
            total_count=obfuscated_count,
            query_hash=query_token,
        )

    def verify_query_token(self, query: str, user_id: str, token: str) -> bool:
        """Verify that a query token is valid for the given user."""
        expected = self._generate_query_token(query, user_id)
        return hmac.compare_digest(expected, token)


# Singleton instance for the application
search_engine = SecureSearchEngine()