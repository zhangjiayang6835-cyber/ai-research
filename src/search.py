"""Secure search module with XS-Search protection and ReDoS defense.
Implements constant-time responses, rate limiting to prevent
Cross-Site Search (XS-Search) user data enumeration attacks,
and ReDoS protection for user-supplied regex patterns.
"""

import hashlib
import hmac
import re
import time
from typing import Optional, List, Dict, Any, Pattern
from dataclasses import dataclass
from collections import defaultdict
import threading

# ── ReDoS Protection Constants ──────────────────────────────────────────

MAX_PATTERN_LENGTH = 500          # Max length of user-supplied pattern
MAX_REGEX_NESTING_DEPTH = 5       # Max allowed nesting depth in pattern
REGEX_COMPILE_TIMEOUT_S = 2.0     # Max seconds to compile a regex
REGEX_EXEC_TIMEOUT_S = 1.0        # Max seconds for a single regex execution

# Quantifier pattern: *, +, ?, {n}, {n,}, {n,m}
_RE_Q = r'(?:[*+?]|\{[0-9]+(?:,[0-9]*)?\})'

# Patterns that signal potential catastrophic backtracking

# Group with quantified content, then group quantified: (a+)+, (a{2,3})+
NESTED_QUANTIFIER_RE = re.compile(
    r'\([^()]*' + _RE_Q + r'[^()]*\)\s*' + _RE_Q
)

# Many-branch alternation, then group quantified: (a|b|c|d|e)+
ALTERNATION_LOOP_RE = re.compile(
    r'\([^)]*(?:\|[^)]+){3,}\)\s*' + _RE_Q
)

# Quantified group inside another quantified group: ((a)?)+
NESTED_GROUP_RE = re.compile(
    r'\([^()]*' + _RE_Q + r'?\([^()]*' + _RE_Q + r'?[^()]*\)'
    + _RE_Q + r'?[^()]*\)\s*' + _RE_Q
)


@dataclass
class SearchResult:
    """Search result with timing-safe metadata."""
    items: List[Dict[str, Any]]
    total_count: int
    query_hash: str


class _TimeoutThread(threading.Thread):
    """Run a target function with a timeout via threading."""

    def __init__(self, target: Any, args: tuple, kwargs: dict | None = None):
        super().__init__(daemon=True)
        self._target_fn = target
        self._args = args
        self._kwargs = kwargs or {}
        self._result: Any = None
        self._exception: Optional[Exception] = None

    def run(self) -> None:
        try:
            self._result = self._target_fn(*self._args, **self._kwargs)
        except Exception as e:
            self._exception = e

    @property
    def result(self) -> Any:
        if self._exception:
            raise self._exception
        return self._result


def _run_with_timeout(
    fn: Any,
    timeout_s: float,
    *args: Any,
    **kwargs: Any,
) -> Any:
    """Execute a function with a threading-based timeout.

    Args:
        fn: Callable to run
        timeout_s: Max seconds before raising TimeoutError
        *args, **kwargs: Passed to fn

    Returns:
        The return value of fn

    Raises:
        TimeoutError: If execution exceeds timeout_s
        Any exception raised by fn
    """
    thread = _TimeoutThread(target=fn, args=args, kwargs=kwargs)
    thread.start()
    thread.join(timeout=timeout_s)
    if thread.is_alive():
        raise TimeoutError(f"Execution timed out after {timeout_s}s")
    return thread.result


def _compute_nesting_depth(pattern: str) -> int:
    """Compute the maximum parenthesis nesting depth in a regex pattern."""
    depth = 0
    max_depth = 0
    for ch in pattern:
        if ch == '(':
            depth += 1
            max_depth = max(max_depth, depth)
        elif ch == ')':
            depth = max(0, depth - 1)
    return max_depth


def _has_dangerous_nested_quantifiers(pattern: str) -> bool:
    """Check if pattern contains nested quantifiers that cause catastrophic backtracking.

    Detects patterns like (a+)+, (a*)*, (a|b)+, ((a)?)+ that are known ReDoS vectors.
    """
    if bool(NESTED_QUANTIFIER_RE.search(pattern)):
        return True
    if bool(ALTERNATION_LOOP_RE.search(pattern)):
        return True
    if bool(NESTED_GROUP_RE.search(pattern)):
        return True
    return False


def _validate_regex_pattern(pattern: str) -> Optional[str]:
    """Validate a regex pattern for ReDoS safety.

    Args:
        pattern: The regex pattern string to validate

    Returns:
        None if the pattern is safe, or an error message string if dangerous
    """
    if not pattern:
        return "Pattern cannot be empty"

    if len(pattern) > MAX_PATTERN_LENGTH:
        return f"Pattern too long ({len(pattern)} chars, max {MAX_PATTERN_LENGTH})"

    if _compute_nesting_depth(pattern) >= MAX_REGEX_NESTING_DEPTH:
        return f"Pattern nesting too deep (max {MAX_REGEX_NESTING_DEPTH} levels)"

    if _has_dangerous_nested_quantifiers(pattern):
        return "Pattern contains dangerous nested quantifiers (potential ReDoS)"

    # Attempt compilation with timeout
    try:
        _run_with_timeout(
            re.compile, REGEX_COMPILE_TIMEOUT_S, pattern
        )
    except TimeoutError:
        return f"Regex compilation timed out (>{REGEX_COMPILE_TIMEOUT_S}s)"
    except re.error as e:
        return f"Invalid regex pattern: {e}"
    except Exception as e:
        return f"Regex compilation error: {e}"

    return None


class SecureSearchEngine:
    """
    Search engine with built-in XS-Search and ReDoS protections:
    1. Constant-time response padding to prevent timing attacks
    2. Rate limiting per user/session to prevent enumeration
    3. Result count obfuscation to prevent data leakage
    4. HMAC-based query validation to prevent cross-origin exploitation
    5. ReDoS protection: input length cap, pattern validation, threading timeout
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
        Perform a secure search with XS-Search protections and input validation.

        Args:
            query: Search query string
            user_id: Authenticated user identifier
            data_source: List of data records to search
            max_results: Maximum results to return

        Returns:
            SearchResult or None if rate limited
        """
        start_time = time.time()

        # Reject excessively long input (ReDoS defense)
        if len(query) > MAX_PATTERN_LENGTH:
            self._constant_time_pad(start_time)
            return None

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

    def validate_regex_pattern(self, pattern: str) -> Optional[str]:
        """Public wrapper around ReDoS pattern validation.

        Args:
            pattern: User-supplied regex pattern string

        Returns:
            None if safe, or error message string
        """
        return _validate_regex_pattern(pattern)

    def search_with_regex(
        self,
        pattern: str,
        user_id: str,
        data_source: List[Dict[str, Any]],
        max_results: int = 10,
    ) -> Optional[SearchResult]:
        """Regex-based search with ReDoS protection.

        Validates the pattern for ReDoS safety before performing the search.
        Each regex match is wrapped in a threading timeout.

        Args:
            pattern: Regex pattern string (user-supplied)
            user_id: Authenticated user identifier
            data_source: List of data records to search
            max_results: Maximum results to return

        Returns:
            SearchResult, or None if rate-limited or pattern rejected
        """
        start_time = time.time()

        # Validate pattern for ReDoS safety
        error = self.validate_regex_pattern(pattern)
        if error is not None:
            self._constant_time_pad(start_time)
            return None

        # Rate limit check
        if not self._check_rate_limit(user_id):
            self._constant_time_pad(start_time)
            return None

        # Compile regex (already validated, but wrap in timeout for safety)
        try:
            compiled = _run_with_timeout(
                re.compile, REGEX_COMPILE_TIMEOUT_S, pattern
            )
        except (TimeoutError, re.error):
            self._constant_time_pad(start_time)
            return None

        # Perform regex search with per-match timeout
        results = []
        for record in data_source:
            if len(results) >= max_results:
                break
            for value in record.values():
                if not isinstance(value, str):
                    continue
                try:
                    match = _run_with_timeout(
                        compiled.search, REGEX_EXEC_TIMEOUT_S, value
                    )
                except TimeoutError:
                    continue
                if match:
                    results.append(record)
                    break

        # Obfuscate count
        actual_count = len(results)
        if actual_count == 0:
            obfuscated_count = 0
        elif actual_count <= 5:
            obfuscated_count = actual_count
        else:
            obfuscated_count = ((actual_count + 2) // 5) * 5

        query_token = self._generate_query_token(pattern, user_id)
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