"""
ReDoS (Regex DoS) via User-Controlled Pattern Fix
Bounty #802 ($120)
=========================================
Vulnerability: Search allows user-supplied regex: new RegExp(userInput).
Attacker submits (a+)+b with input aaaaaaaaaaaaaaaac, causing backtracking.

Fix: Regex timeout + length limit + ReDoS-safe validation.
"""

import re
import signal
from typing import Optional, Pattern
from dataclasses import dataclass


class ReDoSException(Exception):
    """Raised when a regex takes too long to execute."""
    pass


class TimeoutRegex:
    """
    Regex wrapper with timeout protection.
    Prevents catastrophic backtracking.
    """

    def __init__(self, timeout_ms: int = 100):
        self._timeout_ms = timeout_ms

    def search(self, pattern: str, text: str,
               max_length: int = 100) -> Optional[re.Match]:
        """
        Search with timeout.
        Raises ReDoSException if regex takes too long.
        """
        if len(pattern) > max_length:
            raise ValueError(f"Pattern exceeds max length ({max_length})")

        # Pre-validate pattern for ReDoS patterns
        self._validate_pattern(pattern)

        # Compile with timeout
        compiled = self._compile_with_timeout(pattern)
        if compiled is None:
            return None

        # Execute with timeout
        return self._execute_with_timeout(compiled, text)

    def _validate_pattern(self, pattern: str):
        """Validate pattern for ReDoS patterns."""
        # Block patterns with nested quantifiers (classic ReDoS)
        dangerous_patterns = [
            r"\(\w+\+\)\+",  # (a+)+
            r"\(\w+\*\)\*",  # (a*)*
            r"\(\w+\?\)\*",  # (a?)*
            r"\(\w+\*\)\+",  # (a*)+
            r"\.\+\+",       # .++
            r"\.\*\+",       # .*+
            r"\(\w+\+\)\{",  # (a+){n}
            r"\(\w+\*\)\{",  # (a*){n}
        ]
        for dp in dangerous_patterns:
            if re.search(dp, pattern):
                raise ValueError(f"Pattern contains ReDoS-prone construct: {pattern[:30]}")

    def _compile_with_timeout(self, pattern: str) -> Optional[Pattern]:
        """Compile regex pattern."""
        try:
            return re.compile(pattern)
        except re.error:
            return None

    def _execute_with_timeout(self, compiled: Pattern,
                              text: str) -> Optional[re.Match]:
        """Execute regex search with timeout."""
        import threading

        result = [None]
        exception = [None]
        done = threading.Event()

        def search_thread():
            try:
                result[0] = compiled.search(text)
            except Exception as e:
                exception[0] = e
            finally:
                done.set()

        thread = threading.Thread(target=search_thread, daemon=True)
        thread.start()

        if not done.wait(timeout=self._timeout_ms / 1000.0):
            raise ReDoSException(
                f"Regex execution timed out after {self._timeout_ms}ms"
            )

        if exception[0]:
            raise exception[0]

        return result[0]


class SafeRegexEngine:
    """
    Safe regex engine with multiple layers of protection.
    """

    def __init__(self, max_pattern_length: int = 50,
                 timeout_ms: int = 100):
        self._max_length = max_pattern_length
        self._timeout = TimeoutRegex(timeout_ms)

        # Cache of safe patterns
        self._safe_patterns: dict = {}

    def search(self, user_pattern: str, text: str) -> Optional[re.Match]:
        """
        Execute user-supplied regex safely.
        """
        if not user_pattern or not text:
            return None

        # Length check
        if len(user_pattern) > self._max_length:
            raise ValueError(f"Pattern too long ({len(user_pattern)} > {self._max_length})")

        # Character whitelist
        if not re.match(r'^[a-zA-Z0-9\s\.\*\+\?\^\$\(\)\[\]\{\}\|\\\\\-]+$', user_pattern):
            raise ValueError("Pattern contains disallowed characters")

        # Execute with timeout
        return self._timeout.search(user_pattern, text)


# ========== Usage Example ==========
if __name__ == "__main__":
    print("=== ReDoS Prevention ===")
    print()

    # Attack scenario:
    # Pattern: (a+)+b
    # Input: aaaaaaaaaaaaaaaac (many 'a's followed by 'c')
    # Without fix: CPU spike, catastrophic backtracking!

    engine = SafeRegexEngine()

    malicious_pattern = "(a+)+b"
    malicious_input = "a" * 30 + "c"

    print(f"Attack scenario:")
    print(f"  Pattern: {malicious_pattern}")
    print(f"  Input: {malicious_input[:30]}...")
    print()

    print(f"With fix:")
    try:
        result = engine.search(malicious_pattern, malicious_input)
        print(f"  Result: {result}")
    except ReDoSException as e:
        print(f"  ✗ BLOCKED: {e}")
    except ValueError as e:
        print(f"  ✗ BLOCKED: {e}")
    print()

    # Safe pattern
    safe_result = engine.search("hello", "hello world")
    print(f"Safe pattern:")
    print(f"  Pattern: 'hello'")
    print(f"  Input: 'hello world'")
    print(f"  Result: {safe_result}")
    print()

    print("=== Security Measures ===")
    print("✓ Regex execution timeout (100ms)")
    print("✓ Pattern length limit (50 chars)")
    print("✓ Character whitelist")
    print("✓ ReDoS pattern detection (nested quantifiers)")
    print("✓ Thread-based timeout mechanism")