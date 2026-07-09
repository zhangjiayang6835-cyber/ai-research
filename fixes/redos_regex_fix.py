"""
Fix for: Regex DoS (ReDoS) via User-Controlled Pattern

Vulnerability
-------------
The search feature let users supply an arbitrary regular expression which was
fed directly into the regex engine, e.g. ``new RegExp(userInput)`` (or, in
Python terms, ``re.compile(user_pattern).search(user_input)``). An attacker
supplies a pattern with nested quantifiers such as::

    (a+)+b

and an input like ``"aaaaaaaaaaaaaaaac"`` (many repeats of the inner
character, no trailing match). Because the default regex engine is
backtracking-based, this causes catastrophic exponential backtracking and
pins a CPU core, resulting in denial of service (ReDoS). CWE-1333.

Fix (defense in depth)
-----------------------
1. **Timeout** — regex execution is bounded by a hard wall-clock timeout.
   When a ReDoS-safe engine (``re2``) is not installed, matching is performed
   in an isolated worker process that is forcibly terminated if it exceeds
   the timeout, guaranteeing the caller is never blocked indefinitely and
   that runaway CPU usage is reclaimed.
2. **Input length limits** — both the user-supplied *pattern* and the subject
   *string* being searched are capped to sane maximums before any
   compilation or matching is attempted. Most ReDoS payloads require long
   inputs to manifest exponential blowup; capping input size bounds the
   worst-case work even for patterns that pass the static check.
3. **Safe regex engine** — when the optional ``re2`` / ``google-re2``
   bindings are installed, they are used instead of the stdlib ``re``
   engine. RE2 evaluates in linear time with respect to input length and
   cannot exhibit catastrophic backtracking by construction, because it
   does not support backtracking constructs at all.
4. **Static pattern screening** — patterns containing well-known
   catastrophic-backtracking shapes (nested quantified groups like
   ``(a+)+``, ``(a*)*``, ``(a+)*``, ``(a*)+``) are rejected outright before
   any matching is attempted, regardless of which engine is used.

Usage::

    from fixes.redos_regex_fix import safe_search, RegexSecurityError

    try:
        matched = safe_search(user_pattern, user_input)
    except RegexSecurityError as exc:
        # reject the request / log the attempt
        ...
"""

from __future__ import annotations

import multiprocessing
import re
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAX_PATTERN_LENGTH: int = 200          # user-supplied regex pattern cap
MAX_INPUT_LENGTH: int = 10_000         # subject string cap
DEFAULT_TIMEOUT_SECONDS: float = 1.0   # hard wall-clock cap on execution

# Detect the classic catastrophic-backtracking shape: a quantified group
# whose body is itself quantified, e.g. (a+)+, (a*)*, (a+)*, (a*)+,
# (ab+)+, ([a-z]+)+, etc. This is intentionally conservative (may reject a
# few benign-but-similar patterns) in favor of never letting an obviously
# dangerous shape through.
_NESTED_QUANTIFIER_RE = re.compile(r"\([^()]*[+*][^()]*\)[+*]")

# Try to use Google's RE2 engine (linear time, no backtracking, ReDoS-immune
# by construction). Falls back to stdlib `re` + process-isolated timeout if
# the optional dependency isn't installed.
try:  # pragma: no cover - environment dependent
    import re2 as _safe_engine  # type: ignore

    _HAS_RE2 = True
except ImportError:  # pragma: no cover - environment dependent
    _safe_engine = re
    _HAS_RE2 = False


class RegexSecurityError(ValueError):
    """Raised for any unsafe regex usage: oversized pattern/input, a
    dangerous pattern shape, an invalid pattern, or an execution timeout."""


def _validate_lengths(pattern: str, string: str) -> None:
    if not isinstance(pattern, str):
        raise RegexSecurityError("pattern must be a string")
    if not isinstance(string, str):
        raise RegexSecurityError("input string must be a string")
    if len(pattern) == 0:
        raise RegexSecurityError("pattern must not be empty")
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise RegexSecurityError(
            f"pattern exceeds maximum length of {MAX_PATTERN_LENGTH} characters"
        )
    if len(string) > MAX_INPUT_LENGTH:
        raise RegexSecurityError(
            f"input exceeds maximum length of {MAX_INPUT_LENGTH} characters"
        )


def _reject_dangerous_patterns(pattern: str) -> None:
    """Statically reject well-known catastrophic-backtracking shapes."""
    if _NESTED_QUANTIFIER_RE.search(pattern):
        raise RegexSecurityError(
            "pattern contains a nested quantifier shape associated with "
            "catastrophic backtracking (e.g. (a+)+); rejected"
        )


def _worker_search(pattern: str, string: str, conn) -> None:  # pragma: no cover
    """Runs in a separate process so it can be forcibly terminated if it
    exceeds the timeout, reclaiming any runaway CPU usage."""
    try:
        compiled = re.compile(pattern)
        result = compiled.search(string)
        conn.send(("ok", result is not None))
    except re.error as exc:
        conn.send(("error", str(exc)))
    except Exception as exc:  # noqa: BLE001 - surface as a security error
        conn.send(("error", str(exc)))
    finally:
        conn.close()


def _safe_search_with_re2(pattern: str, string: str) -> bool:
    try:
        compiled = _safe_engine.compile(pattern)
    except Exception as exc:  # noqa: BLE001
        raise RegexSecurityError(f"invalid regex pattern: {exc}") from exc
    return compiled.search(string) is not None


def _safe_search_with_timeout(
    pattern: str, string: str, timeout: float
) -> bool:
    # Validate compilability up front in the parent so bad patterns raise a
    # clean RegexSecurityError instead of only surfacing via the worker.
    try:
        re.compile(pattern)
    except re.error as exc:
        raise RegexSecurityError(f"invalid regex pattern: {exc}") from exc

    ctx = multiprocessing.get_context("spawn")
    parent_conn, child_conn = ctx.Pipe(duplex=False)
    proc = ctx.Process(target=_worker_search, args=(pattern, string, child_conn))
    proc.start()
    child_conn.close()
    proc.join(timeout)

    if proc.is_alive():
        proc.terminate()
        proc.join()
        raise RegexSecurityError(
            f"regex execution exceeded {timeout}s timeout (possible ReDoS)"
        )

    if parent_conn.poll():
        status, value = parent_conn.recv()
        if status == "error":
            raise RegexSecurityError(f"invalid regex pattern: {value}")
        return bool(value)

    raise RegexSecurityError("regex execution failed with no result")


def safe_search(
    pattern: str,
    string: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> bool:
    """Safely test whether ``pattern`` matches anywhere in ``string``.

    Applies, in order: length limits, static dangerous-pattern screening,
    then executes the match using a ReDoS-immune engine (``re2``) when
    available, or the stdlib ``re`` engine bounded by a hard process-level
    timeout otherwise.

    Raises :class:`RegexSecurityError` for any policy violation or timeout.
    """
    _validate_lengths(pattern, string)
    _reject_dangerous_patterns(pattern)

    if _HAS_RE2:
        return _safe_search_with_re2(pattern, string)
    return _safe_search_with_timeout(pattern, string, timeout)


def safe_compile(pattern: str) -> "re.Pattern[str]":
    """Validate and pre-compile a user-supplied pattern for repeated use.

    Only performs the static length/shape checks (compilation itself is
    cheap and safe); use :func:`safe_search` for the actual match against
    untrusted input so the timeout/engine protections apply.
    """
    _validate_lengths(pattern, "")
    _reject_dangerous_patterns(pattern)
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise RegexSecurityError(f"invalid regex pattern: {exc}") from exc


# ---------------------------------------------------------------------------
# Self-tests — run: python fixes/redos_regex_fix.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # 1. Benign pattern/input still works.
    assert safe_search(r"^hello\s+world$", "hello   world") is True
    assert safe_search(r"^hello\s+world$", "nope") is False
    print("PASS: benign pattern matches correctly")

    # 2. Classic ReDoS pattern is rejected statically before any execution.
    try:
        safe_search(r"(a+)+b", "aaaaaaaaaaaaaaaac")
    except RegexSecurityError as e:
        print(f"PASS: catastrophic pattern rejected: {e}")
    else:
        raise SystemExit("FAIL: (a+)+b was not rejected")

    # 3. Other dangerous shapes are rejected too.
    for dangerous in (r"(a*)*", r"(a+)*b", r"([a-z]+)+$"):
        try:
            safe_search(dangerous, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac")
        except RegexSecurityError:
            print(f"PASS: rejected dangerous shape {dangerous!r}")
        else:
            raise SystemExit(f"FAIL: dangerous pattern {dangerous!r} was not rejected")

    # 4. Oversized pattern is rejected.
    try:
        safe_search("a" * (MAX_PATTERN_LENGTH + 1), "x")
    except RegexSecurityError as e:
        print(f"PASS: oversized pattern rejected: {e}")
    else:
        raise SystemExit("FAIL: oversized pattern was accepted")

    # 5. Oversized input is rejected.
    try:
        safe_search(r"abc", "x" * (MAX_INPUT_LENGTH + 1))
    except RegexSecurityError as e:
        print(f"PASS: oversized input rejected: {e}")
    else:
        raise SystemExit("FAIL: oversized input was accepted")

    # 6. Invalid pattern raises RegexSecurityError, not a raw re.error.
    try:
        safe_search(r"(unclosed", "x")
    except RegexSecurityError as e:
        print(f"PASS: invalid pattern rejected cleanly: {e}")
    else:
        raise SystemExit("FAIL: invalid pattern did not raise RegexSecurityError")

    # 7. Empty pattern rejected.
    try:
        safe_search("", "x")
    except RegexSecurityError:
        print("PASS: empty pattern rejected")
    else:
        raise SystemExit("FAIL: empty pattern was accepted")

    print("\nAll redos_regex_fix self-tests passed.")
