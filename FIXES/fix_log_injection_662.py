"""
fix_log_injection_662.py — Log Injection → Log Forging → SIEM Poisoning Fix

VULNERABILITY (#662):
User input (username, User-Agent, etc.) written directly to log files
without sanitization. Attackers inject \\r\\n to forge log entries,
poisoning SIEM detection logic.

FIX:
1. Strip all \\r \\n from log inputs (CRLF removal)
2. Structured JSON logging format (prevents log forging entirely)
3. Log schema validation on every field
4. Reject entries exceeding safe length
"""

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class LogSecurityConfig:
    """Log injection prevention configuration."""
    max_field_length: int = 4096
    max_entry_length: int = 8192
    allow_json_output: bool = True
    log_level_whitelist: frozenset = field(
        default_factory=lambda: frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})
    )
    # Fields that are allowed in structured logs
    allowed_fields: frozenset = field(
        default_factory=lambda: frozenset({
            "timestamp", "level", "message", "username", "user_agent",
            "remote_addr", "method", "path", "status", "duration_ms",
            "session_id", "trace_id", "event_type",
        })
    )


DEFAULT_CONFIG = LogSecurityConfig()

# CRLF / line-break patterns
_CRLF_RE = re.compile(r'[\r\n]')
_CONTROL_CHAR_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')


# =============================================================================
# Log Sanitizer
# =============================================================================

class LogSanitizer:
    """Strips dangerous characters from log input fields."""

    @staticmethod
    def sanitize(value: str, config: LogSecurityConfig = DEFAULT_CONFIG) -> str:
        """
        Remove CRLF, control chars, and enforce length limits.

        Returns a clean string safe for log storage.
        """
        if not isinstance(value, str):
            return str(value)

        # Strip CR/LF
        cleaned = _CRLF_RE.sub('', value)
        # Strip control characters (except normal whitespace like space/tab)
        cleaned = _CONTROL_CHAR_RE.sub('', cleaned)
        # Enforce max field length
        if len(cleaned) > config.max_field_length:
            cleaned = cleaned[:config.max_field_length]
        return cleaned

    @staticmethod
    def contains_crlf(value: str) -> bool:
        """Detect if a raw value contains CRLF sequences."""
        return bool(_CRLF_RE.search(value))

    @staticmethod
    def contains_control_chars(value: str) -> bool:
        """Detect if a raw value contains dangerous control characters."""
        return bool(_CONTROL_CHAR_RE.search(value))


# =============================================================================
# Log Schema Validator
# =============================================================================

class LogSchemaValidator:
    """Validates log entry structure against an allowed schema."""

    def __init__(self, config: LogSecurityConfig = DEFAULT_CONFIG):
        self.config = config

    def validate(self, entry: Dict[str, Any]) -> tuple[bool, str]:
        """
        Validate a log entry dict against the schema.

        Returns (is_valid, error_message).
        """
        if not isinstance(entry, dict):
            return False, "Log entry must be a dict"

        unknown_keys = set(entry.keys()) - self.config.allowed_fields
        if unknown_keys:
            return False, f"Unknown log fields: {unknown_keys}"

        # Required field
        if 'timestamp' not in entry:
            return False, "Missing required field: timestamp"

        # Level validation
        level = entry.get('level', '')
        if level not in self.config.log_level_whitelist:
            return False, f"Invalid log level: {level}"

        # Message validation
        message = entry.get('message', '')
        if not isinstance(message, str) or not message.strip():
            return False, "Message must be a non-empty string"

        return True, ""

    def validate_and_sanitize(self, entry: Dict[str, Any]) -> tuple[bool, Dict[str, Any], str]:
        """
        Validate AND sanitize every field in the entry.

        Returns (is_valid, sanitized_entry, error_message).
        """
        ok, err = self.validate(entry)
        if not ok:
            return False, {}, err

        sanitized = {}
        for key, value in entry.items():
            if isinstance(value, str):
                sanitized[key] = LogSanitizer.sanitize(value, self.config)
            else:
                sanitized[key] = value

        # Final length check on the full JSON
        try:
            serialized = json.dumps(sanitized)
            if len(serialized) > self.config.max_entry_length:
                return False, sanitized, f"Serialized entry exceeds {self.config.max_entry_length} bytes"
        except (TypeError, ValueError) as e:
            return False, sanitized, f"Serialization error: {e}"

        return True, sanitized, ""


# =============================================================================
# Structured JSON Logger
# =============================================================================

class SecureJSONLogger:
    """
    Writes log entries in structured JSON format.

    Because each log entry is a single JSON object on one line,
    CRLF injection is impossible — newlines in values are escaped
    by the JSON serializer.
    """

    def __init__(self, config: LogSecurityConfig = DEFAULT_CONFIG):
        self.config = config
        self.validator = LogSchemaValidator(config)

    def log(self, level: str, message: str, **extra_fields) -> Optional[str]:
        """
        Build and return a safe JSON log line.

        All user-controlled fields are sanitized before inclusion.
        """
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "message": message,
        }
        entry.update(extra_fields)

        ok, sanitized, err = self.validator.validate_and_sanitize(entry)
        if not ok:
            # Fallback: write a safe error record instead
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": "ERROR",
                "message": f"[LOG_SANITIZATION_FAILED] {err}",
            }
            sanitized = entry

        return json.dumps(sanitized, ensure_ascii=False)

    def log_access(self, remote_addr: str, method: str, path: str,
                   status: int, user_agent: str = "", username: str = "") -> Optional[str]:
        """Build a structured access-log entry."""
        return self.log(
            "INFO",
            f"{method} {path} {status}",
            remote_addr=remote_addr,
            method=method,
            path=path,
            status=status,
            user_agent=user_agent,
            username=username,
        )

    def log_auth_event(self, event: str, username: str, success: bool,
                       user_agent: str = "", remote_addr: str = "") -> Optional[str]:
        """Build an authentication event log entry."""
        return self.log(
            "WARNING" if not success else "INFO",
            f"auth.{event}: user={username} success={success}",
            username=username,
            event=event,
            success=success,
            user_agent=user_agent,
            remote_addr=remote_addr,
        )


# =============================================================================
# Legacy Compatibility — CRLF-safe plain-text logger
# =============================================================================

class CRLFSafeLogger:
    """
    Drop-in replacement for legacy plain-text loggers.

    Strips CRLF from every field before writing.
    Prefer SecureJSONLogger for new code.
    """

    def __init__(self, config: LogSecurityConfig = DEFAULT_CONFIG):
        self.config = config

    def write(self, message: str, **fields) -> str:
        """Write a single-line log entry with CRLF stripped from all fields."""
        parts = [LogSanitizer.sanitize(str(message), self.config)]
        for k, v in fields.items():
            safe_k = LogSanitizer.sanitize(str(k), self.config)
            safe_v = LogSanitizer.sanitize(str(v), self.config)
            parts.append(f"{safe_k}={safe_v}")
        return " | ".join(parts) + "\n"


# =============================================================================
# Tests
# =============================================================================

def test_crlf_removal():
    assert LogSanitizer.sanitize("admin\r\nmalicious") == "adminmalicious"
    assert LogSanitizer.sanitize("test\nline") == "testline"
    assert LogSanitizer.sanitize("normal text") == "normal text"
    assert LogSanitizer.contains_crlf("hello\r\nworld")
    assert not LogSanitizer.contains_crlf("hello world")
    print("PASS: CRLF removal works")


def test_control_char_removal():
    assert '\x00' not in LogSanitizer.sanitize("test\x00value")
    assert '\x1f' not in LogSanitizer.sanitize("test\x1fvalue")
    print("PASS: Control char removal works")


def test_schema_validation():
    v = LogSchemaValidator()
    ok, err = v.validate({"timestamp": "2026-01-01T00:00:00Z", "level": "INFO", "message": "hello"})
    assert ok, err
    ok, err = v.validate({"timestamp": "2026-01-01T00:00:00Z", "level": "INVALID", "message": "hello"})
    assert not ok
    ok, err = v.validate({"level": "INFO", "message": "no timestamp"})
    assert not ok
    ok, err = v.validate({"timestamp": "2026-01-01T00:00:00Z", "level": "INFO", "message": "hello", "evil_field": "x"})
    assert not ok
    print("PASS: Schema validation works")


def test_structured_json_logging():
    logger = SecureJSONLogger()
    line = logger.log("INFO", "user logged in", username="admin\nbad", user_agent="Mozilla\r\nInjected")
    assert line is not None
    parsed = json.loads(line)
    assert '\n' not in parsed['username']
    assert '\r' not in parsed['user_agent']
    assert parsed['level'] == 'INFO'
    print("PASS: Structured JSON logging works")


def test_access_log():
    logger = SecureJSONLogger()
    line = logger.log_access(
        "10.0.0.1", "GET", "/api/test", 200,
        user_agent="Mozilla/5.0\r\nX-Evil: true",
        username="admin\ninject"
    )
    parsed = json.loads(line)
    assert '\r' not in parsed.get('user_agent', '')
    assert '\n' not in parsed.get('username', '')
    print("PASS: Access log sanitization works")


def test_legacy_crlf_safe_logger():
    logger = CRLFSafeLogger()
    line = logger.write("login attempt", username="hacker\r\n伪造条目", ip="1.2.3.4")
    assert '\r' not in line
    assert '\n' not in line.replace('\n', '', 1)  # only trailing newline
    print("PASS: Legacy CRLF-safe logger works")


if __name__ == "__main__":
    test_crlf_removal()
    test_control_char_removal()
    test_schema_validation()
    test_structured_json_logging()
    test_access_log()
    test_legacy_crlf_safe_logger()
    print("\n✅ All log injection prevention tests passed!")
