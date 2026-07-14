"""Secure structured logger with CRLF escaping and schema validation."""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional


class LogSchemaValidator:
    """Validates log entries against a defined schema."""

    REQUIRED_FIELDS = {"timestamp", "level", "message", "source"}
    ALLOWED_FIELDS = REQUIRED_FIELDS | {"username", "user_agent", "ip_address",
                                         "request_id", "endpoint", "status_code",
                                         "extra"}
    MAX_STRING_LENGTH = 1024

    @classmethod
    def validate(cls, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize a log entry.

        Args:
            log_entry: The log entry dictionary to validate.

        Returns:
            A sanitized log entry dictionary.

        Raises:
            ValueError: If required fields are missing.
        """
        missing = cls.REQUIRED_FIELDS - set(log_entry.keys())
        if missing:
            raise ValueError(f"Missing required log fields: {missing}")

        sanitized = {}
        for key, value in log_entry.items():
            if key not in cls.ALLOWED_FIELDS:
                continue
            if isinstance(value, str):
                value = cls._sanitize_string(value)
            sanitized[key] = value

        return sanitized

    @classmethod
    def _sanitize_string(cls, value: str) -> str:
        """Escape CRLF characters and truncate long strings.

        Args:
            value: The string to sanitize.

        Returns:
            Sanitized string with CRLF escaped and length limited.
        """
        # Escape CRLF characters to prevent log injection
        value = value.replace("\r", "\\r")
        value = value.replace("\n", "\\n")

        # Truncate excessively long strings
        if len(value) > cls.MAX_STRING_LENGTH:
            value = value[:cls.MAX_STRING_LENGTH] + "...[TRUNCATED]"

        return value


class SecureJSONFormatter(logging.Formatter):
    """JSON formatter that sanitizes log records against injection."""

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record as a sanitized JSON string.

        Args:
            record: The log record to format.

        Returns:
            A JSON string representation of the sanitized log entry.
        """
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": LogSchemaValidator._sanitize_string(record.getMessage()),
            "source": record.name,
        }

        # Include extra fields if present
        if hasattr(record, "username"):
            log_entry["username"] = LogSchemaValidator._sanitize_string(
                str(record.username)
            )
        if hasattr(record, "user_agent"):
            log_entry["user_agent"] = LogSchemaValidator._sanitize_string(
                str(record.user_agent)
            )

        return json.dumps(log_entry, ensure_ascii=False)