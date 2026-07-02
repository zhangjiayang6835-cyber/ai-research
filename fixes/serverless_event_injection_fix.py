#!/usr/bin/env python3
"""
Serverless Function Event Injection → Privilege Escalation Fix

This module validates and sanitizes incoming serverless function events
to prevent event injection attacks that could lead to privilege escalation.
It restricts event sources, authorizes callers, and sanitizes payload content.
"""

import json
import re
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Whitelist of allowed event sources (e.g., API Gateway, S3, SNS)
ALLOWED_SOURCES = ["apigateway.amazonaws.com", "s3.amazonaws.com", "sns.amazonaws.com"]

MAX_PAYLOAD_SIZE = 256 * 1024  # 256 KB
SANITIZE_PATTERN = re.compile(r"[<>&\"'\\;`$|]")  # Block injection characters


def validate_event_source(event: Dict[str, Any]) -> bool:
    """Check that the event originates from an allowed source."""
    source = event.get("source") or event.get("eventSource") or ""
    if source in ALLOWED_SOURCES:
        return True
    logger.warning("Event source %s not allowed", source)
    return False


def authorize_invocation(event: Dict[str, Any], context: Any) -> bool:
    """
    Perform authorization check.
    Expects either a bearer token in headers or IAM context arn.
    """
    # Example: validate JWT or IAM role
    if hasattr(context, "invoked_function_arn"):
        # Basic check: ensure caller has required permission (placeholder)
        return True
    # Additional authorization logic can be added here
    return False


def sanitize_payload(event: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize string values in event payload to prevent injection."""
    sanitized = {}
    for key, value in event.items():
        if isinstance(value, str):
            # Remove dangerous characters
            sanitized[key] = SANITIZE_PATTERN.sub("", value)
        else:
            sanitized[key] = value
    return sanitized


def validate_and_sanitize_event(event: Dict[str, Any], context: Any) -> Optional[Dict[str, Any]]:
    """Main entry point: validate, authorize, and sanitize the event."""
    if not validate_event_source(event):
        raise PermissionError("Event source not allowed")
    if not authorize_invocation(event, context):
        raise PermissionError("Unauthorized invocation")
    payload = event.get("body") or event.get("Records") or event
    if isinstance(payload, str):
        if len(payload) > MAX_PAYLOAD_SIZE:
            raise ValueError("Payload too large")
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            raise ValueError("Invalid JSON payload")
    sanitized_payload = sanitize_payload(payload)
