"""
Fix for Issue #40 — HTTP Parameter Pollution
Agent: lushan888 (via dev-nana27)
Bounty: $10 USD

Fix: Validate and deduplicate HTTP parameters by keeping only the first value,
and reject requests with duplicate parameters to prevent HPP attacks.
"""

from flask import request, jsonify
from urllib.parse import parse_qs
from typing import Dict, List, Tuple, Optional


def sanitize_query_params(params: Dict[str, List[str]]) -> Dict[str, str]:
    """Deduplicate HTTP parameters — keep only the first value.

    Flask's default request.args allows duplicate keys, where the last value
    wins. An attacker can inject security parameters like ?admin=true&admin=false
    to bypass checks.

    This function returns the FIRST value for each parameter, preventing
    parameter pollution attacks.
    """
    return {k: v[0] for k, v in params.items() if v}


def get_deduplicated_params() -> Dict[str, str]:
    """Parse and deduplicate HTTP query parameters.

    Returns a dict with only the first value for each parameter name.
    """
    raw = request.query_string.decode("utf-8") if request.query_string else ""
    parsed = parse_qs(raw, keep_blank_values=True)
    return sanitize_query_params(parsed)


def validate_no_duplicate_params() -> Tuple[bool, Optional[Tuple]]:
    """Reject requests with duplicate parameters.

    Returns (is_valid, error_response_or_None).
    If is_valid is False, error_response is a Flask tuple (body, status_code).
    """
    raw = request.query_string.decode("utf-8") if request.query_string else ""
    if not raw:
        return True, None

    seen = set()
    for pair in raw.split("&"):
        if not pair:
            continue
        key = pair.split("=")[0]
        if key in seen:
            return (
                False,
                (
                    jsonify(
                        {
                            "error": "Duplicate parameter detected",
                            "message": "HTTP Parameter Pollution attack detected",
                        }
                    ),
                    400,
                ),
            )
        seen.add(key)
    return True, None