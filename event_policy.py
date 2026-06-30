import os
import hmac
import time

PRIVILEGED_EVENT_FIELDS = frozenset({
    "role",
    "is_admin",
    "isAdmin",
    "admin_role",
    "permissions",
    "groups",
    "claims",
    "authorizer",
    "privileged",
    "auth_level",
    "access_level",
    "clearance",
    "scope",
    "roles",
    "is_superuser",
    "superuser",
})


def _load_valid_api_keys() -> frozenset:
    raw = os.environ.get("EVENT_POLICY_API_KEYS", "")
    if not raw:
        return frozenset()
    return frozenset(k.strip() for k in raw.split(",") if k.strip())


def authenticate_event(event: dict) -> tuple[bool, str]:
    valid_keys = _load_valid_api_keys()
    if not valid_keys:
        return False, "endpoint_disabled_no_keys_configured"
    api_key = ""
    headers = event.get("headers", {})
    if isinstance(headers, dict):
        api_key = headers.get("x-api-key", headers.get("X-Api-Key", ""))
    if not api_key:
        api_key = event.get("api_key", "")
    if not api_key:
        return False, "missing_api_key"
    for valid in valid_keys:
        if hmac.compare_digest(api_key, valid):
            return True, ""
    return False, "invalid_api_key"


def parse_event_body(event: dict) -> dict:
    if not isinstance(event, dict):
        return {}
    body = event.get("body", event.get("event", {}))
    if isinstance(body, str):
        try:
            import json
            body = json.loads(body)
        except (json.JSONDecodeError, ValueError, TypeError):
            body = {}
    if not isinstance(body, dict):
        body = {}
    return body


def extract_trusted_claims(event: dict) -> dict:
    authorizer = (
        event.get("requestContext", {})
        .get("authorizer", {})
        .get("claims", {})
    )
    if isinstance(authorizer, dict):
        return authorizer
    return {}


def handle_serverless_event(event: dict) -> dict:
    authenticated, auth_msg = authenticate_event(event)
    if not authenticated:
        return {
            "success": False,
            "error": "unauthorized",
            "detail": auth_msg,
            "privilege_escalation": False,
        }
    body = parse_event_body(event)
    for field in body:
        if field in PRIVILEGED_EVENT_FIELDS:
            return {
                "success": False,
                "error": "privilege_injection_blocked",
                "field": field,
                "privilege_escalation": False,
            }
    claims = extract_trusted_claims(event)
    role = claims.get("role", "user")
    is_admin = str(claims.get("is_admin", "false")).lower() == "true"
    permissions = claims.get("permissions", [])
    return {
        "success": True,
        "role": role,
        "is_admin": is_admin,
        "permissions": permissions,
        "privilege_escalation": False,
    }
