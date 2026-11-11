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
