import json
import os
from typing import Any, Dict

# Define allowed roles to prevent privilege escalation
ALLOWED_ROLES = {'admin', 'editor', 'viewer'}

def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Serverless function handler that updates user roles securely.
    Fixes Event Injection vulnerability by validating and sanitizing inputs,
    and enforcing authorization checks.
    """
    # Parse event body safely
    try:
        body = json.loads(event.get('body', '{}'))
    except json.JSONDecodeError:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Invalid JSON in request body'})
        }

    # Extract and validate target user ID
    target_user = body.get('userId')
    if not target_user or not isinstance(target_user, str):
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Invalid or missing userId'})
        }

    # Extract and validate new role
    new_role = body.get('role')
    if new_role not in ALLOWED_ROLES:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': f'Invalid role. Allowed: {ALLOWED_ROLES}'})
        }

    # Authorization: Check if requester has admin privileges
    # Here we assume event.requestContext.authorizer contains user info
    # In real app, verify token, session, etc.
    try:
        requester_role = event['requestContext']['authorizer']['claims']['custom:role']
    except (KeyError, TypeError):
        return {
            'statusCode': 401,
            'body': json.dumps({'error': 'Unauthorized: missing authentication'})
        }

    # Only admins can change roles
    if requester_role != 'admin':
        return {
            'statusCode': 403,
            'body': json.dumps({'error': 'Forbidden: insufficient privileges'})
        }

    # Business logic: Update role in database (pseudo-code)
    # db_update_user_role(target_user, new_role)

    return {
        'statusCode': 200,
        'body': json.dumps({'message': f'Role for user {target_user} updated to {new_role}'})
    }
