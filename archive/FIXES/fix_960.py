"""
Fix for Issue #960 — IDOR in GraphQL Nested Query → Mass Data Leak
====================================================================

Vulnerability
-------------
GraphQL queries like user(id: 123) { orders { items { price } } } do not check
whether the current user has permission to access that user's order data.
Attackers iterate through user IDs to leak all users' information.

Fix Strategy
------------
1. Implement DataLoader-level permission checks.
2. Use auth context from the request, not client-provided IDs.
3. Verify data ownership at each resolver level.
4. Add query rate limiting.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class AuthContext:
    """Authentication context extracted from the request."""
    user_id: str
    roles: set[str] = field(default_factory=set)
    is_authenticated: bool = False


@dataclass
class GraphQLResolver:
    """A GraphQL resolver with built-in authorization checking."""

    name: str
    resolve_fn: Callable
    authorize_fn: Callable | None = None

    def resolve(self, parent: Any, args: dict, context: AuthContext) -> Any:
        """Resolve with authorization check."""
        if self.authorize_fn and not self.authorize_fn(parent, args, context):
            raise PermissionError(f"Access denied to resolver '{self.name}'")
        return self.resolve_fn(parent, args, context)


class OwnershipChecker:
    """
    Checks that a user can only access their own data.
    """

    @staticmethod
    def check_user_access(target_user_id: str, context: AuthContext) -> bool:
        """Check if the current user can access the target user's data."""
        if not context.is_authenticated:
            return False
        if context.user_id == target_user_id:
            return True
        if "admin" in context.roles:
            return True
        return False

    @staticmethod
    def check_order_access(order_user_id: str, context: AuthContext) -> bool:
        """Check if the current user can access an order."""
        return OwnershipChecker.check_user_access(order_user_id, context)

    @staticmethod
    def check_item_access(item_owner_id: str, context: AuthContext) -> bool:
        """Check if the current user can access an item."""
        return OwnershipChecker.check_user_access(item_owner_id, context)


class RateLimiter:
    """Simple rate limiter for GraphQL queries."""

    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)

    def check(self, user_id: str) -> bool:
        """Check if the user has exceeded the rate limit."""
        now = time.time()
        cutoff = now - self.window_seconds
        user_requests = self._requests[user_id]
        # Remove expired entries
        self._requests[user_id] = [t for t in user_requests if t > cutoff]
        if len(self._requests[user_id]) >= self.max_requests:
            return False
        self._requests[user_id].append(now)
        return True


# Example resolvers with authorization
def resolve_user(parent: Any, args: dict, context: AuthContext) -> dict | None:
    """Resolve a user, checking ownership."""
    target_id = args.get("id", "")
    if not OwnershipChecker.check_user_access(target_id, context):
        return None
    # Fetch user data...
    return {"id": target_id, "name": "User"}


def resolve_orders(parent: dict, args: dict, context: AuthContext) -> list[dict]:
    """Resolve orders, checking ownership against parent user."""
    user_id = parent.get("id", "")
    if not OwnershipChecker.check_order_access(user_id, context):
        return []
    # Fetch orders...
    return [{"id": "order1", "price": 100}]


# Rate limited resolver
rate_limiter = RateLimiter(max_requests=50, window_seconds=60)


def resolve_with_rate_limit(resolver_fn: Callable, args: dict, context: AuthContext) -> Any:
    """Wrap a resolver with rate limiting."""
    if not rate_limiter.check(context.user_id):
        raise Exception("Rate limit exceeded")
    return resolver_fn({}, args, context)
