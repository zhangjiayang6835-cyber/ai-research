"""
Fix for Issue #947 — GraphQL Batch Query + Rate Limit Bypass
============================================================

Vulnerability
-------------
The GraphQL endpoint allows batch requests (multiple queries in a single HTTP
request), but rate limiting is only applied per HTTP request, not per query.
An attacker can send hundreds of queries in a single request, bypassing the
rate limit and scraping data at high throughput.

Fix Strategy
------------
1. Implement query complexity analysis — assign a cost to each field/query.
2. Enforce maximum query depth to prevent deeply nested queries.
3. Aggregate costs across batch requests and reject if total exceeds limit.
4. Rate limit based on total query cost, not just request count.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence


# Default cost limits
DEFAULT_MAX_COMPLEXITY = 1000  # Max total complexity per request
DEFAULT_MAX_DEPTH = 10         # Max query nesting depth
DEFAULT_MAX_BATCH_SIZE = 10    # Max queries per batch request
DEFAULT_COST_PER_FIELD = 1     # Base cost for each field
DEFAULT_COST_PER_CONNECTION = 5  # Additional cost for list/connection fields

# Rate limiting
DEFAULT_RATE_LIMIT_COST = 5000  # Max total cost per time window
DEFAULT_RATE_WINDOW = 60        # Time window in seconds

# Regex to detect connection/list fields (plural names)
CONNECTION_FIELD_RE = re.compile(r"^(list|all|get|search|find|query|fetch|load|query|search)\w*$", re.IGNORECASE)


class GraphQLRateLimitError(Exception):
    """Raised when a GraphQL request exceeds rate limits."""


@dataclass
class QueryCost:
    """Cost analysis result for a single GraphQL query."""
    total_cost: int = 0
    depth: int = 0
    field_count: int = 0
    connection_count: int = 0

    def __add__(self, other: QueryCost) -> QueryCost:
        return QueryCost(
            total_cost=self.total_cost + other.total_cost,
            depth=max(self.depth, other.depth),
            field_count=self.field_count + other.field_count,
            connection_count=self.connection_count + other.connection_count,
        )


@dataclass
class GraphQLRateLimiter:
    """Rate limiter with cost-based throttling for GraphQL endpoints.

    Usage::

        limiter = GraphQLRateLimiter()

        # On each request:
        try:
            limiter.check_request(queries, client_ip)
        except GraphQLRateLimitError:
            return 429 Too Many Requests
    """

    max_complexity: int = DEFAULT_MAX_COMPLEXITY
    max_depth: int = DEFAULT_MAX_DEPTH
    max_batch_size: int = DEFAULT_MAX_BATCH_SIZE
    cost_per_field: int = DEFAULT_COST_PER_FIELD
    cost_per_connection: int = DEFAULT_COST_PER_CONNECTION
    rate_limit_cost: int = DEFAULT_RATE_LIMIT_COST
    rate_window: int = DEFAULT_RATE_WINDOW

    # Client usage tracking: {client_key: [(timestamp, cost), ...]}
    _client_usage: dict[str, list[tuple[float, int]]] = field(default_factory=dict)

    def check_request(self, queries: list[dict[str, Any]], client_id: str) -> list[QueryCost]:
        """Validate and compute costs for a batch of GraphQL queries.

        Args:
            queries: List of parsed GraphQL query objects. Each query should
                     have a ``query`` string and optional ``operationName``.
            client_id: Identifier for the client (IP address, API key, etc.).

        Returns:
            List of QueryCost objects for each query.

        Raises:
            GraphQLRateLimitError: If any limit is exceeded.
        """
        # Check batch size
        if len(queries) > self.max_batch_size:
            raise GraphQLRateLimitError(
                f"batch size {len(queries)} exceeds maximum of {self.max_batch_size}"
            )

        # Analyze each query
        costs = []
        total_cost = 0

        for query_data in queries:
            query_str = query_data.get("query", "")
            if not query_str:
                raise GraphQLRateLimitError("empty query in batch request")

            cost = self._analyze_query(query_str)
            costs.append(cost)
            total_cost += cost.total_cost

            # Check individual query depth
            if cost.depth > self.max_depth:
                raise GraphQLRateLimitError(
                    f"query depth {cost.depth} exceeds maximum of {self.max_depth}"
                )

        # Check total complexity
        if total_cost > self.max_complexity:
            raise GraphQLRateLimitError(
                f"total query complexity {total_cost} exceeds maximum of {self.max_complexity}"
            )

        # Check rate limit
        self._check_rate_limit(client_id, total_cost)

        return costs

    def _analyze_query(self, query_str: str) -> QueryCost:
        """Analyze a GraphQL query string to compute its cost.

        This is a simplified cost analysis that estimates complexity
        based on field count, nesting depth, and connection patterns.
        In production, use a proper GraphQL query parser (e.g., graphql-core)
        for accurate AST-based analysis.
        """
        cost = QueryCost()
        depth = 0
        brace_depth = 0

        # Simple parser: count fields and track nesting depth
        i = 0
        in_string = False
        in_comment = False
        current_word = ""

        while i < len(query_str):
            ch = query_str[i]

            # Handle string literals
            if ch in ("'", '"') and not in_comment:
                in_string = not in_string
                i += 1
                continue

            if in_string:
                i += 1
                continue

            # Handle comments
            if ch == "#" and not in_comment:
                in_comment = True
                i += 1
                continue
            if ch == "\n" and in_comment:
                in_comment = False
                i += 1
                continue
            if in_comment:
                i += 1
                continue

            # Track braces for depth
            if ch == "{":
                brace_depth += 1
                depth = max(depth, brace_depth)
                # New selection set — potential field boundary
                if current_word:
                    cost.field_count += 1
                    if self._is_connection_field(current_word):
                        cost.connection_count += 1
                    current_word = ""
            elif ch == "}":
                brace_depth = max(0, brace_depth - 1)
            elif ch in (" ", "\n", "\t", ",", "(", ")"):
                if current_word and current_word not in _GRAPHQL_KEYWORDS:
                    # Check if this is a field name (not a keyword/argument)
                    pass
                current_word = ""
            else:
                current_word += ch

            i += 1

        # Compute total cost
        cost.depth = depth
        cost.total_cost = (
            cost.field_count * self.cost_per_field
            + cost.connection_count * self.cost_per_connection
        )

        return cost

    def _is_connection_field(self, field_name: str) -> bool:
        """Check if a field name suggests a connection/list query."""
        return bool(CONNECTION_FIELD_RE.match(field_name))

    def _check_rate_limit(self, client_id: str, cost: int) -> None:
        """Check and update rate limit for a client."""
        now = time.time()
        window_start = now - self.rate_window

        # Get or create usage history
        if client_id not in self._client_usage:
            self._client_usage[client_id] = []

        # Clean up old entries
        usage = self._client_usage[client_id]
        self._client_usage[client_id] = [
            (ts, c) for ts, c in usage if ts > window_start
        ]

        # Calculate total cost in current window
        current_cost = sum(c for _, c in self._client_usage[client_id])

        # Check if adding this request would exceed the limit
        if current_cost + cost > self.rate_limit_cost:
            reset_time = int(window_start + self.rate_window)
            raise GraphQLRateLimitError(
                f"rate limit exceeded. "
                f"current cost: {current_cost}, "
                f"request cost: {cost}, "
                f"limit: {self.rate_limit_cost} per {self.rate_window}s. "
                f"resets at: {reset_time}"
            )

        # Record this request
        self._client_usage[client_id].append((now, cost))

    def get_client_usage(self, client_id: str) -> int:
        """Get current usage cost for a client in the current window."""
        now = time.time()
        window_start = now - self.rate_window
        usage = self._client_usage.get(client_id, [])
        return sum(c for ts, c in usage if ts > window_start)


# GraphQL keywords that should not be counted as fields
_GRAPHQL_KEYWORDS = frozenset({
    "query", "mutation", "subscription", "fragment",
    "on", "type", "interface", "union", "enum", "input",
    "extend", "directive", "schema", "scalar",
    "true", "false", "null",
})


# ---------------------------------------------------------------------------
# Middleware example
# ---------------------------------------------------------------------------

def make_graphql_rate_limit_middleware(
    app: Callable,
    limiter: GraphQLRateLimiter | None = None,
    get_client_id: Callable | None = None,
) -> Callable:
    """WSGI middleware for GraphQL rate limiting.

    Usage::

        app = Flask(__name__)
        app.wsgi_app = make_graphql_rate_limit_middleware(app.wsgi_app)

        @app.route("/graphql", methods=["POST"])
        def graphql_endpoint():
            data = request.get_json()
            # queries = [data] or data (for batch)
            # limiter.check_request(queries, request.remote_addr)
            ...
    """
    import json

    if limiter is None:
        limiter = GraphQLRateLimiter()

    if get_client_id is None:
        def get_client_id(environ):
            return environ.get("REMOTE_ADDR", "unknown")

    def middleware(environ, start_response):
        path = environ.get("PATH_INFO", "")
        if path != "/graphql":
            return app(environ, start_response)

        client_id = get_client_id(environ)

        # Read request body
        try:
            content_length = int(environ.get("CONTENT_LENGTH", 0))
            body = environ["wsgi.input"].read(content_length)
            data = json.loads(body)
        except (ValueError, KeyError):
            start_response("400 Bad Request", [("Content-Type", "application/json")])
            return [b'{"error": "invalid request body"}']

        # Normalize to list of queries
        if isinstance(data, dict):
            queries = [data]
        elif isinstance(data, list):
            queries = data
        else:
            start_response("400 Bad Request", [("Content-Type", "application/json")])
            return [b'{"error": "invalid request format"}']

        try:
            limiter.check_request(queries, client_id)
        except GraphQLRateLimitError as e:
            start_response(
                "429 Too Many Requests",
                [("Content-Type", "application/json"),
                 ("Retry-After", "60")],
            )
            return [json.dumps({"error": str(e)}).encode("utf-8")]

        return app(environ, start_response)

    return middleware