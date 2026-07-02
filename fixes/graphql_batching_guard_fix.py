"""
Fix for Issue #59 - GraphQL batching attack guard
=================================================

GraphQL servers often accept either a single JSON operation or an array of
operations. If the HTTP layer applies rate limiting only once per request, an
attacker can send a large batch and brute-force many auth tokens while paying for
one request. This helper closes that gap before the operations reach the GraphQL
executor.

The guard is framework-agnostic:

* cap the number of operations accepted in one GraphQL request;
* reject empty or malformed batch payloads deterministically;
* apply a per-query rate-limit check to every operation inside the batch;
* expose clear rejection reasons that can be logged or returned as HTTP 400/429.

Drop it into a Flask/FastAPI/Django/ASGI GraphQL endpoint before calling the
actual schema executor.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, MutableMapping, Sequence


DEFAULT_MAX_BATCH_OPERATIONS = 10
DEFAULT_PER_QUERY_LIMIT = 30
DEFAULT_RATE_WINDOW_SECONDS = 60


class GraphQLBatchingRejected(ValueError):
    """Raised when a GraphQL request fails batching or per-query limits."""

    def __init__(self, reason: str, *, status_code: int = 400) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status_code = status_code


@dataclass
class InMemoryQueryRateLimiter:
    """Small dependency-free fixed-window limiter for per-operation checks."""

    max_operations: int = DEFAULT_PER_QUERY_LIMIT
    window_seconds: int = DEFAULT_RATE_WINDOW_SECONDS
    clock: Callable[[], float] = time.time
    _hits: MutableMapping[str, list[float]] = field(default_factory=dict)

    def allow(self, key: str) -> bool:
        now = self.clock()
        window_start = now - self.window_seconds
        bucket = [seen_at for seen_at in self._hits.get(key, []) if seen_at > window_start]
        if len(bucket) >= self.max_operations:
            self._hits[key] = bucket
            return False
        bucket.append(now)
        self._hits[key] = bucket
        return True


def _normalise_operations(payload: Any) -> list[Mapping[str, Any]]:
    if isinstance(payload, Mapping):
        operations: Sequence[Any] = [payload]
    elif isinstance(payload, list):
        operations = payload
    else:
        raise GraphQLBatchingRejected("graphql payload must be an object or array")

    if not operations:
        raise GraphQLBatchingRejected("graphql batch must contain at least one operation")

    normalised: list[Mapping[str, Any]] = []
    for index, operation in enumerate(operations):
        if not isinstance(operation, Mapping):
            raise GraphQLBatchingRejected(f"graphql operation {index} must be an object")
        query = operation.get("query")
        if not isinstance(query, str) or not query.strip():
            raise GraphQLBatchingRejected(f"graphql operation {index} has no query")
        normalised.append(operation)
    return normalised


def _operation_fingerprint(operation: Mapping[str, Any]) -> str:
    query = " ".join(str(operation.get("query", "")).split())
    operation_name = str(operation.get("operationName") or "")
    digest = hashlib.sha256(f"{operation_name}\0{query}".encode("utf-8")).hexdigest()
    return digest[:24]


@dataclass
class GraphQLBatchingGuard:
    """Validate GraphQL request payloads before execution."""

    max_batch_operations: int = DEFAULT_MAX_BATCH_OPERATIONS
    rate_limiter: InMemoryQueryRateLimiter = field(default_factory=InMemoryQueryRateLimiter)

    def __post_init__(self) -> None:
        if self.max_batch_operations < 1:
            raise ValueError("max_batch_operations must be at least 1")

    def validate(self, payload: Any, *, client_id: str) -> list[Mapping[str, Any]]:
        operations = _normalise_operations(payload)
        if len(operations) > self.max_batch_operations:
            raise GraphQLBatchingRejected(
                f"graphql batch contains {len(operations)} operations; limit is {self.max_batch_operations}"
            )

        for operation in operations:
            key = f"{client_id}:{_operation_fingerprint(operation)}"
            if not self.rate_limiter.allow(key):
                raise GraphQLBatchingRejected("graphql per-query rate limit exceeded", status_code=429)

        return operations


def graphql_error_response(exc: GraphQLBatchingRejected) -> tuple[dict[str, Any], int]:
    """Convert a guard failure into a simple JSON response tuple."""

    return {"error": exc.reason}, exc.status_code


if __name__ == "__main__":
    import unittest

    class GraphQLBatchingGuardTests(unittest.TestCase):
        def test_accepts_single_operation(self) -> None:
            guard = GraphQLBatchingGuard(max_batch_operations=2)
            operations = guard.validate({"query": "query Me { me { id } }"}, client_id="ip:1")
            self.assertEqual(len(operations), 1)

        def test_accepts_batch_within_limit(self) -> None:
            guard = GraphQLBatchingGuard(max_batch_operations=2)
            payload = [
                {"query": "query A { viewer { id } }", "operationName": "A"},
                {"query": "query B { health }", "operationName": "B"},
            ]
            self.assertEqual(guard.validate(payload, client_id="ip:1"), payload)

        def test_rejects_oversized_batch_before_execution(self) -> None:
            guard = GraphQLBatchingGuard(max_batch_operations=1)
            with self.assertRaises(GraphQLBatchingRejected) as ctx:
                guard.validate([{"query": "query A { a }"}, {"query": "query B { b }"}], client_id="ip:1")
            self.assertIn("limit is 1", ctx.exception.reason)
            self.assertEqual(ctx.exception.status_code, 400)

        def test_rejects_malformed_batch_operation(self) -> None:
            guard = GraphQLBatchingGuard()
            with self.assertRaises(GraphQLBatchingRejected):
                guard.validate([{"variables": {"token": "guess"}}], client_id="ip:1")

        def test_each_batched_query_consumes_rate_limit(self) -> None:
            limiter = InMemoryQueryRateLimiter(max_operations=1, window_seconds=60, clock=lambda: 1000.0)
            guard = GraphQLBatchingGuard(max_batch_operations=5, rate_limiter=limiter)
            operation = {"query": "query Token($token: String!) { check(token: $token) }", "operationName": "Token"}

            guard.validate([operation], client_id="ip:1")
            with self.assertRaises(GraphQLBatchingRejected) as ctx:
                guard.validate([operation], client_id="ip:1")
            self.assertEqual(ctx.exception.status_code, 429)

        def test_rate_limit_is_per_client_and_per_query(self) -> None:
            limiter = InMemoryQueryRateLimiter(max_operations=1, window_seconds=60, clock=lambda: 1000.0)
            guard = GraphQLBatchingGuard(max_batch_operations=5, rate_limiter=limiter)
            query_a = {"query": "query A { a }", "operationName": "A"}
            query_b = {"query": "query B { b }", "operationName": "B"}

            guard.validate([query_a], client_id="ip:1")
            guard.validate([query_b], client_id="ip:1")
            guard.validate([query_a], client_id="ip:2")

    unittest.main()
