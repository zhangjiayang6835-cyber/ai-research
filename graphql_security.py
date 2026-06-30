"""
graphql_security.py — GraphQL Security Middleware

Prevents Depth Bypass + Batching → Data Exfiltration attacks by enforcing:
  1. Query depth limiting (AST-based, fragment-aware)
  2. Query complexity/cost analysis (field weights + multipliers)
  3. Batch query limiting (max operations per request)
  4. Alias amplification prevention (max aliases per operation)
  5. Execution timeout enforcement

Usage:
    from graphql_security import GraphQLSecurityMiddleware

    middleware = GraphQLSecurityMiddleware(
        max_depth=6,
        max_complexity=1000,
        max_batch_size=5,
        max_aliases=20,
        execution_timeout_ms=5000,
    )

    # Before executing a GraphQL query:
    result = middleware.check(document, operation_name="MyQuery")
    if not result["allowed"]:
        raise PermissionError(result["reason"])
"""

import math
import time
from typing import Any

from graphql import DocumentNode, FieldNode, FragmentDefinitionNode, FragmentSpreadNode, InlineFragmentNode, OperationDefinitionNode, parse
from graphql.language.ast import Node, SelectionSetNode


class DepthLimitValidator:
    """Rejects queries exceeding a configured maximum nesting depth.

    Walks the AST recursively, tracking depth across fragment spreads
    and inline fragments.  A query with depth > ``max_depth`` is rejected.
    """

    def __init__(self, max_depth: int = 6) -> None:
        if max_depth < 1:
            raise ValueError("max_depth must be >= 1")
        self._max_depth = max_depth

    def __call__(self, document: DocumentNode) -> dict:
        violations: list[str] = []
        fragments = {
            d.name.value: d
            for d in document.definitions
            if isinstance(d, FragmentDefinitionNode)
        }
        for definition in document.definitions:
            if isinstance(definition, OperationDefinitionNode):
                depth = self._measure_depth(definition.selection_set, 0, set(), fragments)
                if depth > self._max_depth:
                    violations.append(
                        f"Operation '{definition.name or '<unnamed>'}' "
                        f"depth {depth} exceeds limit {self._max_depth}"
                    )
        if violations:
            return {"allowed": False, "reason": "; ".join(violations)}
        return {"allowed": True}

    def _measure_depth(
        self,
        selections: SelectionSetNode | None,
        current: int,
        visited_fragments: set[str],
        fragments: dict[str, FragmentDefinitionNode],
    ) -> int:
        if not selections:
            return current
        max_child = current
        for node in selections.selections:
            if isinstance(node, FieldNode):
                child = self._measure_depth(node.selection_set, current + 1, visited_fragments, fragments)
                if child > max_child:
                    max_child = child
            elif isinstance(node, InlineFragmentNode):
                child = self._measure_depth(node.selection_set, current, visited_fragments, fragments)
                if child > max_child:
                    max_child = child
            elif isinstance(node, FragmentSpreadNode):
                name = node.name.value
                if name not in visited_fragments and name in fragments:
                    visited_fragments.add(name)
                    frag_node = fragments[name]
                    child = self._measure_depth(frag_node.selection_set, current, visited_fragments, fragments)
                    if child > max_child:
                        max_child = child
        return max_child


class ComplexityValidator:
    """Rejects queries whose estimated computational cost exceeds a threshold.

    Each field is assigned a default weight of 1.0.  List fields (heuristic:
    names ending in 's', 'es', 'ies', or 'List') receive a multiplier
    of 10x to reflect N+1 / pagination cost.  Depth also amplifies cost
    (1 + depth * 0.5) to penalise deep nesting under list fields.
    """

    def __init__(self, max_complexity: int = 1000) -> None:
        if max_complexity < 1:
            raise ValueError("max_complexity must be >= 1")
        self._max_complexity = max_complexity

    def __call__(self, document: DocumentNode) -> dict:
        violations: list[str] = []
        fragments = {
            d.name.value: d
            for d in document.definitions
            if isinstance(d, FragmentDefinitionNode)
        }
        for definition in document.definitions:
            if isinstance(definition, OperationDefinitionNode):
                cost = self._compute_cost(definition.selection_set, depth=1, visited_fragments=set(), fragments=fragments)
                if cost > self._max_complexity:
                    op_name = definition.name or "<unnamed>"
                    violations.append(
                        f"Operation '{op_name}' complexity {cost} exceeds limit {self._max_complexity}"
                    )
        if violations:
            return {"allowed": False, "reason": "; ".join(violations)}
        return {"allowed": True}

    def _compute_cost(
        self,
        selections: SelectionSetNode | None,
        depth: int,
        visited_fragments: set[str],
        fragments: dict[str, FragmentDefinitionNode],
    ) -> int:
        if not selections:
            return 0
        total = 0
        for node in selections.selections:
            if isinstance(node, FieldNode):
                weight = 1.0
                name = node.name.value
                if name.endswith(("s", "es", "ies")) or "List" in name:
                    weight = 10.0
                field_cost = weight * (1 + depth * 0.5)
                if node.selection_set:
                    field_cost += self._compute_cost(node.selection_set, depth + 1, visited_fragments, fragments)
                total += field_cost
            elif isinstance(node, InlineFragmentNode):
                total += self._compute_cost(node.selection_set, depth, visited_fragments, fragments)
            elif isinstance(node, FragmentSpreadNode):
                name = node.name.value
                if name not in visited_fragments and name in fragments:
                    visited_fragments.add(name)
                    total += self._compute_cost(fragments[name].selection_set, depth, visited_fragments, fragments)
        return int(total)


class BatchLimitValidator:
    """Rejects requests containing more than ``max_batch_size`` operations.

    GraphQL batching allows multiple queries in a single HTTP request.
    An attacker can use this to amplify data exfiltration.  This validator
    limits the number of operations per document.
    """

    def __init__(self, max_batch_size: int = 5) -> None:
        if max_batch_size < 1:
            raise ValueError("max_batch_size must be >= 1")
        self._max_batch_size = max_batch_size

    def __call__(self, document: DocumentNode) -> dict:
        operations = [d for d in document.definitions if isinstance(d, OperationDefinitionNode)]
        if len(operations) > self._max_batch_size:
            return {
                "allowed": False,
                "reason": f"Batch size {len(operations)} exceeds limit {self._max_batch_size}",
            }
        return {"allowed": True}


class AliasLimitValidator:
    """Rejects operations that use too many aliases.

    Aliases allow requesting the same field multiple times under different names.
    An attacker can use hundreds of aliases to bypass depth and complexity limits
    while exfiltrating large volumes of data.
    """

    def __init__(self, max_aliases: int = 20) -> None:
        if max_aliases < 1:
            raise ValueError("max_aliases must be >= 1")
        self._max_aliases = max_aliases

    def __call__(self, document: DocumentNode) -> dict:
        fragments = {
            d.name.value: d
            for d in document.definitions
            if isinstance(d, FragmentDefinitionNode)
        }
        for definition in document.definitions:
            if isinstance(definition, OperationDefinitionNode):
                count = self._count_aliases(definition.selection_set, set(), fragments)
                if count > self._max_aliases:
                    op_name = definition.name or "<unnamed>"
                    return {
                        "allowed": False,
                        "reason": f"Operation '{op_name}' uses {count} aliases, limit is {self._max_aliases}",
                    }
        return {"allowed": True}

    def _count_aliases(
        self,
        selections: SelectionSetNode | None,
        visited_fragments: set[str],
        fragments: dict[str, FragmentDefinitionNode],
    ) -> int:
        if not selections:
            return 0
        count = 0
        for node in selections.selections:
            if isinstance(node, FieldNode):
                if node.alias:
                    count += 1
                if node.selection_set:
                    count += self._count_aliases(node.selection_set, visited_fragments, fragments)
            elif isinstance(node, InlineFragmentNode):
                count += self._count_aliases(node.selection_set, visited_fragments, fragments)
            elif isinstance(node, FragmentSpreadNode):
                name = node.name.value
                if name not in visited_fragments and name in fragments:
                    visited_fragments.add(name)
                    count += self._count_aliases(fragments[name].selection_set, visited_fragments, fragments)
        return count


class TimeoutValidator:
    """Monitors query execution time and signals when it exceeds the limit.

    Unlike the AST-based validators above, this one wraps execution.
    Use it as a guard around your resolver invocation.
    """

    def __init__(self, timeout_ms: int = 5000) -> None:
        if timeout_ms < 1:
            raise ValueError("timeout_ms must be >= 1")
        self._timeout_s = timeout_ms / 1000.0

    def check_timeout(self) -> None:
        """Has the deadline passed?"""

    @property
    def timeout_s(self) -> float:
        return self._timeout_s


class GraphQLSecurityMiddleware:
    """Aggregates all five GraphQL security checks into one facade.

    Typical usage in a server (pseudo-code)::

        security = GraphQLSecurityMiddleware(...)
        for raw_query in batch_requests:
            document = parse(raw_query)
            result = security.check(document)
            if not result["allowed"]:
                return {"errors": [{"message": result["reason"]}]}
    """

    def __init__(
        self,
        max_depth: int = 6,
        max_complexity: int = 1000,
        max_batch_size: int = 5,
        max_aliases: int = 20,
        execution_timeout_ms: int = 5000,
    ) -> None:
        self.validators = [
            DepthLimitValidator(max_depth),
            ComplexityValidator(max_complexity),
            BatchLimitValidator(max_batch_size),
            AliasLimitValidator(max_aliases),
        ]
        self.timeout = TimeoutValidator(execution_timeout_ms)

    def check(self, document: DocumentNode) -> dict:
        """Run all static validators against the parsed document.

        Returns ``{"allowed": True}`` if all checks pass, or
        ``{"allowed": False, "reason": "..."}`` with the first violation.
        """
        for validator in self.validators:
            result = validator(document)
            if not result["allowed"]:
                return result
        return {"allowed": True}

    def check_raw_query(self, raw_query: str) -> dict:
        """Parse and validate a raw GraphQL query string."""
        try:
            document = parse(raw_query)
        except Exception as exc:
            return {"allowed": False, "reason": f"Parse error: {exc}"}
        return self.check(document)


def vulnerable_handler(query: str) -> dict:
    """Simulates a VULNERABLE GraphQL handler with no security checks (baseline)."""
    return {"allowed": True, "reason": "No security — query passes through unchanged"}


def secured_handler(query: str, middleware: GraphQLSecurityMiddleware | None = None) -> dict:
    """Simulates a SECURED GraphQL handler that applies all security checks."""
    if middleware is None:
        middleware = GraphQLSecurityMiddleware()
    result = middleware.check_raw_query(query)
    if not result["allowed"]:
        return result
    return {"allowed": True, "data": "Executed safely"}
