"""Defense-in-depth fix for issue #335: GraphQL depth and batching abuse.

The vulnerable pattern is accepting arbitrary GraphQL payloads without limits:
deep nested selections, alias/field explosions, introspection probes, and large
HTTP batches can turn one request into broad data extraction.

This module is framework-neutral. Call ``GraphQLRequestGuard.validate_payload``
before handing a parsed JSON body to the GraphQL executor.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


class GraphQLRequestGuardError(ValueError):
    """Raised when a GraphQL request exceeds configured safety limits."""


_NAME_RE = re.compile(r"\b[_A-Za-z][_0-9A-Za-z]*\b")
_ALIAS_RE = re.compile(r"\b[_A-Za-z][_0-9A-Za-z]*\s*:")
_STRUCTURAL_CHARS = set("{}():@[]")
_KEYWORDS = {
    "fragment",
    "mutation",
    "on",
    "query",
    "schema",
    "subscription",
}


def _strip_strings_and_comments(document: str) -> str:
    """Replace string/comment contents so braces inside them do not count."""

    out: list[str] = []
    i = 0
    length = len(document)
    in_string = False
    triple = False

    while i < length:
        char = document[i]

        if not in_string and char == "#":
            while i < length and document[i] not in "\r\n":
                out.append(" ")
                i += 1
            continue

        if not in_string and document.startswith('"""', i):
            in_string = True
            triple = True
            out.extend("   ")
            i += 3
            continue

        if not in_string and char == '"':
            in_string = True
            triple = False
            out.append(" ")
            i += 1
            continue

        if in_string:
            if triple and document.startswith('"""', i):
                in_string = False
                triple = False
                out.extend("   ")
                i += 3
                continue
            if not triple and char == "\\":
                out.extend("  ")
                i += 2
                continue
            if not triple and char == '"':
                in_string = False
                out.append(" ")
                i += 1
                continue
            out.append(" " if char not in "\r\n" else char)
            i += 1
            continue

        out.append(char)
        i += 1

    return "".join(out)


def _count_selection_names(document: str) -> int:
    """Count likely field selections without treating keywords as fields."""

    count = 0
    depth = 0
    paren_depth = 0
    cursor = 0

    for match in _NAME_RE.finditer(document):
        for char in document[cursor : match.start()]:
            if char == "{":
                depth += 1
            elif char == "}":
                depth = max(depth - 1, 0)
            elif char == "(":
                paren_depth += 1
            elif char == ")":
                paren_depth = max(paren_depth - 1, 0)
        cursor = match.end()

        name = match.group(0)
        if depth == 0 or paren_depth > 0:
            continue
        if name in _KEYWORDS or name.startswith("__"):
            continue

        prefix = document[: match.start()].rstrip()
        suffix = document[match.end() :].lstrip()

        if prefix.endswith("$"):
            continue
        if suffix.startswith(":"):
            continue
        count += 1

    return count


def max_selection_depth(document: str) -> int:
    """Return the deepest nested GraphQL selection-set depth."""

    stripped = _strip_strings_and_comments(document)
    depth = 0
    max_depth = 0
    for char in stripped:
        if char == "{":
            depth += 1
            max_depth = max(max_depth, depth)
        elif char == "}":
            depth -= 1
            if depth < 0:
                raise GraphQLRequestGuardError("Unbalanced GraphQL selection braces")

    if depth != 0:
        raise GraphQLRequestGuardError("Unbalanced GraphQL selection braces")
    if max_depth == 0:
        raise GraphQLRequestGuardError("GraphQL document has no selection set")
    return max_depth


@dataclass(frozen=True)
class GraphQLDocumentMetrics:
    """Measured request characteristics used by the guard."""

    depth: int
    fields: int
    aliases: int
    bytes: int
    complexity: int
    has_introspection: bool


def analyze_document(document: str) -> GraphQLDocumentMetrics:
    """Measure a GraphQL document after neutralizing strings and comments."""

    if not isinstance(document, str) or not document.strip():
        raise GraphQLRequestGuardError("Missing GraphQL query")

    stripped = _strip_strings_and_comments(document)
    aliases = len(_ALIAS_RE.findall(stripped))
    fields = _count_selection_names(stripped)
    depth = max_selection_depth(stripped)
    has_introspection = bool(re.search(r"\b__(?:schema|type)\b", stripped))

    return GraphQLDocumentMetrics(
        depth=depth,
        fields=fields,
        aliases=aliases,
        bytes=len(document.encode("utf-8")),
        complexity=fields + (aliases * 2) + (depth * 5),
        has_introspection=has_introspection,
    )


@dataclass(frozen=True)
class GraphQLRequestGuard:
    """Configurable pre-execution limits for GraphQL HTTP requests."""

    max_depth: int = 8
    max_fields: int = 80
    max_aliases: int = 15
    max_complexity: int = 150
    max_batch_size: int = 3
    max_operation_bytes: int = 32_768
    allow_introspection: bool = False

    def validate_document(self, document: str) -> GraphQLDocumentMetrics:
        metrics = analyze_document(document)

        if metrics.bytes > self.max_operation_bytes:
            raise GraphQLRequestGuardError("GraphQL operation is too large")
        if metrics.depth > self.max_depth:
            raise GraphQLRequestGuardError("GraphQL depth limit exceeded")
        if metrics.fields > self.max_fields:
            raise GraphQLRequestGuardError("GraphQL field count limit exceeded")
        if metrics.aliases > self.max_aliases:
            raise GraphQLRequestGuardError("GraphQL alias limit exceeded")
        if metrics.complexity > self.max_complexity:
            raise GraphQLRequestGuardError("GraphQL complexity limit exceeded")
        if metrics.has_introspection and not self.allow_introspection:
            raise GraphQLRequestGuardError("GraphQL introspection is disabled")

        return metrics

    def validate_payload(self, payload: Any) -> list[GraphQLDocumentMetrics]:
        """Validate a parsed JSON GraphQL HTTP body.

        ``payload`` may be a single request object or a list of request objects.
        Batching is allowed only within ``max_batch_size``.
        """

        requests = payload if isinstance(payload, list) else [payload]
        if not requests:
            raise GraphQLRequestGuardError("Empty GraphQL batch")
        if len(requests) > self.max_batch_size:
            raise GraphQLRequestGuardError("GraphQL batch size limit exceeded")

        metrics: list[GraphQLDocumentMetrics] = []
        for request in requests:
            if not isinstance(request, dict):
                raise GraphQLRequestGuardError("GraphQL request must be an object")
            query = request.get("query")
            metrics.append(self.validate_document(query))

        return metrics


__all__ = [
    "GraphQLDocumentMetrics",
    "GraphQLRequestGuard",
    "GraphQLRequestGuardError",
    "analyze_document",
    "max_selection_depth",
]
