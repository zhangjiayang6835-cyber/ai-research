"""Tests for issue #335 GraphQL depth and batching hardening."""

from __future__ import annotations

import unittest

from fixes.graphql_depth_batching_fix import (
    GraphQLRequestGuard,
    GraphQLRequestGuardError,
    analyze_document,
    max_selection_depth,
)


class GraphQLDepthBatchingFixTests(unittest.TestCase):
    def test_allows_simple_query_under_limits(self) -> None:
        guard = GraphQLRequestGuard(max_depth=3, max_fields=8, max_complexity=40)

        metrics = guard.validate_payload(
            {"query": "query { viewer { id name } }"},
        )

        self.assertEqual(len(metrics), 1)
        self.assertEqual(metrics[0].depth, 2)
        self.assertGreaterEqual(metrics[0].fields, 3)

    def test_rejects_deeply_nested_selection(self) -> None:
        guard = GraphQLRequestGuard(max_depth=3)

        with self.assertRaises(GraphQLRequestGuardError):
            guard.validate_payload(
                {"query": "query { a { b { c { d { id } } } } }"},
            )

    def test_rejects_large_http_batch(self) -> None:
        guard = GraphQLRequestGuard(max_batch_size=2)
        payload = [
            {"query": "query { viewer { id } }"},
            {"query": "query { me { id } }"},
            {"query": "query { account { id } }"},
        ]

        with self.assertRaises(GraphQLRequestGuardError):
            guard.validate_payload(payload)

    def test_rejects_field_explosion(self) -> None:
        guard = GraphQLRequestGuard(max_fields=4)
        fields = " ".join(f"field{i}" for i in range(8))

        with self.assertRaises(GraphQLRequestGuardError):
            guard.validate_payload({"query": f"query {{ viewer {{ {fields} }} }}"})

    def test_rejects_alias_explosion(self) -> None:
        guard = GraphQLRequestGuard(max_aliases=2, max_complexity=100)
        aliases = " ".join(f"a{i}: user(id: {i}) {{ id }}" for i in range(4))

        with self.assertRaises(GraphQLRequestGuardError):
            guard.validate_payload({"query": f"query {{ {aliases} }}"})

    def test_rejects_introspection_by_default(self) -> None:
        guard = GraphQLRequestGuard()

        with self.assertRaises(GraphQLRequestGuardError):
            guard.validate_payload({"query": "query { __schema { types { name } } }"})

    def test_allows_introspection_when_enabled(self) -> None:
        guard = GraphQLRequestGuard(allow_introspection=True)

        metrics = guard.validate_payload(
            {"query": "query { __schema { types { name } } }"},
        )

        self.assertTrue(metrics[0].has_introspection)

    def test_string_literals_do_not_affect_depth(self) -> None:
        query = 'query { search(text: "{ not a selection }") { id } }'

        self.assertEqual(max_selection_depth(query), 2)

    def test_rejects_non_object_batch_item(self) -> None:
        guard = GraphQLRequestGuard()

        with self.assertRaises(GraphQLRequestGuardError):
            guard.validate_payload([{"query": "query { viewer { id } }"}, "bad"])

    def test_analyze_document_returns_complexity_inputs(self) -> None:
        metrics = analyze_document(
            "query { first: viewer { id } second: viewer { name } }",
        )

        self.assertEqual(metrics.depth, 2)
        self.assertEqual(metrics.aliases, 2)
        self.assertGreater(metrics.complexity, metrics.fields)


if __name__ == "__main__":
    unittest.main()
