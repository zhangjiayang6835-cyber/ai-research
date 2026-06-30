"""
Tests for graphql_security.py — validates that all five security
layers correctly block Depth Bypass + Batching attacks.
"""

import json
import time

import pytest
from graphql import parse, print_ast

from graphql_security import (
    AliasLimitValidator,
    BatchLimitValidator,
    ComplexityValidator,
    DepthLimitValidator,
    GraphQLSecurityMiddleware,
    TimeoutValidator,
    secured_handler,
    vulnerable_handler,
)

# ---------------------------------------------------------------------------
# 1. Depth Limit Tests
# ---------------------------------------------------------------------------


class TestDepthLimit:
    SHALLOW = """
    {
        viewer {
            name
            email
        }
    }
    """

    DEEP = """
    {
        user {
            friends {
                posts {
                    comments {
                        author {
                            profile {
                                address
                            }
                        }
                    }
                }
            }
        }
    }
    """

    FRAGMENT_BYPASS = """
    fragment deep on User {
        posts {
            comments {
                author {
                    profile {
                        address
                        friends {
                            name
                        }
                    }
                }
            }
        }
    }
    query {
        user {
            ...deep
        }
    }
    """

    def test_shallow_query_allowed(self):
        doc = parse(self.SHALLOW)
        result = DepthLimitValidator(max_depth=5)(doc)
        assert result["allowed"] is True

    def test_deep_query_rejected(self):
        doc = parse(self.DEEP)
        result = DepthLimitValidator(max_depth=5)(doc)
        assert result["allowed"] is False
        assert "depth" in result["reason"]

    def test_fragment_bypass_blocked(self):
        doc = parse(self.FRAGMENT_BYPASS)
        result = DepthLimitValidator(max_depth=5)(doc)
        assert result["allowed"] is False

    def test_custom_depth_limit(self):
        doc = parse(self.DEEP)
        result = DepthLimitValidator(max_depth=10)(doc)
        assert result["allowed"] is True

    def test_invalid_max_depth(self):
        with pytest.raises(ValueError):
            DepthLimitValidator(max_depth=0)

    def test_unnamed_operation(self):
        doc = parse(self.DEEP)
        result = DepthLimitValidator(max_depth=2)(doc)
        assert result["allowed"] is False
        assert "<unnamed>" in result["reason"]


# ---------------------------------------------------------------------------
# 2. Complexity / Cost Analysis Tests
# ---------------------------------------------------------------------------


class TestComplexity:
    SIMPLE = """
    {
        user(id: 1) {
            name
            email
        }
    }
    """

    EXPENSIVE = """
    {
        users {
            name
            email
            posts {
                title
                comments {
                    body
                    author {
                        name
                    }
                }
            }
        }
    }
    """

    def test_simple_query_allowed(self):
        doc = parse(self.SIMPLE)
        result = ComplexityValidator(max_complexity=100)(doc)
        assert result["allowed"] is True

    def test_expensive_query_rejected(self):
        doc = parse(self.EXPENSIVE)
        result = ComplexityValidator(max_complexity=10)(doc)
        assert result["allowed"] is False
        assert "complexity" in result["reason"]

    def test_custom_threshold(self):
        doc = parse(self.EXPENSIVE)
        result = ComplexityValidator(max_complexity=5000)(doc)
        assert result["allowed"] is True

    def test_invalid_max_complexity(self):
        with pytest.raises(ValueError):
            ComplexityValidator(max_complexity=0)

    def test_named_list_fields_amplify_cost(self):
        names_query = """
        {
            users {
                name
                friends {
                    name
                }
            }
        }
        """
        doc = parse(names_query)
        strict = ComplexityValidator(max_complexity=15)(doc)
        relaxed = ComplexityValidator(max_complexity=50)(doc)
        assert strict["allowed"] is False
        assert relaxed["allowed"] is True


# ---------------------------------------------------------------------------
# 3. Batch Limit Tests
# ---------------------------------------------------------------------------


class TestBatchLimit:
    SINGLE = "query Q1 { user { name } }"
    BATCH_OF_3 = """
    query A { user { name } }
    query B { posts { title } }
    query C { comments { body } }
    """
    BATCH_OF_10 = "\n".join(f"query Q{i} {{ {'user' if i % 2 == 0 else 'post'} {{ name }} }}" for i in range(10))

    def test_single_allowed(self):
        doc = parse(self.SINGLE)
        result = BatchLimitValidator(max_batch_size=5)(doc)
        assert result["allowed"] is True

    def test_moderate_batch_allowed(self):
        doc = parse(self.BATCH_OF_3)
        result = BatchLimitValidator(max_batch_size=5)(doc)
        assert result["allowed"] is True

    def test_large_batch_rejected(self):
        doc = parse(self.BATCH_OF_10)
        result = BatchLimitValidator(max_batch_size=5)(doc)
        assert result["allowed"] is False
        assert "Batch size" in result["reason"]

    def test_custom_batch_size(self):
        doc = parse(self.BATCH_OF_10)
        result = BatchLimitValidator(max_batch_size=10)(doc)
        assert result["allowed"] is True

    def test_invalid_max_batch(self):
        with pytest.raises(ValueError):
            BatchLimitValidator(max_batch_size=0)


# ---------------------------------------------------------------------------
# 4. Alias Limit Tests
# ---------------------------------------------------------------------------


class TestAliasLimit:
    NO_ALIASES = "{ user { name } }"
    MANY_ALIASES = """
    query {
        a1: user { name }
        a2: user { name }
        a3: user { name }
        a4: user { name }
        a5: user { name }
        a6: user { name }
        a7: user { name }
        a8: user { name }
    }
    """

    def test_no_aliases_allowed(self):
        doc = parse(self.NO_ALIASES)
        result = AliasLimitValidator(max_aliases=5)(doc)
        assert result["allowed"] is True

    def test_many_aliases_rejected(self):
        doc = parse(self.MANY_ALIASES)
        result = AliasLimitValidator(max_aliases=5)(doc)
        assert result["allowed"] is False
        assert "aliases" in result["reason"]

    def test_exactly_at_limit_allowed(self):
        doc = parse(self.MANY_ALIASES)
        result = AliasLimitValidator(max_aliases=8)(doc)
        assert result["allowed"] is True

    def test_invalid_max_aliases(self):
        with pytest.raises(ValueError):
            AliasLimitValidator(max_aliases=0)


# ---------------------------------------------------------------------------
# 5. Integration Tests — Full Middleware
# ---------------------------------------------------------------------------


class TestMiddleware:
    SAFE_QUERY = "{ viewer { name email } }"

    ATTACK_DEPTH = """
    {
        a1: user { friends { posts { comments { author { profile { address } } } } } }
        a2: user { friends { posts { comments { author { profile { address } } } } } }
        a3: user { friends { posts { comments { author { profile { address } } } } } }
        a4: user { friends { posts { comments { author { profile { address } } } } } }
        a5: user { friends { posts { comments { author { profile { address } } } } } }
    }
    """

    ATTACK_BATCH = "\n".join(f"query Q{i} {{ a{i}: user {{ friends {{ posts {{ title }} }} }} }}" for i in range(10))

    def test_safe_query_passes(self):
        mw = GraphQLSecurityMiddleware()
        result = mw.check_raw_query(self.SAFE_QUERY)
        assert result["allowed"] is True

    def test_depth_plus_alias_attack_blocked(self):
        mw = GraphQLSecurityMiddleware(max_depth=4, max_aliases=4)
        result = mw.check_raw_query(self.ATTACK_DEPTH)
        assert result["allowed"] is False
        assert any(word in result["reason"] for word in ["depth", "alias", "complexity"])

    def test_batch_attack_blocked(self):
        mw = GraphQLSecurityMiddleware(max_batch_size=3)
        result = mw.check_raw_query(self.ATTACK_BATCH)
        assert result["allowed"] is False
        assert "Batch size" in result["reason"]

    def test_vulnerable_handler_allows_everything(self):
        result = vulnerable_handler(self.ATTACK_DEPTH)
        assert result["allowed"] is True

    def test_secured_handler_blocks_attack(self):
        mw = GraphQLSecurityMiddleware(max_depth=4, max_aliases=4, max_complexity=100)
        result = secured_handler(self.ATTACK_DEPTH, mw)
        assert result["allowed"] is False

    def test_secured_handler_allows_safe(self):
        result = secured_handler(self.SAFE_QUERY)
        assert result["allowed"] is True

    def test_malformed_query_returns_error(self):
        mw = GraphQLSecurityMiddleware()
        result = mw.check_raw_query("{ invalid syntax !!! }")
        assert result["allowed"] is False
        assert "Parse error" in result["reason"]

    def test_fragment_spread_attack(self):
        fragment_attack = """
        fragment f on User { posts { comments { author { friends { name } } } } }
        query { user { ...f ...f ...f ...f ...f } }
        """
        mw = GraphQLSecurityMiddleware(max_depth=4)
        result = mw.check_raw_query(fragment_attack)
        assert result["allowed"] is False


# ---------------------------------------------------------------------------
# 6. Timeout Tests
# ---------------------------------------------------------------------------


class TestTimeout:
    def test_timeout_configured(self):
        tv = TimeoutValidator(timeout_ms=500)
        assert tv.timeout_s == 0.5

    def test_timeout_reasonable_default(self):
        tv = TimeoutValidator()
        assert tv.timeout_s == 5.0

    def test_invalid_timeout(self):
        with pytest.raises(ValueError):
            TimeoutValidator(timeout_ms=0)


# ---------------------------------------------------------------------------
# 7. Regression — existing functionality unaffected
# ---------------------------------------------------------------------------


class TestRegression:
    MUTATION = """
    mutation {
        createUser(input: {name: "test", email: "a@b.com"}) {
            id
            name
        }
    }
    """

    SUBSCRIPTION = """
    subscription {
        userAdded {
            id
            name
        }
    }
    """

    def test_mutations_pass(self):
        doc = parse(self.MUTATION)
        mw = GraphQLSecurityMiddleware()
        result = mw.check(doc)
        assert result["allowed"] is True

    def test_subscriptions_pass(self):
        doc = parse(self.SUBSCRIPTION)
        mw = GraphQLSecurityMiddleware()
        result = mw.check(doc)
        assert result["allowed"] is True

    def test_introspection_query_passes(self):
        doc = parse("{ __schema { types { name } } }")
        mw = GraphQLSecurityMiddleware()
        result = mw.check(doc)
        assert result["allowed"] is True
