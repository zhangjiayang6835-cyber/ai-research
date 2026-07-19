from __future__ import annotations

import unittest

from src.search import (
    _validate_regex_pattern,
    _compute_nesting_depth,
    _has_dangerous_nested_quantifiers,
    SecureSearchEngine,
    MAX_PATTERN_LENGTH,
    MAX_REGEX_NESTING_DEPTH,
)


class RegexValidationTests(unittest.TestCase):
    """Tests for ReDoS pattern validation logic."""

    # ── Safe patterns ────────────────────────────────────────────────

    def test_safe_simple_string(self) -> None:
        self.assertIsNone(_validate_regex_pattern(r"hello"))

    def test_safe_digit_pattern(self) -> None:
        self.assertIsNone(_validate_regex_pattern(r"\d+"))

    def test_safe_character_class(self) -> None:
        self.assertIsNone(_validate_regex_pattern(r"[a-z]+"))

    def test_safe_capturing_group_no_quantifier(self) -> None:
        self.assertIsNone(_validate_regex_pattern(r"(abc)"))

    def test_safe_anchored_pattern(self) -> None:
        self.assertIsNone(_validate_regex_pattern(r"^[a-zA-Z0-9]+$"))

    def test_safe_lookahead(self) -> None:
        self.assertIsNone(_validate_regex_pattern(r"(?=foo)bar"))

    def test_safe_quantified_but_not_nested(self) -> None:
        self.assertIsNone(_validate_regex_pattern(r"a+b*c?"))

    # ── Nested quantifiers ───────────────────────────────────────────

    def test_nested_quantifier_plus_plus(self) -> None:
        err = _validate_regex_pattern(r"(a+)+")
        self.assertIsNotNone(err)
        self.assertIn("quantifier", err.lower())

    def test_nested_quantifier_star_star(self) -> None:
        err = _validate_regex_pattern(r"(a*)*")
        self.assertIsNotNone(err)

    def test_nested_quantifier_plus_star(self) -> None:
        err = _validate_regex_pattern(r"(a+)*")
        self.assertIsNotNone(err)

    def test_nested_quantifier_brace_plus(self) -> None:
        err = _validate_regex_pattern(r"(a{2,3})+")
        self.assertIsNotNone(err)

    def test_nested_optional_group_plus(self) -> None:
        err = _validate_regex_pattern(r"((a)?)+")
        self.assertIsNotNone(err)

    def test_nested_character_class_quantifier(self) -> None:
        err = _validate_regex_pattern(r"([a-z]+)+")
        self.assertIsNotNone(err)

    def test_word_boundary_nested(self) -> None:
        err = _validate_regex_pattern(r"(\w+\.)+com")
        self.assertIsNotNone(err)

    # ── Alternation loops ────────────────────────────────────────────

    def test_alternation_loop_four_branches(self) -> None:
        err = _validate_regex_pattern(r"(a|b|c|d)+")
        self.assertIsNotNone(err)

    def test_alternation_loop_six_branches(self) -> None:
        err = _validate_regex_pattern(r"(a|b|c|d|e|f)+")
        self.assertIsNotNone(err)

    def test_short_alternation_not_rejected(self) -> None:
        self.assertIsNone(_validate_regex_pattern(r"(a|b)"))

    def test_three_branch_alternation_not_rejected(self) -> None:
        self.assertIsNone(_validate_regex_pattern(r"(a|b|c)"))

    # ── Nesting depth ────────────────────────────────────────────────

    def test_deep_nesting_rejected(self) -> None:
        err = _validate_regex_pattern(r"(((((a)))))")
        self.assertIsNotNone(err)
        self.assertIn("nesting", err.lower())

    def test_nesting_depth_calculation(self) -> None:
        self.assertEqual(_compute_nesting_depth(r"((((a))))"), 4)
        self.assertEqual(_compute_nesting_depth(r"(((((a)))))"), 5)
        self.assertEqual(_compute_nesting_depth(r"(a(b)c)"), 2)
        self.assertEqual(_compute_nesting_depth(r"abc"), 0)

    # ── Length limits ────────────────────────────────────────────────

    def test_empty_pattern_rejected(self) -> None:
        err = _validate_regex_pattern("")
        self.assertIsNotNone(err)
        self.assertIn("empty", err.lower())

    def test_overly_long_pattern_rejected(self) -> None:
        long_pattern = "a" * (MAX_PATTERN_LENGTH + 1)
        err = _validate_regex_pattern(long_pattern)
        self.assertIsNotNone(err)
        self.assertIn("too long", err.lower())

    def test_boundary_length_accepted(self) -> None:
        long_pattern = "a" * MAX_PATTERN_LENGTH
        self.assertIsNone(_validate_regex_pattern(long_pattern))

    # ── Danger detection helper ──────────────────────────────────────

    def test_has_dangerous_nested_quantifiers(self) -> None:
        self.assertTrue(_has_dangerous_nested_quantifiers(r"(a+)+"))
        self.assertTrue(_has_dangerous_nested_quantifiers(r"(a|b|c|d|e)+"))
        self.assertTrue(_has_dangerous_nested_quantifiers(r"((a)?)+"))
        self.assertFalse(_has_dangerous_nested_quantifiers(r"hello"))
        self.assertFalse(_has_dangerous_nested_quantifiers(r"\d+"))


class SecureSearchEngineTests(unittest.TestCase):
    """Tests for SecureSearchEngine ReDoS integration."""

    def setUp(self) -> None:
        self.engine = SecureSearchEngine()
        self.data = [
            {"title": "Hello World", "body": "This is a test document"},
            {"title": "Python Regex", "body": "Has numbers like 42 and 100"},
            {"title": "No Match", "body": "Nothing here"},
        ]

    def test_long_search_query_rejected(self) -> None:
        result = self.engine.search(
            "x" * (MAX_PATTERN_LENGTH + 1), "user1", self.data
        )
        self.assertIsNone(result)

    def test_search_accepts_normal_query(self) -> None:
        result = self.engine.search("hello", "user1", self.data)
        self.assertIsNotNone(result)
        self.assertEqual(len(result.items), 1)

    def test_search_with_regex_safe_pattern(self) -> None:
        result = self.engine.search_with_regex(r"\d+", "user1", self.data)
        self.assertIsNotNone(result)
        self.assertEqual(len(result.items), 1)
        self.assertIn("42", result.items[0]["body"])

    def test_search_with_regex_dangerous_pattern_rejected(self) -> None:
        result = self.engine.search_with_regex(r"(a+)+", "user1", self.data)
        self.assertIsNone(result)

    def test_search_with_regex_alternation_loop_rejected(self) -> None:
        result = self.engine.search_with_regex(
            r"(a|b|c|d|e|f)+", "user1", self.data
        )
        self.assertIsNone(result)

    def test_validate_regex_pattern_public_method(self) -> None:
        self.assertIsNone(self.engine.validate_regex_pattern(r"hello"))
        self.assertIsNotNone(self.engine.validate_regex_pattern(r"(a+)+"))

    def test_search_with_regex_no_match_returns_empty(self) -> None:
        result = self.engine.search_with_regex(
            r"zzz", "user1", self.data
        )
        self.assertIsNotNone(result)
        self.assertEqual(len(result.items), 0)

    def test_search_with_regex_multiple_matches(self) -> None:
        data = [
            {"text": "apple"},
            {"text": "banana"},
            {"text": "apricot"},
        ]
        result = self.engine.search_with_regex(r"^a", "user1", data)
        self.assertIsNotNone(result)
        self.assertEqual(len(result.items), 2)

    def test_rate_limit_still_applies(self) -> None:
        engine = SecureSearchEngine(max_requests_per_window=1)
        engine.search("first", "user2", self.data)  # uses the quota
        result = engine.search_with_regex(r"\d+", "user2", self.data)
        self.assertIsNone(result)  # rate limited


if __name__ == "__main__":
    unittest.main()
