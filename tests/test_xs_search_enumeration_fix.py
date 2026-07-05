from __future__ import annotations

import unittest

from fixes.xs_search_enumeration_fix import (
    SAFE_EMPTY_BODY,
    TRUSTED_ORIGIN,
    RequestContext,
    SearchDocument,
    safe_private_search,
    vulnerable_private_search_count,
)


class XSSearchEnumerationFixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.documents = [
            SearchDocument("victim", "Payroll memo", "confidential raise discussion"),
            SearchDocument("victim", "Travel", "Paris itinerary"),
            SearchDocument("other", "Payroll memo", "other tenant data"),
        ]
        self.same_site = RequestContext(
            user_id="victim",
            origin=TRUSTED_ORIGIN,
            sec_fetch_site="same-origin",
            has_session_cookie=True,
            csrf_token_valid=True,
        )

    def test_authorized_same_site_search_returns_private_matches(self) -> None:
        response = safe_private_search("payroll", self.same_site, self.documents)

        self.assertEqual(response.status, 200)
        self.assertEqual(len(response.results), 1)
        self.assertIn("Payroll memo", response.body)
        self.assertNotIn("other tenant", response.body)

    def test_cross_site_probe_gets_constant_empty_response_for_matching_query(self) -> None:
        cross_site = RequestContext("victim", "https://attacker.example", "cross-site", True, True)

        response = safe_private_search("payroll", cross_site, self.documents)

        self.assertEqual(response.status, 200)
        self.assertEqual(response.body, SAFE_EMPTY_BODY)
        self.assertEqual(response.results, ())

    def test_cross_site_responses_are_identical_for_hit_and_miss(self) -> None:
        cross_site = RequestContext("victim", "https://attacker.example", "cross-site", True, True)

        hit = safe_private_search("payroll", cross_site, self.documents)
        miss = safe_private_search("definitely-not-present", cross_site, self.documents)

        self.assertEqual(hit.status, miss.status)
        self.assertEqual(hit.body, miss.body)
        self.assertEqual(dict(hit.headers), dict(miss.headers))

    def test_missing_session_or_csrf_token_is_opaque(self) -> None:
        for context in (
            RequestContext("victim", TRUSTED_ORIGIN, "same-origin", False, True),
            RequestContext("victim", TRUSTED_ORIGIN, "same-origin", True, False),
            RequestContext(None, TRUSTED_ORIGIN, "same-origin", True, True),
        ):
            with self.subTest(context=context):
                response = safe_private_search("payroll", context, self.documents)
                self.assertEqual(response.body, SAFE_EMPTY_BODY)

    def test_fetch_metadata_blocks_cross_site_even_with_cookie(self) -> None:
        context = RequestContext("victim", TRUSTED_ORIGIN, "cross-site", True, True)

        response = safe_private_search("payroll", context, self.documents)

        self.assertEqual(response.body, SAFE_EMPTY_BODY)

    def test_safe_headers_disable_cache_and_cross_origin_reads(self) -> None:
        response = safe_private_search("payroll", self.same_site, self.documents)

        self.assertEqual(response.headers["Cache-Control"], "no-store, private")
        self.assertEqual(response.headers["Cross-Origin-Resource-Policy"], "same-origin")
        self.assertIn("Origin", response.headers["Vary"])
        self.assertIn("Sec-Fetch-Site", response.headers["Vary"])

    def test_vulnerable_count_leaks_private_data_existence(self) -> None:
        hit = vulnerable_private_search_count("payroll", self.same_site, self.documents)
        miss = vulnerable_private_search_count("definitely-not-present", self.same_site, self.documents)

        self.assertEqual(hit, 1)
        self.assertEqual(miss, 0)

    def test_query_is_normalized_and_limited(self) -> None:
        response = safe_private_search("  PAYROLL\nmemo  " + "x" * 300, self.same_site, self.documents)

        self.assertEqual(response.status, 200)
        self.assertEqual(response.results, ())


if __name__ == "__main__":
    unittest.main()
