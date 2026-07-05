import sqlite3
import unittest

from fixes.second_order_sql_injection_fix import (
    StoredSqlValueError,
    build_safe_procedure_call,
    create_schema,
    fetch_orders_for_saved_report,
    save_report_filter,
    validate_identifier,
)


class TestSecondOrderSqlInjectionFix(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        create_schema(self.conn)
        self.conn.executemany(
            "INSERT INTO orders (id, owner_id, status, total) VALUES (?, ?, ?, ?)",
            [
                (1, "alice", "paid", 100),
                (2, "alice", "pending", 50),
                (3, "bob", "paid", 999),
            ],
        )

    def tearDown(self):
        self.conn.close()

    def test_saved_filter_is_reused_as_literal_parameter(self):
        save_report_filter(
            self.conn,
            report_id="rce-report",
            owner_id="alice",
            status_filter="paid' OR 1=1 --",
        )

        self.assertEqual(
            fetch_orders_for_saved_report(
                self.conn,
                report_id="rce-report",
                owner_id="alice",
            ),
            [],
        )

    def test_benign_saved_filter_returns_only_matching_owner_rows(self):
        save_report_filter(
            self.conn,
            report_id="paid-orders",
            owner_id="alice",
            status_filter="paid",
        )

        self.assertEqual(
            fetch_orders_for_saved_report(
                self.conn,
                report_id="paid-orders",
                owner_id="alice",
            ),
            [(1, "paid", 100)],
        )

    def test_report_lookup_is_owner_scoped(self):
        save_report_filter(
            self.conn,
            report_id="paid-orders",
            owner_id="bob",
            status_filter="paid",
        )

        self.assertEqual(
            fetch_orders_for_saved_report(
                self.conn,
                report_id="paid-orders",
                owner_id="alice",
            ),
            [],
        )

    def test_build_safe_procedure_call_binds_malicious_argument(self):
        sql, params = build_safe_procedure_call(
            "refresh_customer_report",
            ["paid' OR 1=1 --", "alice"],
        )

        self.assertEqual(sql, "CALL refresh_customer_report(?, ?)")
        self.assertEqual(params, ("paid' OR 1=1 --", "alice"))

    def test_rejects_injected_procedure_name(self):
        with self.assertRaises(StoredSqlValueError):
            build_safe_procedure_call("refresh_report; DROP TABLE orders; --", [])

    def test_validate_identifier_allows_simple_trusted_names(self):
        self.assertEqual(validate_identifier("refresh_report_2026"), "refresh_report_2026")

    def test_rejects_non_scalar_values(self):
        with self.assertRaises(StoredSqlValueError):
            build_safe_procedure_call("refresh_report", [{"$ne": None}])

    def test_rejects_overlong_stored_string(self):
        with self.assertRaises(StoredSqlValueError):
            save_report_filter(
                self.conn,
                report_id="large",
                owner_id="alice",
                status_filter="x" * 300,
            )


if __name__ == "__main__":
    unittest.main()
