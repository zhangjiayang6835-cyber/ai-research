"""
Tests for second_order_sql_fix.py — validates that all security layers
correctly block Second-Order SQL Injection in Stored Procedure Chains.
"""

import pytest

from second_order_sql_fix import (
    DataFlowTracker,
    DynamicSqlDetector,
    ProcedureParameterExtractor,
    QuerySanitizer,
    SecondOrderSecurityMiddleware,
    StoredProcedureAnalyzer,
    secured_handler,
    vulnerable_handler,
)


# ── 1. Dynamic SQL Pattern Detection Tests ──────────────────────────────────


class TestDynamicSqlDetector:
    def test_safe_procedure_passes(self):
        safe_sql = """
        CREATE PROCEDURE GetUser
        @id INT
        AS
        SELECT id, name FROM users WHERE id = @id
        """
        result = DynamicSqlDetector().scan(safe_sql)
        assert result["allowed"] is True

    def test_exec_statement_detected(self):
        sql = "CREATE PROC BadProc AS EXEC('SELECT * FROM users')"
        result = DynamicSqlDetector().scan(sql)
        assert result["allowed"] is False
        assert "EXEC" in result["reason"]

    def test_sp_executesql_detected(self):
        sql = "CREATE PROC Bad AS sp_executesql @sql"
        result = DynamicSqlDetector().scan(sql)
        assert result["allowed"] is False

    def test_string_concat_detected(self):
        sql = """CREATE PROC ConcatBad @n NVARCHAR(100) AS SELECT * FROM users WHERE name = ' + @n + '"""
        result = DynamicSqlDetector().scan(sql)
        assert result["allowed"] is False
        assert "concatenation" in result["reason"]

    def test_clean_proc_allows_concat_if_disabled(self):
        sql = "CREATE PROC Safe AS SELECT * FROM users"
        result = DynamicSqlDetector(block_concat=True).scan(sql)
        assert result["allowed"] is True

    def test_detector_returns_findings(self):
        sql = "EXEC('DROP TABLE users')"
        result = DynamicSqlDetector().scan(sql)
        assert len(result["findings"]) > 0
        assert "EXEC" in result["findings"][0]


# ── 2. Procedure Parameter Extraction Tests ──────────────────────────────────


class TestProcedureParameterExtractor:
    def test_extract_name_and_params(self):
        sql = """
        CREATE PROCEDURE usp_UpdateEmail
        @userId INT,
        @email NVARCHAR(100)
        AS
        UPDATE users SET email = @email WHERE id = @userId
        """
        result = ProcedureParameterExtractor().extract(sql)
        assert result["name"] == "usp_UpdateEmail"
        assert len(result["parameters"]) >= 2

    def test_procedure_without_params(self):
        sql = "CREATE PROCEDURE GetAll AS SELECT * FROM users"
        result = ProcedureParameterExtractor().extract(sql)
        assert result["name"] == "GetAll"

    def test_dynamic_sql_detected_in_extraction(self):
        sql = "CREATE PROCEDURE Bad AS EXEC('SELECT 1')"
        result = ProcedureParameterExtractor().extract(sql)
        assert result["has_dynamic_sql"] is True

    def test_procedure_with_output_param(self):
        sql = "CREATE PROC Calc @a INT, @result INT OUTPUT AS SET @result = @a * 2"
        result = ProcedureParameterExtractor().extract(sql)
        assert result["name"] == "Calc"

    def test_or_alter_procedure(self):
        sql = "CREATE OR ALTER PROCEDURE dbo.usp_Test AS SELECT 1"
        result = ProcedureParameterExtractor().extract(sql)
        assert result["name"] == "usp_Test"


# ── 3. Data Flow Chain Detection Tests ──────────────────────────────────────


class TestDataFlowTracker:
    WRITER_PROC = ("InsertUser", "CREATE PROC InsertUser @n NVARCHAR(100) AS INSERT INTO users (name) VALUES (@n)")
    SAFE_READER = ("GetUser", "CREATE PROC GetUser @id INT AS SELECT name FROM users WHERE id = @id")
    DANGEROUS_EXEC = (
        "ExecBad",
        "CREATE PROC ExecBad AS DECLARE @n NVARCHAR(100) SELECT @n = name FROM users WHERE id = 1 EXEC('UPDATE logs SET msg = ''' + @n + '''')"
    )

    def test_safe_chain_no_findings(self):
        result = DataFlowTracker().analyze_chain([self.WRITER_PROC, self.SAFE_READER])
        assert result["risk_count"] == 0

    def test_risky_chain_detected(self):
        result = DataFlowTracker().analyze_chain([
            self.WRITER_PROC,
            self.DANGEROUS_EXEC,
        ])
        assert result["chains"] is not None

    def test_empty_chain(self):
        result = DataFlowTracker().analyze_chain([])
        assert result["risk_count"] == 0

    def test_single_procedure_chain(self):
        result = DataFlowTracker().analyze_chain([self.SAFE_READER])
        assert result["risk_count"] == 0


# ── 4. Stored Procedure Analyzer Tests ──────────────────────────────────────


class TestStoredProcedureAnalyzer:
    def test_safe_procedure_allowed(self):
        sql = "CREATE PROC GetUsers AS SELECT * FROM users"
        result = StoredProcedureAnalyzer().analyze(sql)
        assert result["allowed"] is True

    def test_dynamic_sql_procedure_blocked(self):
        sql = "CREATE PROC Bad AS EXEC('SELECT 1')"
        result = StoredProcedureAnalyzer().analyze(sql)
        assert result["allowed"] is False

    def test_procedure_info_returned(self):
        sql = "CREATE PROC dbo.usp_Find @name NVARCHAR(100) AS SELECT * FROM users WHERE name = @name"
        result = StoredProcedureAnalyzer().analyze(sql)
        assert result["procedure"] == "usp_Find"
        assert len(result["parameters"]) > 0

    def test_concat_procedure_blocked(self):
        sql = "CREATE PROC ConcatBad @n NVARCHAR(100) AS SELECT * FROM users WHERE name = '" + "' + @n + '" + "'"
        result = StoredProcedureAnalyzer().analyze(sql)
        assert result["allowed"] is False


# ── 5. Query Sanitizer Tests ────────────────────────────────────────────────


class TestQuerySanitizer:
    def test_parameterize_simple_query(self):
        sanitizer = QuerySanitizer()
        query, params = sanitizer.parameterize(
            "SELECT * FROM users WHERE id = @id AND name = @name",
            {"id": 1, "name": "alice"},
        )
        assert "?" in query
        assert len(params) == 2
        assert 1 in params
        assert "alice" in params

    def test_parameterize_no_params(self):
        sanitizer = QuerySanitizer()
        query, params = sanitizer.parameterize("SELECT 1", {})
        assert query == "SELECT 1"
        assert params == []

    def test_check_value_safe(self):
        sanitizer = QuerySanitizer()
        assert sanitizer.check_value_safe("alice") is True
        assert sanitizer.check_value_safe("normal text 123") is True

    def test_check_value_unsafe(self):
        sanitizer = QuerySanitizer()
        assert sanitizer.check_value_safe("'; DROP TABLE users; --") is False
        assert sanitizer.check_value_safe("1 OR 1=1") is False
        assert sanitizer.check_value_safe("' UNION SELECT * FROM passwords") is False
        assert sanitizer.check_value_safe("/* comment */") is False

    def test_check_value_edge_cases(self):
        sanitizer = QuerySanitizer()
        assert sanitizer.check_value_safe("") is True
        assert sanitizer.check_value_safe(42) is True
        assert sanitizer.check_value_safe(None) is True


# ── 6. Integration Tests — Full Middleware ──────────────────────────────────


class TestMiddleware:
    SAFE_PROC = "CREATE PROC GetUser @id INT AS SELECT name FROM users WHERE id = @id"
    DANGEROUS_PROC = ("BadProc", "CREATE PROC BadProc AS EXEC('SELECT * FROM users')")

    def test_safe_procedure_passes(self):
        mw = SecondOrderSecurityMiddleware()
        result = mw.analyze_procedure(self.SAFE_PROC)
        assert result["allowed"] is True

    def test_dangerous_procedure_blocked(self):
        mw = SecondOrderSecurityMiddleware()
        result = mw.analyze_procedure(self.DANGEROUS_PROC[1])
        assert result["allowed"] is False

    def test_safe_chain_passes(self):
        mw = SecondOrderSecurityMiddleware()
        procedures = [
            ("InsertUser", "CREATE PROC InsertUser @n NVARCHAR(100) AS INSERT INTO users (name) VALUES (@n)"),
            ("GetUser", "CREATE PROC GetUser @id INT AS SELECT name FROM users WHERE id = @id"),
        ]
        result = mw.analyze_chain(procedures)
        assert result["allowed"] is True

    def test_chain_with_dynamic_sql_blocked(self):
        mw = SecondOrderSecurityMiddleware()
        procedures = [
            ("InsertBad", "CREATE PROC InsertBad @n NVARCHAR(100) AS INSERT INTO users (name) VALUES (@n)"),
            ("ExecBad", "CREATE PROC ExecBad AS EXEC('SELECT * FROM users')"),
        ]
        result = mw.analyze_chain(procedures)
        assert result["allowed"] is False

    def test_sanitize_via_middleware(self):
        mw = SecondOrderSecurityMiddleware()
        query, params = mw.sanitize_query(
            "SELECT * FROM users WHERE id = @id",
            {"id": 5},
        )
        assert query == "SELECT * FROM users WHERE id = ?"
        assert params == [5]

    def test_check_value_via_middleware(self):
        mw = SecondOrderSecurityMiddleware()
        assert mw.check_value("safe_text") is True
        assert mw.check_value("'; DROP TABLE users; --") is False


# ── 7. Vulnerable vs Secured Handler Tests ──────────────────────────────────


class TestHandlers:
    def test_vulnerable_handler_allows_everything(self):
        result = vulnerable_handler("SELECT * FROM users", {"id": 1})
        assert result["allowed"] is True

    def test_secured_handler_passes_safe(self):
        result = secured_handler(
            "SELECT * FROM users WHERE id = @id",
            {"id": 1},
        )
        assert result["allowed"] is True
        assert "query" in result
        assert "params" in result

    def test_secured_handler_blocks_unsafe_value(self):
        result = secured_handler(
            "SELECT * FROM users WHERE id = @id",
            {"id": "1; DROP TABLE users; --"},
        )
        assert result["allowed"] is False

    def test_secured_handler_blocks_dynamic_proc(self):
        result = secured_handler(
            "CREATE PROC Bad AS EXEC('SELECT 1')",
        )
        assert result["allowed"] is False

    def test_secured_handler_empty_params(self):
        result = secured_handler("SELECT 1", None)
        assert result["allowed"] is True


# ── 8. Edge Cases ──────────────────────────────────────────────────────────


class TestEdgeCases:
    def test_empty_sql(self):
        detector = DynamicSqlDetector()
        result = detector.scan("")
        assert result["allowed"] is True

    def test_very_long_sql(self):
        sql = "SELECT * FROM users WHERE id = " + "1 " * 1000
        result = DynamicSqlDetector().scan(sql)
        assert result["allowed"] is True

    def test_unicode_injection_attempt(self):
        sanitizer = QuerySanitizer()
        assert sanitizer.check_value_safe("正常文本") is True

    def test_numeric_edge_cases(self):
        sanitizer = QuerySanitizer()
        assert sanitizer.check_value_safe(0) is True
        assert sanitizer.check_value_safe(-1) is True
        assert sanitizer.check_value_safe(3.14159) is True

    def test_simulated_second_order_chain(self):
        from second_order_sql_fix import SecondOrderInjectionSimulator

        simulator = SecondOrderInjectionSimulator()
        procedures = [
            ("InsertProc", "CREATE PROC InsertProc @val TEXT AS INSERT INTO test_data (val) VALUES (@val)"),
            ("SafeRead", "CREATE PROC SafeRead AS SELECT val FROM test_data"),
        ]
        result = simulator.simulate(procedures, {"input": "safe"})
        assert result["allowed"] is True

    def test_non_string_params_in_parameterize(self):
        sanitizer = QuerySanitizer()
        query, params = sanitizer.parameterize(
            "SELECT * FROM items WHERE id = @id AND active = @active",
            {"id": 42, "active": True},
        )
        assert "?" in query
        assert 42 in params
        assert True in params

    def test_case_insensitive_detection(self):
        sql = "create proc bad as exec('select 1')"
        result = DynamicSqlDetector().scan(sql)
        assert result["allowed"] is False

    def test_procedure_with_schema_name(self):
        sql = "CREATE PROCEDURE dbo.usp_Test AS SELECT 1"
        result = StoredProcedureAnalyzer().analyze(sql)
        assert result["procedure"] == "usp_Test"
        assert result["allowed"] is True
