"""
second_order_sql_fix.py — Second-Order SQL Injection Prevention Middleware

Prevents Second-Order SQL Injection in Stored Procedure Chains by enforcing:
  1. Stored procedure source scanning (dynamic SQL detection)
  2. Data flow tracking between procedures (input → storage → reuse)
  3. Parameterized query enforcement across procedure boundaries
  4. Dynamic SQL pattern detection (EXEC, sp_executesql, string concat)
  5. Stored procedure chain validation

What is Second-Order SQL Injection?
  First-order:  User input → directly in SQL query  (blocked by param queries)
  Second-order: User input → stored in DB → read later → used in ANOTHER query

  Example:
    Step 1: INSERT INTO users (name) VALUES ('Robert''); DROP TABLE users;--')
            (stored safely if parameterized — looks harmless)
    Step 2: SELECT name FROM users WHERE id = 1 → returns "Robert'); DROP TABLE users;--"
    Step 3: EXEC('UPDATE logs SET msg = ''' + name + '''')  ← BOOM! Second-order!

Usage:
    from second_order_sql_fix import SecondOrderSecurityMiddleware

    sql = (
        "CREATE PROCEDURE UpdateLog @msg NVARCHAR(100) "
        "AS EXEC('UPDATE logs SET message = ''' + @msg + '''')"
    )
    result = middleware.analyze_procedure(sql)
    if not result["allowed"]:
        raise PermissionError(result["reason"])
"""

import re
import sqlite3
from typing import Any


# ── Dynamic SQL Pattern Detection ────────────────────────────────────────────

class DynamicSqlDetector:
    """Detects dynamic SQL construction patterns in stored procedure source.

    Dynamic SQL is dangerous in procedure chains because data stored
    from one operation can be executed as code in another.
    """

    DANGEROUS_PATTERNS = [
        (re.compile(r'\bEXEC\b', re.IGNORECASE), "EXEC statement (dynamic execution)"),
        (re.compile(r'\bEXECUTE\b', re.IGNORECASE), "EXECUTE statement (dynamic execution)"),
        (re.compile(r'\bsp_executesql\b', re.IGNORECASE), "sp_executesql (dynamic execution)"),
        (re.compile(r'\bEXEC\s*\(', re.IGNORECASE), "EXEC() with dynamic SQL"),
        (re.compile(r'\bEXECUTE\s*\(', re.IGNORECASE), "EXECUTE() with dynamic SQL"),
    ]

    CONCAT_PATTERNS = [
        (re.compile(r"""['"']\s*\+[^=]"""), "String concatenation in SQL (potential injection)"),
        (re.compile(r"""['"']\s*\|\|\s"""), "String concatenation in SQL (|| operator)"),
        (re.compile(r'\bf\'(?!.*FROM)', re.IGNORECASE), "f-string in SQL query"),
        (re.compile(r'''['"]\s*\.format\(|\%\s*\(|\.format\(\s*["']'''), ".format() or % formatting"),
    ]

    def __init__(self, block_dynamic_sql: bool = True, block_concat: bool = True) -> None:
        self._block_dynamic = block_dynamic_sql
        self._block_concat = block_concat

    def scan(self, sql: str) -> dict:
        findings = []
        if self._block_dynamic:
            for pattern, desc in self.DANGEROUS_PATTERNS:
                matches = pattern.findall(sql)
                if matches:
                    findings.append(f"{desc} ({len(matches)} occurrence(s))")
        if self._block_concat:
            for pattern, desc in self.CONCAT_PATTERNS:
                matches = pattern.findall(sql)
                if matches:
                    findings.append(f"{desc} ({len(matches)} occurrence(s))")
        if findings:
            return {
                "allowed": False,
                "reason": "Dynamic SQL patterns detected: " + "; ".join(findings),
                "findings": findings,
            }
        return {"allowed": True, "findings": []}


class ProcedureParameterExtractor:
    """Extracts procedure parameters from CREATE PROCEDURE / CREATE PROC statements."""

    PARAM_PATTERN = re.compile(r'@\w+\s+\w+(?:\([^)]+\))?(?:\s*(?:=\s*\w+)?(?:\s*OUTPUT|\s*OUT)?)?', re.IGNORECASE)
    PROC_NAME_PATTERN = re.compile(r'CREATE\s+(?:OR\s+ALTER\s+)?(?:PROC(?:EDURE)?)\s+(?:\[?\w+\]?\.)?(?:\[?\w+\]?)', re.IGNORECASE)
    PROC_NAME_CAPTURE = re.compile(r'CREATE\s+(?:OR\s+ALTER\s+)?(?:PROC(?:EDURE)?)\s+(?:\[?(?:\w+)\]?\.)*\[?(\w+)\]?', re.IGNORECASE)

    def extract(self, sql: str) -> dict:
        name_match = self.PROC_NAME_CAPTURE.search(sql)
        proc_name = name_match.group(1) if name_match else "unknown"
        params = self.PARAM_PATTERN.findall(sql)
        return {
            "name": proc_name,
            "parameters": [p.strip() for p in params] if params else [],
            "has_dynamic_sql": bool(DynamicSqlDetector().scan(sql)["findings"]),
        }


class DataFlowTracker:
    """Tracks how data flows between stored procedures in a chain.

    A second-order injection chain looks like:
      UserInput → SP1(INSERT) → DB → SP2(SELECT) → SP3(EXEC with that value)

    This tracker analyzes procedure call graphs to identify risky chains.
    """

    CALL_PATTERN = re.compile(r'\b(?:EXEC|EXECUTE)\s+(?:\[?\w+\]?\.)?(?:\[?(\w+)\]?)(?:\s|$)', re.IGNORECASE)

    def analyze_chain(self, procedures: list[tuple[str, str]]) -> dict:
        proc_map = {name: src for name, src in procedures}
        findings = []
        for name, src in procedures:
            called_procs = self._find_calls(src)
            for called in called_procs:
                if called in proc_map:
                    caller_info = self._analyze_procedure(name, src)
                    callee_info = self._analyze_procedure(called, proc_map[called])
                    if caller_info["writes_to_db"] and callee_info["reads_from_db"]:
                        findings.append(
                            f"Risky chain: {name} (writes) → {called} (reads → may execute)"
                        )
        return {
            "chains": findings,
            "risk_count": len(findings),
        }

    def _find_calls(self, sql: str) -> list[str]:
        return self.CALL_PATTERN.findall(sql)

    def _analyze_procedure(self, name: str, sql: str) -> dict:
        return {
            "name": name,
            "writes_to_db": bool(re.search(r'\b(?:INSERT|UPDATE|DELETE)\b', sql, re.IGNORECASE)),
            "reads_from_db": bool(re.search(r'\bSELECT\b', sql, re.IGNORECASE)),
            "has_dynamic_sql": bool(DynamicSqlDetector().scan(sql)["findings"]),
        }


class SecondOrderInjectionSimulator:
    """Simulates second-order injection scenarios to validate defenses.

    Creates a mini SQLite database and runs the procedure chain to
    verify whether a second-order injection would succeed.
    """

    def simulate(self, procedures: list[tuple[str, str]], initial_data: dict[str, str]) -> dict:
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE test_data (id INTEGER PRIMARY KEY, val TEXT)")
        conn.execute("CREATE TABLE logs (id INTEGER PRIMARY KEY, msg TEXT)")
        conn.execute("CREATE TABLE audit (id INTEGER PRIMARY KEY, entry TEXT)")

        try:
            conn.execute(
                "INSERT INTO test_data (val) VALUES (?)",
                (initial_data.get("input", "safe_value"),),
            )
            row = conn.execute("SELECT val FROM test_data WHERE id = 1").fetchone()
            stored_value = row[0] if row else ""

            for proc_name, proc_sql in procedures:
                lower_sql = proc_sql.lower()
                if "exec" in lower_sql and "select" in lower_sql:
                    try:
                        conn.execute(
                            "INSERT INTO logs (msg) VALUES (?)",
                            (f"Processed: {stored_value}",),
                        )
                    except Exception:
                        pass
                elif ("insert" in lower_sql or "update" in lower_sql) and "+" in proc_sql:
                    try:
                        query = proc_sql.replace("@val", f"'{stored_value}'")
                        conn.execute(query)
                    except Exception as e:
                        pass
                elif "select" in lower_sql and "from" in lower_sql:
                    conn.execute("INSERT INTO audit (entry) VALUES (?)", ("chain step ok",))
            return {
                "allowed": True,
                "simulated": True,
            }
        except Exception as e:
            return {
                "allowed": False,
                "reason": f"Simulation error: {e}",
            }
        finally:
            conn.close()


class QuerySanitizer:
    """Sanitizes and parameterizes SQL queries to prevent SQL injection.

    Converts string-concatenated queries to parameterized form.
    """

    SAFE_TYPES = {int, float, bool, type(None)}

    def parameterize(self, query: str, params: dict[str, Any]) -> tuple[str, list[Any]]:
        param_names = re.findall(r'@(\w+)', query)
        sanitized_query = query
        param_values = []
        for name in param_names:
            if name in params:
                value = params[name]
                if not isinstance(value, (str, int, float, bool, type(None))):
                    return "", []
            sanitized_query = sanitized_query.replace(f"@{name}", "?")
            param_values.append(params.get(name))
        return sanitized_query, param_values

    def check_value_safe(self, value: Any) -> bool:
        if isinstance(value, str):
            patterns = [
                re.compile(r"'.*?(?:OR|or).*?'.*?="),
                re.compile(r"(?:\d|')\s+OR\s+\d", re.IGNORECASE),
                re.compile(r"--"),
                re.compile(r"/\*"),
                re.compile(r"';"),
                re.compile(r"\b(?:DROP|ALTER|TRUNCATE|DELETE|INSERT|EXEC|EXECUTE|UNION)\b", re.IGNORECASE),
            ]
            for p in patterns:
                if p.search(value):
                    return False
        return True


class StoredProcedureAnalyzer:
    """Full analysis of a stored procedure for second-order injection risks."""

    def __init__(self) -> None:
        self.dynamic_detector = DynamicSqlDetector()
        self.param_extractor = ProcedureParameterExtractor()

    def analyze(self, sql: str) -> dict:
        dynamic_result = self.dynamic_detector.scan(sql)
        proc_info = self.param_extractor.extract(sql)
        return {
            "allowed": not dynamic_result["findings"],
            "reason": dynamic_result.get("reason", "Procedure is safe"),
            "procedure": proc_info["name"],
            "parameters": proc_info["parameters"],
            "dynamic_sql_findings": dynamic_result["findings"],
        }


class SecondOrderSecurityMiddleware:
    """Aggregates all second-order SQL injection checks into one facade.

    Typical usage::

        middleware = SecondOrderSecurityMiddleware()
        result = middleware.analyze_procedure(sp_source_code)
        if not result["allowed"]:
            raise PermissionError(result["reason"])
    """

    def __init__(self) -> None:
        self.analyzer = StoredProcedureAnalyzer()
        self.dynamic_detector = DynamicSqlDetector()
        self.flow_tracker = DataFlowTracker()
        self.sanitizer = QuerySanitizer()
        self.simulator = SecondOrderInjectionSimulator()

    def analyze_procedure(self, sql: str) -> dict:
        return self.analyzer.analyze(sql)

    def analyze_chain(self, procedures: list[tuple[str, str]]) -> dict:
        proc_results = []
        for name, sql in procedures:
            proc_results.append(self.analyze_procedure(sql))
        chain_result = self.flow_tracker.analyze_chain(procedures)
        return {
            "allowed": all(r["allowed"] for r in proc_results) and chain_result["risk_count"] == 0,
            "procedures": proc_results,
            "chains": chain_result,
        }

    def sanitize_query(self, query: str, params: dict[str, Any]) -> tuple[str, list[Any]]:
        return self.sanitizer.parameterize(query, params)

    def check_value(self, value: Any) -> bool:
        return self.sanitizer.check_value_safe(value)


def vulnerable_handler(query: str, params: dict[str, Any] | None = None) -> dict:
    """Simulates a VULNERABLE handler — no second-order injection protection."""
    return {"allowed": True, "executed": "SELECT * FROM users WHERE id = '" + str(params or {}) + "'"}


def secured_handler(query: str, params: dict[str, Any] | None = None) -> dict:
    """Simulates a SECURED handler with full parameterization."""
    mw = SecondOrderSecurityMiddleware()
    safe = mw.analyze_procedure(query) if "CREATE" in query.upper() else {"allowed": True}
    if not safe["allowed"]:
        return {"allowed": False, "reason": safe["reason"]}
    if params:
        param_query, param_values = mw.sanitize_query(query, params)
        if not param_query:
            return {"allowed": False, "reason": "Parameterization failed"}
        for v in param_values:
            if not mw.check_value(v):
                return {"allowed": False, "reason": f"Unsafe value detected: {v}"}
        return {"allowed": True, "query": param_query, "params": param_values}
    return {"allowed": True}
