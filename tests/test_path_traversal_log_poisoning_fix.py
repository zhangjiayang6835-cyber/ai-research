"""Tests for issue #334 path traversal and log poisoning hardening."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fixes.path_traversal_log_poisoning_fix import (
    PathTraversalLogPoisoningError,
    read_text_under_base,
    resolve_safe_path,
    sanitize_log_value,
    structured_log_line,
)


class PathTraversalLogPoisoningFixTests(unittest.TestCase):
    def test_resolve_safe_path_allows_in_tree_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "public").mkdir()
            target = base / "public" / "report.txt"
            target.write_text("safe", encoding="utf-8")

            resolved = resolve_safe_path(base, "public/report.txt")

            self.assertEqual(resolved, target.resolve())

    def test_resolve_safe_path_rejects_parent_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(PathTraversalLogPoisoningError):
                resolve_safe_path(tmp, "../secret.txt")

    def test_resolve_safe_path_rejects_url_encoded_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(PathTraversalLogPoisoningError):
                resolve_safe_path(tmp, "%252e%252e%252fsecret.txt")

    def test_resolve_safe_path_rejects_absolute_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            absolute = str(Path(tmp).resolve() / "secret.txt")

            with self.assertRaises(PathTraversalLogPoisoningError):
                resolve_safe_path(tmp, absolute)

    def test_read_text_under_base_reads_allowed_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "docs").mkdir()
            (base / "docs" / "note.txt").write_text("hello", encoding="utf-8")

            content = read_text_under_base(base, "docs/note.txt")

            self.assertEqual(content, "hello")

    def test_read_text_under_base_rejects_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(PathTraversalLogPoisoningError):
                read_text_under_base(tmp, "missing.txt")

    def test_sanitize_log_value_neutralizes_newlines_and_controls(self) -> None:
        sanitized = sanitize_log_value("ok\nlevel=admin\r\x1b[31m")

        self.assertNotIn("\n", sanitized)
        self.assertNotIn("\r", sanitized)
        self.assertNotIn("\x1b", sanitized)
        self.assertIn("\\u000a", sanitized)
        self.assertIn("\\u001b", sanitized)

    def test_structured_log_line_is_single_line_json(self) -> None:
        line = structured_log_line(
            "file_access_denied",
            user="alice\nrole=admin",
            path="../../etc/passwd",
        )

        self.assertNotIn("\n", line)
        decoded = json.loads(line)
        self.assertEqual(decoded["event"], "file_access_denied")
        self.assertIn("\\u000a", decoded["user"])
        self.assertEqual(decoded["path"], "../../etc/passwd")

    def test_structured_log_line_rejects_untrusted_field_names(self) -> None:
        with self.assertRaises(PathTraversalLogPoisoningError):
            structured_log_line("file_access", **{"bad\nkey": "value"})


if __name__ == "__main__":
    unittest.main()
