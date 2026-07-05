from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from fixes.path_traversal_download_fix import (
    DownloadNotFound,
    SafeDownloadStore,
    UnsafeDownloadPath,
)


class SafeDownloadStoreTests(unittest.TestCase):
    def test_reads_regular_file_under_base_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir, "downloads")
            target = base / "reports" / "summary 2026.txt"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"safe report")
            store = SafeDownloadStore(base)

            self.assertEqual(store.read_bytes("reports/summary%202026.txt"), b"safe report")
            self.assertEqual(store.resolve("reports/summary 2026.txt"), target.resolve())

    def test_rejects_plain_and_encoded_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir, "downloads")
            base.mkdir()
            Path(temp_dir, "secret.txt").write_text("secret", encoding="utf-8")
            store = SafeDownloadStore(base)

            for requested in (
                "../secret.txt",
                "reports/../../secret.txt",
                "%2e%2e/secret.txt",
                "%252e%252e%252fsecret.txt",
                "reports/%2e%2e/%2e%2e/secret.txt",
            ):
                with self.subTest(requested=requested):
                    with self.assertRaises(UnsafeDownloadPath):
                        store.read_bytes(requested)

    def test_rejects_absolute_windows_unc_and_control_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = SafeDownloadStore(Path(temp_dir, "downloads"))

            for requested in (
                "/etc/passwd",
                "C:/Windows/win.ini",
                r"C:\Windows\win.ini",
                r"\\server\share\file.txt",
                "safe\x00.txt",
                "safe\n.txt",
            ):
                with self.subTest(requested=requested):
                    with self.assertRaises(UnsafeDownloadPath):
                        store.resolve(requested)

    def test_rejects_directories_and_missing_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir, "downloads")
            Path(base, "nested").mkdir(parents=True)
            store = SafeDownloadStore(base)

            with self.assertRaises(DownloadNotFound):
                store.read_bytes("nested")
            with self.assertRaises(DownloadNotFound):
                store.read_bytes("missing.txt")

    def test_rejects_symlink_escape_after_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir, "downloads")
            base.mkdir()
            outside = Path(temp_dir, "outside.txt")
            outside.write_text("outside", encoding="utf-8")
            link = base / "outside-link.txt"
            try:
                os.symlink(outside, link)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            store = SafeDownloadStore(base)

            with self.assertRaises(UnsafeDownloadPath):
                store.read_bytes("outside-link.txt")


if __name__ == "__main__":
    unittest.main()

