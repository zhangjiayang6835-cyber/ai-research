"""
Fix for Issue #958 — Zip Slip → Arbitrary File Write via Archive Extraction
==============================================================================

Vulnerability
-------------
ZIP file extraction does not validate whether filenames contain ../. Attackers
construct ZIP files with entries like ../../etc/cron.d/malicious, overwriting
system files.

Fix Strategy
------------
1. Normalize output paths using os.path.realpath() and verify containment.
2. Reject entries containing .. or starting with /.
3. Validate each entry's path before extraction.
"""

from __future__ import annotations

import os
import zipfile
from pathlib import Path
from typing import Iterator


class SafeZipExtractor:
    """
    Safe ZIP extractor that prevents Zip Slip path traversal attacks.

    Usage:
        extractor = SafeZipExtractor("/safe/output/dir")
        extractor.extract_all("archive.zip")
    """

    def __init__(self, extract_dir: str):
        self._extract_dir = os.path.realpath(os.path.normpath(extract_dir))

    def _is_safe_path(self, entry_path: str) -> bool:
        """
        Check if a ZIP entry path is safe for extraction.

        Returns False if:
        - Path contains parent directory traversal (..)
        - Path is absolute (starts with /)
        - Resolved path is outside the extraction directory
        """
        # Reject paths with parent traversal
        if ".." in entry_path.split("/"):
            return False

        # Reject absolute paths
        if entry_path.startswith("/"):
            return False

        # Reject paths that escape the extraction directory
        resolved = os.path.realpath(os.path.join(self._extract_dir, entry_path))
        if not resolved.startswith(self._extract_dir):
            return False

        return True

    def extract_all(self, zip_path: str) -> list[str]:
        """
        Safely extract all entries from a ZIP file.

        Parameters
        ----------
        zip_path : str
            Path to the ZIP file.

        Returns
        -------
        list of str
            Paths of successfully extracted files.

        Raises
        ------
        ValueError
            If a Zip Slip attempt is detected.
        """
        extracted: list[str] = []

        with zipfile.ZipFile(zip_path, "r") as zf:
            for entry in zf.infolist():
                # Normalize the entry filename
                entry_name = entry.filename.rstrip("/")

                if not self._is_safe_path(entry_name):
                    raise ValueError(
                        f"Zip Slip detected: entry '{entry_name}' attempts "
                        f"path traversal outside {self._extract_dir}"
                    )

                if entry_name.endswith("/"):
                    # Directory entry
                    os.makedirs(
                        os.path.join(self._extract_dir, entry_name),
                        exist_ok=True,
                    )
                else:
                    # File entry
                    target = os.path.join(self._extract_dir, entry_name)
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with zf.open(entry) as source, open(target, "wb") as dest:
                        dest.write(source.read())
                    extracted.append(target)

        return extracted

    def extract_entry(self, zf: zipfile.ZipFile, entry_name: str) -> bytes | None:
        """Extract a single ZIP entry safely, returning its content or None."""
        if not self._is_safe_path(entry_name):
            return None
        try:
            with zf.open(entry_name) as entry:
                return entry.read()
        except KeyError:
            return None
