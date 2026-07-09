"""
Fix for Issue #48 -- Zip Slip -> Arbitrary File Write via Archive Extraction.

Root cause
----------
Naive ZIP extraction (e.g. calling `ZipFile.extract(member, dest_dir)` or
manually joining `dest_dir` with a member's `filename`) trusts the entry name
verbatim. A malicious archive can contain an entry such as
`../../etc/cron.d/malicious` or an absolute path like `/etc/passwd`. When
joined with the destination directory, the resulting path can escape the
intended extraction directory entirely, allowing an attacker to overwrite
arbitrary files on the host ("Zip Slip").

Per standard guidance (OWASP, Snyk zip-slip advisory) the fix must:

  1. Canonicalize (resolve symlinks / `..` / `.` components) both the
     destination directory and every computed member target path.
  2. Verify the canonical member path is a strict sub-path of the canonical
     destination directory before writing anything to disk.
  3. Reject / skip entries containing `..` path segments or absolute paths
     outright, as defense in depth on top of the canonical-path check.

This module provides:

  * `safe_extract_all(zip_path, dest_dir)` -- validates and extracts every
    entry in a ZIP archive, raising `PathTraversalError` for any entry that
    would escape `dest_dir`.
  * `resolve_safe_path(dest_dir, member_name)` -- the core canonicalization +
    containment check, reusable for other archive formats (tar, etc).
  * Self-tests demonstrating that path traversal, absolute-path, and
    legitimate nested entries are all handled correctly.
"""

from __future__ import annotations

import io
import logging
import os
import zipfile
from typing import List

log = logging.getLogger(__name__)


class PathTraversalError(Exception):
    """Raised when a ZIP entry would extract outside the destination directory."""


def _has_traversal_segment(member_name: str) -> bool:
    """Reject entries with explicit '..' path components or absolute paths."""
    # Normalize separators so both '/' and '\\' style entries are checked.
    normalized = member_name.replace("\\", "/")
    if normalized.startswith("/"):
        return True
    # Windows drive-letter absolute path, e.g. 'C:/evil'
    if len(normalized) >= 2 and normalized[1] == ":":
        return True
    parts = normalized.split("/")
    return any(part == ".." for part in parts)


def resolve_safe_path(dest_dir: str, member_name: str) -> str:
    """
    Compute the canonical extraction path for `member_name` inside `dest_dir`
    and verify it does not escape `dest_dir`.

    Returns the canonical (real) path to extract to. Raises
    `PathTraversalError` if the entry is unsafe.
    """
    if not member_name or member_name.strip() == "":
        raise PathTraversalError("empty archive entry name")

    # Defense in depth: reject '..' segments / absolute paths outright,
    # regardless of what canonicalization would resolve to.
    if _has_traversal_segment(member_name):
        raise PathTraversalError(
            f"rejected archive entry with path traversal sequence: {member_name!r}"
        )

    # Canonicalize the destination directory once.
    canonical_dest = os.path.realpath(dest_dir)

    # Join and canonicalize the candidate target path.
    candidate = os.path.join(canonical_dest, member_name)
    canonical_candidate = os.path.realpath(candidate)

    # Verify the canonical candidate path is inside (or equal to) the
    # canonical destination directory using commonpath, which correctly
    # handles symlink resolution and relative segment collapsing.
    try:
        common = os.path.commonpath([canonical_dest, canonical_candidate])
    except ValueError:
        # Different drives on Windows, etc. -- definitely not contained.
        raise PathTraversalError(
            f"archive entry resolves outside destination directory: {member_name!r}"
        )

    if common != canonical_dest:
        raise PathTraversalError(
            f"archive entry resolves outside destination directory: {member_name!r}"
        )

    return canonical_candidate


def safe_extract_all(zip_path: str, dest_dir: str) -> List[str]:
    """
    Safely extract every entry of the ZIP archive at `zip_path` into
    `dest_dir`.

    Each entry's target path is canonicalized and validated to remain inside
    `dest_dir` before any file or directory is created. Any entry that fails
    validation causes `PathTraversalError` to be raised and aborts extraction
    before writing that entry (previously extracted, validated entries are
    left on disk).

    Returns the list of canonical file paths written.
    """
    os.makedirs(dest_dir, exist_ok=True)
    canonical_dest = os.path.realpath(dest_dir)
    written: List[str] = []

    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            member_name = info.filename
            target_path = resolve_safe_path(canonical_dest, member_name)

            if info.is_dir():
                os.makedirs(target_path, exist_ok=True)
                continue

            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            with zf.open(info, "r") as src, open(target_path, "wb") as dst:
                dst.write(src.read())
            written.append(target_path)
            log.info("extracted safe entry %r -> %s", member_name, target_path)

    return written


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

def _make_zip_bytes(entries: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _run_self_tests() -> None:
    import shutil
    import tempfile

    tmp_root = tempfile.mkdtemp(prefix="zipslip_test_")
    try:
        dest_dir = os.path.join(tmp_root, "extract_here")
        os.makedirs(dest_dir, exist_ok=True)

        # 1. Malicious relative traversal entry must be rejected.
        evil_zip_path = os.path.join(tmp_root, "evil.zip")
        with open(evil_zip_path, "wb") as f:
            f.write(
                _make_zip_bytes(
                    {"../../etc/cron.d/malicious": "* * * * * root evil\n"}
                )
            )
        try:
            safe_extract_all(evil_zip_path, dest_dir)
        except PathTraversalError:
            pass
        else:
            raise AssertionError("path traversal entry must be rejected")

        # Ensure nothing escaped the destination directory.
        escaped_path = os.path.realpath(
            os.path.join(dest_dir, "..", "..", "etc", "cron.d", "malicious")
        )
        assert not os.path.exists(escaped_path), "traversal entry must not be written"

        # 2. Absolute path entry must be rejected.
        abs_zip_path = os.path.join(tmp_root, "abs.zip")
        with open(abs_zip_path, "wb") as f:
            f.write(_make_zip_bytes({"/etc/passwd": "pwned\n"}))
        try:
            safe_extract_all(abs_zip_path, dest_dir)
        except PathTraversalError:
            pass
        else:
            raise AssertionError("absolute path entry must be rejected")

        # 3. Windows-style traversal entry must be rejected.
        win_zip_path = os.path.join(tmp_root, "win.zip")
        with open(win_zip_path, "wb") as f:
            f.write(_make_zip_bytes({"..\\..\\windows\\evil.dll": "pwned"}))
        try:
            safe_extract_all(win_zip_path, dest_dir)
        except PathTraversalError:
            pass
        else:
            raise AssertionError("windows-style traversal entry must be rejected")

        # 4. Legitimate nested entries extract correctly inside dest_dir.
        good_dest = os.path.join(tmp_root, "good_extract")
        good_zip_path = os.path.join(tmp_root, "good.zip")
        with open(good_zip_path, "wb") as f:
            f.write(
                _make_zip_bytes(
                    {
                        "file.txt": "hello\n",
                        "sub/dir/file2.txt": "nested\n",
                    }
                )
            )
        written = safe_extract_all(good_zip_path, good_dest)
        assert len(written) == 2
        for path in written:
            assert os.path.commonpath(
                [os.path.realpath(good_dest), path]
            ) == os.path.realpath(good_dest)
            assert os.path.isfile(path)

        print("All Zip Slip fix self-tests passed.")
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    _run_self_tests()
