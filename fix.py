"""Submission entrypoint for issue #1503: Race Condition in /tmp File Handling (TOCTOU)."""

from fixes.toctou_tmp_file_fix import (
    SecureTempFile,
    ToctouSecurityError,
    create_named_lock,
    create_secure_temp_file,
    release_named_lock,
)

__all__ = [
    "SecureTempFile",
    "ToctouSecurityError",
    "create_named_lock",
    "create_secure_temp_file",
    "release_named_lock",
]


if __name__ == "__main__":
    print("fix #1503: /tmp temp files are created atomically without TOCTOU races")
