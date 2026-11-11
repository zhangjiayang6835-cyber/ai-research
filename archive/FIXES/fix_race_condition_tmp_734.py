"""
Fix for Issue #734 — Race Condition in /tmp File Handling (TOCTOU)
====================================================================

Vulnerability
-------------
A script checks if ``/tmp/lock`` does not exist, then creates and writes data.
Between the existence check and file creation, an attacker can replace the
path with a symlink pointing to an arbitrary file (e.g., ``/etc/passwd``),
leading to arbitrary file write.

Fix Strategy
------------
1. Use ``os.open()`` with ``O_CREAT | O_EXCL`` to atomically create the lock
   file — no TOCTOU window between check and creation.
2. Use ``tempfile.mkstemp()`` in a dedicated secure directory.
3. Set strict file permissions (0o600) after creation.
4. Verify the file owner matches the expected user.
"""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path


# ---------------------------------------------------------------------------
# Secure lock-file helper (O_EXCL atomic creation)
# ---------------------------------------------------------------------------

SECURE_LOCK_DIR = Path(tempfile.gettempdir()) / ".secure_locks"


def _ensure_secure_lock_dir() -> Path:
    """Create the secure lock directory with restricted permissions."""
    SECURE_LOCK_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    return SECURE_LOCK_DIR


def create_lock_atomic(lock_name: str) -> int:
    """
    Create a lock file atomically using O_CREAT | O_EXCL.

    Parameters
    ----------
    lock_name : str
        Name of the lock file (e.g., ``"myapp.lock"``).

    Returns
    -------
    int
        File descriptor of the newly created lock file.

    Raises
    ------
    FileExistsError
        If the lock file already exists (another process holds it).
    PermissionError
        If the secure lock directory cannot be created/accessed.
    """
    lock_dir = _ensure_secure_lock_dir()
    lock_path = lock_dir / lock_name

    try:
        fd = os.open(
            str(lock_path),
            os.O_CREAT | os.O_EXCL | os.O_RDWR,
            mode=0o600,
        )
    except FileExistsError:
        raise FileExistsError(
            f"Lock file already exists: {lock_path}. "
            "Another process may hold the lock."
        )

    # Verify the file we just created belongs to us
    st = os.fstat(fd)
    if st.st_uid != os.getuid():
        os.close(fd)
        os.unlink(lock_path)
        raise PermissionError(
            f"Lock file owner mismatch: expected uid {os.getuid()}, "
            f"got {st.st_uid}."
        )

    return fd


def release_lock(lock_name: str, fd: int | None = None) -> None:
    """
    Release a lock file by closing and unlinking it.

    Parameters
    ----------
    lock_name : str
        Name of the lock file to release.
    fd : int or None
        File descriptor to close. If None, only the file is unlinked.
    """
    lock_path = SECURE_LOCK_DIR / lock_name

    if fd is not None:
        try:
            os.close(fd)
        except OSError:
            pass

    try:
        lock_path.unlink(missing_ok=True)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Secure temporary file helper (using mkstemp)
# ---------------------------------------------------------------------------


def create_secure_tempfile(
    prefix: str = "tmp_",
    suffix: str = "",
    dir: str | None = None,
) -> tuple[int, str]:
    """
    Create a secure temporary file using ``tempfile.mkstemp``.

    The file is created with mode 0o600 in a directory with mode 0o700.

    Parameters
    ----------
    prefix : str
        Prefix for the temporary file name.
    suffix : str
        Suffix for the temporary file name.
    dir : str or None
        Directory to create the temporary file in. If None, uses the
        system temporary directory.

    Returns
    -------
    tuple of (int, str)
        File descriptor and absolute path to the temporary file.
    """
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=dir)

    # Set strict permissions on the file
    os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)  # 0o600

    # Verify ownership
    st = os.fstat(fd)
    if st.st_uid != os.getuid():
        os.close(fd)
        os.unlink(path)
        raise PermissionError(
            f"Temporary file owner mismatch: expected uid {os.getuid()}, "
            f"got {st.st_uid}."
        )

    return fd, path


# ---------------------------------------------------------------------------
# Example: Replacing the vulnerable lock pattern
# ---------------------------------------------------------------------------

# Instead of:
#
#   lock_path = "/tmp/lock"
#   if not os.path.exists(lock_path):
#       with open(lock_path, "w") as f:
#           f.write("data")
#
# Use:
#
#   try:
#       fd = create_lock_atomic("myapp.lock")
#       with os.fdopen(fd, "w") as f:
#           f.write("data")
#   except FileExistsError:
#       print("Another process holds the lock.")
#   finally:
#       release_lock("myapp.lock")
