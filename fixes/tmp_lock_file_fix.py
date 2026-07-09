"""
Fix for: Race Condition in /tmp File Handling (TOCTOU)

Vulnerability
-------------
The previous implementation checked ``if not os.path.exists('/tmp/lock')``
and then, in a *separate* step, opened/created the file and wrote data to
it. Between the existence check and the creation, a local attacker can
replace ``/tmp/lock`` with a symlink pointing at a sensitive file (for
example ``/etc/passwd`` or another user's file). When the victim process
then opens "/tmp/lock" for writing, it actually follows the symlink and
overwrites the attacker-chosen target -- a classic TOCTOU (time-of-check
to time-of-use) race condition leading to arbitrary file write / privilege
escalation.

Root cause
----------
1. Existence check ("check") and file creation ("use") are two separate
   syscalls with an exploitable window in between.
2. The file is created with default (often world-readable/writable)
   permissions.
3. No validation is performed on the resulting file's owner or type
   before writing to it.

Fix (defense in depth)
-----------------------
1. Replace the check-then-create pattern with a single atomic
   ``os.open()`` call using ``O_CREAT | O_EXCL | O_NOFOLLOW``. This
   guarantees the file did not already exist (whether as a real file or
   a symlink) and that the kernel refuses to follow a symlink even if
   one is planted at that path.
2. Create the file with strict ``0600`` permissions from the very first
   syscall (no window where the file is more permissive).
3. After opening, validate via ``os.fstat`` on the *file descriptor*
   (not the path, to avoid a second TOCTOU) that:
     - the file is owned by the current effective UID,
     - the file is a regular file (not a symlink/FIFO/device),
     - the permission bits are exactly what we requested.
4. For lock/scratch files that do not need a fixed well-known name,
   prefer ``tempfile.mkstemp()`` inside a dedicated, securely-created
   (``0700``) temporary directory, which provides the same atomicity
   guarantees plus an unpredictable filename.
5. Expose a context manager, ``secure_lock_file``, so callers cannot
   forget to validate/clean up the file descriptor.

This mirrors the style used elsewhere in this repository for security
fixes (see ``fixes/directory_listing_uploads_fix.py`` and
``fix-ssrf-aws-metadata.py``): a small, dependency-free, drop-in
replacement plus self-tests at the bottom of the file.
"""

from __future__ import annotations

import contextlib
import errno
import os
import stat
import tempfile
from typing import IO, Iterator, Optional


class LockFileError(Exception):
    """Raised when a lock/scratch file cannot be created or validated safely."""


#: Permission bits enforced on every lock file we create: rw for owner only.
_SECURE_MODE = 0o600

#: Flags that guarantee atomic, symlink-safe creation.
_SECURE_OPEN_FLAGS = os.O_CREAT | os.O_EXCL | os.O_WRONLY
if hasattr(os, "O_NOFOLLOW"):
    _SECURE_OPEN_FLAGS |= os.O_NOFOLLOW


def _validate_fd_owner_and_type(fd: int, path: str) -> None:
    """Validate that ``fd`` refers to a regular file owned by us.

    Uses ``os.fstat`` on the already-open descriptor (not a fresh
    ``os.stat(path)``) so there is no additional TOCTOU window between
    validation and use.
    """
    try:
        st = os.fstat(fd)
    except OSError as exc:  # pragma: no cover - defensive
        raise LockFileError(f"unable to stat lock file {path!r}: {exc}") from exc

    if not stat.S_ISREG(st.st_mode):
        raise LockFileError(f"lock file {path!r} is not a regular file")

    expected_uid = os.geteuid() if hasattr(os, "geteuid") else None
    if expected_uid is not None and st.st_uid != expected_uid:
        raise LockFileError(
            f"lock file {path!r} is owned by uid {st.st_uid}, expected {expected_uid}"
        )

    mode_bits = stat.S_IMODE(st.st_mode)
    if mode_bits != _SECURE_MODE:
        raise LockFileError(
            f"lock file {path!r} has permissions {oct(mode_bits)}, "
            f"expected {oct(_SECURE_MODE)}"
        )


def create_secure_lock_file(path: str) -> int:
    """Atomically create ``path`` as a fresh, owner-only file.

    Returns an open file descriptor. Raises :class:`LockFileError` if the
    file already exists (including as a symlink), or if post-creation
    validation of owner/type/permissions fails.

    This single call replaces the vulnerable pattern::

        if not os.path.exists(path):        # CHECK
            with open(path, 'w') as f:       # USE (race window above!)
                f.write(data)
    """
    # Restrict umask during creation so no other process/thread running in
    # this interpreter can widen the permissions of the new file before we
    # get a chance to fstat/validate it. Restore immediately afterward.
    previous_umask = os.umask(0o077)
    try:
        try:
            fd = os.open(path, _SECURE_OPEN_FLAGS, _SECURE_MODE)
        except FileExistsError as exc:
            raise LockFileError(
                f"lock file {path!r} already exists; refusing to overwrite "
                "(possible TOCTOU/symlink attack)"
            ) from exc
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise LockFileError(
                    f"lock file {path!r} is a symlink; refusing to follow it"
                ) from exc
            raise LockFileError(f"unable to create lock file {path!r}: {exc}") from exc
    finally:
        os.umask(previous_umask)

    try:
        # Belt-and-braces: enforce the exact mode even if umask/platform
        # behavior caused something looser to be applied at creation time.
        os.fchmod(fd, _SECURE_MODE)
        _validate_fd_owner_and_type(fd, path)
    except LockFileError:
        os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise
    except Exception:
        os.close(fd)
        raise

    return fd


def create_secure_tmp_scratch_file(prefix: str = "lock-", dir: Optional[str] = None) -> tuple[int, str]:
    """Create an unpredictable-named scratch file inside a private tmp dir.

    Prefer this over :func:`create_secure_lock_file` whenever the caller
    does not need a fixed, well-known filename (e.g. a well-known PID/lock
    path that other processes must discover). Uses ``tempfile.mkstemp``,
    which is implemented with ``O_CREAT | O_EXCL`` internally, inside a
    directory we create with ``0700`` permissions.

    Returns ``(fd, path)``.
    """
    secure_dir = dir
    if secure_dir is None:
        base = tempfile.gettempdir()
        secure_dir = os.path.join(base, f".secure-{os.getpid()}")
        os.makedirs(secure_dir, mode=0o700, exist_ok=True)
        # Ensure permissions are exactly 0700 even if the dir pre-existed
        # with looser permissions (e.g. inherited umask).
        os.chmod(secure_dir, 0o700)

    fd, path = tempfile.mkstemp(prefix=prefix, dir=secure_dir)
    try:
        os.fchmod(fd, _SECURE_MODE)
        _validate_fd_owner_and_type(fd, path)
    except LockFileError:
        os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise
    except Exception:
        os.close(fd)
        raise

    return fd, path


@contextlib.contextmanager
def secure_lock_file(path: str) -> Iterator[IO[bytes]]:
    """Context manager wrapping :func:`create_secure_lock_file`.

    Guarantees the underlying descriptor is closed on exit and that the
    file is removed if the caller's block raises an exception, so a
    failed operation never leaves a half-written lock file behind.

    Usage::

        with secure_lock_file('/tmp/myapp.lock') as f:
            f.write(b'locked by pid %d' % os.getpid())
    """
    fd = create_secure_lock_file(path)
    file_obj = os.fdopen(fd, "wb")
    try:
        yield file_obj
    except Exception:
        file_obj.close()
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise
    else:
        file_obj.close()


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------


def _selftest() -> None:  # pragma: no cover - executed on module load in tests
    import shutil

    tmp_root = tempfile.mkdtemp(prefix="tmp_lock_file_fix_selftest_")
    try:
        lock_path = os.path.join(tmp_root, "app.lock")

        # 1. Fresh creation succeeds and has mode 0600.
        with secure_lock_file(lock_path) as f:
            f.write(b"hello")
        mode = stat.S_IMODE(os.stat(lock_path).st_mode)
        assert mode == _SECURE_MODE, f"expected 0600, got {oct(mode)}"

        # 2. Re-acquiring the same path fails (file already exists) -
        #    proves atomicity of O_EXCL and that we don't silently
        #    overwrite / follow anything.
        try:
            create_secure_lock_file(lock_path)
        except LockFileError:
            pass
        else:  # pragma: no cover
            raise AssertionError("expected LockFileError for existing lock file")

        # 3. Symlink attack: attacker pre-creates a symlink pointing
        #    somewhere sensitive; our atomic open must refuse to follow it.
        if hasattr(os, "symlink"):
            victim_target = os.path.join(tmp_root, "victim.txt")
            with open(victim_target, "w") as vf:
                vf.write("do not touch")
            symlink_path = os.path.join(tmp_root, "attacker.lock")
            os.symlink(victim_target, symlink_path)
            try:
                create_secure_lock_file(symlink_path)
            except LockFileError:
                pass
            else:  # pragma: no cover
                raise AssertionError("expected LockFileError when target is a symlink")
            # Victim file must be untouched.
            with open(victim_target) as vf:
                assert vf.read() == "do not touch"

        # 4. tempfile-based scratch file also gets 0600 and a private dir.
        fd, scratch_path = create_secure_tmp_scratch_file()
        try:
            scratch_mode = stat.S_IMODE(os.stat(scratch_path).st_mode)
            assert scratch_mode == _SECURE_MODE
            parent_mode = stat.S_IMODE(os.stat(os.path.dirname(scratch_path)).st_mode)
            assert parent_mode == 0o700
        finally:
            os.close(fd)
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


if __name__ == "__main__":  # pragma: no cover
    _selftest()
    print("tmp_lock_file_fix: all self-tests passed")
