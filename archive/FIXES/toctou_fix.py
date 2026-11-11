"""
Fix for Issue #734 — Race Condition in /tmp File Handling (TOCTOU)

Vulnerability
-------------
The script first checks whether `/tmp/lock` exists, then creates and writes to it.
An attacker can replace the file with a symlink pointing to `/etc/passwd` between
the check and create operations (TOCTOU race condition), leading to arbitrary
file write.

Fix
---
Use O_CREAT | O_EXCL atomic file creation with mkstemp(), strict file
permissions (0600), and file ownership verification.
"""

import os
import tempfile
import stat
import time
import errno


class SecureTempFile:
    """TOCTOU-safe temporary file handler using O_CREAT | O_EXCL."""

    def __init__(self, prefix="tmp", dir="/tmp"):
        self.dir = dir
        self.prefix = prefix
        self.fd = None
        self.path = None

    def __enter__(self):
        # Atomic create: mkstemp uses O_CREAT | O_EXCL internally
        self.fd, self.path = tempfile.mkstemp(
            prefix=self.prefix,
            dir=self.dir,
            suffix=".lock"
        )
        # Set strict permissions: owner read/write only
        os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
        # Verify file owner is current process
        fstat = os.fstat(self.fd)
        assert fstat.st_uid == os.getuid(), \
            "File owner mismatch - possible TOCTOU attack"
        return self

    def write(self, data: bytes):
        """Write data to secure temp file."""
        os.write(self.fd, data)
        os.fsync(self.fd)

    def read(self) -> bytes:
        """Read data from secure temp file."""
        os.lseek(self.fd, 0, os.SEEK_SET)
        return os.read(self.fd, 4096)

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.fd is not None:
            os.close(self.fd)
        if self.path and os.path.exists(self.path):
            os.unlink(self.path)


class SecureFileLock:
    """TOCTOU-safe file lock using atomic link() operation."""

    def __init__(self, lock_path: str):
        self.lock_path = lock_path
        self.lock_fd, self.lock_temp = tempfile.mkstemp(
            dir=os.path.dirname(lock_path)
        )
        os.close(self.lock_fd)

    def acquire(self, timeout: float = 10.0) -> bool:
        """Acquire lock atomically using link()."""
        start = time.time()
        while True:
            try:
                os.link(self.lock_temp, self.lock_path)
                return True
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise
                if time.time() - start > timeout:
                    return False
                time.sleep(0.01)

    def release(self):
        """Release the lock."""
        try:
            os.unlink(self.lock_path)
        except FileNotFoundError:
            pass
        finally:
            try:
                os.unlink(self.lock_temp)
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    with SecureTempFile(prefix="myapp_") as stf:
        stf.write(b"sensitive data")
        print(f"Wrote to: {stf.get_path()}")

    lock = SecureFileLock("/tmp/app.lock")
    if lock.acquire(timeout=5.0):
        try:
            print("Critical section - TOCTOU safe")
        finally:
            lock.release()