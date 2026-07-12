"""
Fix: Race Condition in /tmp File Handling (TOCTOU)
===================================================
Issue #1160 — Checking if a file like /tmp/lock exists and then creating it
introduces a Time-of-Check to Time-of-Use (TOCTOU) race condition. An attacker
could replace the file with a symlink to /etc/passwd or another critical file
between the check and the write, leading to arbitrary file write.

This fix provides a secure way to create temporary files using mkstemp, which
uses the O_CREAT | O_EXCL flags to atomically create the file and fail if it
already exists. It also enforces strict file permissions (0600) and verifies
file ownership.
"""

import os
import stat
import tempfile

class SecurityError(Exception):
    """Raised when security requirements are violated."""
    pass

def create_secure_temp_file(data: bytes, prefix: str = "lock_", suffix: str = "", directory: str = "/tmp") -> str:
    """
    Atomically creates a temporary file and writes data to it.
    
    Uses mkstemp with O_CREAT | O_EXCL to prevent TOCTOU race conditions.
    Ensures the file is created with 0600 permissions and is owned by the
    current user.
    """
    if not isinstance(data, bytes):
        data = data.encode('utf-8')
        
    # mkstemp automatically sets O_RDWR | O_CREAT | O_EXCL and 0600 permissions
    fd, tmp_path = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=directory)
    
    try:
        # Verify file ownership
        st = os.fstat(fd)
        if st.st_uid != os.getuid():
            raise SecurityError(f"Temporary file {tmp_path} is not owned by the current user.")
        
        # Verify file permissions (must be exactly 0600)
        # stat.S_IMODE gets the permission bits
        mode = stat.S_IMODE(st.st_mode)
        expected_mode = stat.S_IRUSR | stat.S_IWUSR  # 0600
        if mode != expected_mode:
            raise SecurityError(f"Temporary file {tmp_path} has insecure permissions {oct(mode)}.")
            
        # Write data to the file atomically
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
            
    except Exception:
        # Cleanup on failure
        os.unlink(tmp_path)
        raise
        
    return tmp_path
