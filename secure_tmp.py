"""
Fix for TOCTOU race condition in /tmp file handling.
Issue: https://github.com/zhangjiayang6835-cyber/ai-research/issues/1177
"""

import os
import tempfile


def secure_read_file(filepath):
    """
    Read file securely without TOCTOU vulnerability.
    Opens directly with file descriptor, no existence check first.
    """
    try:
        fd = os.open(filepath, os.O_RDONLY)
        with os.fdopen(fd, 'r') as f:
            return f.read()
    except (FileNotFoundError, PermissionError):
        return None


def secure_write_tmp(data, prefix="tmp"):
    """
    Write to temporary file securely using mkstemp.
    Returns file path.
    """
    fd, path = tempfile.mkstemp(prefix=prefix)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(data)
        return path
    except Exception:
        os.close(fd)
        raise


def atomic_replace(src, dst):
    """
    Atomically replace dst with src to prevent race conditions.
    """
    import shutil
    shutil.move(src, dst)