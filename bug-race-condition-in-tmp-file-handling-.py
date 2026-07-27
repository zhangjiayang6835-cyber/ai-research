#!/usr/bin/env python3
"""
Secure /tmp File Handling - TOCTOU Race Condition Fix

This module provides secure alternatives to the vulnerable TOCTOU (Time-of-Check
Time-of-Use) pattern commonly found in /tmp file handling.

VULNERABILITY DESCRIPTION:
    The original code used a pattern like:
        if os.path.exists(tmp_file):
            # process file
        else:
            # create file

    This creates a race condition (CWE-367) where an attacker can replace the file
    between the existence check and the actual file operation, potentially leading
    to:
        - Arbitrary file read/write via symlinks
        - Denial of service
        - Privilege escalation

FIX:
    Use atomic operations that eliminate the time gap between check and use:
        - os.open() with O_CREAT | O_EXCL for file creation
        - tempfile module for secure temporary files
        - lstat() checks for symlink detection
        - Proper file permissions (0600)
        - O_NOFOLLOW to prevent symlink following

References:
    - CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
    - CWE-59: Improper Link Resolution Before File Access
    - CWE-377: Insecure Temporary File
"""

import os
import tempfile
import logging
import stat
import errno
from typing import Optional, IO, Any
from contextlib import contextmanager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TmpFileError(Exception):
    """Base exception for temporary file errors."""
    pass


class TocTOURaceConditionError(TmpFileError):
    """Raised when a potential TOCTOU race condition is detected."""
    pass


class SymlinkAttackError(TmpFileError):
    """Raised when a symlink attack is detected."""
    pass


class SecureTmpFileHandler:
    """
    Secure handler for temporary file operations in /tmp.

    This class eliminates TOCTOU race conditions by using atomic file operations
    and proper symlink checks.
    """

    # Secure file permissions: owner read/write only
    SECURE_FILE_MODE = 0o600
    # Secure directory permissions: owner read/write/execute only
    SECURE_DIR_MODE = 0o700

    def __init__(self, prefix: str = "secure_tmp", suffix: str = ".tmp",
                 tmp_dir: Optional[str] = None):
        """
        Initialize the secure temporary file handler.

        Args:
            prefix: Prefix for the temporary file name.
            suffix: Suffix for the temporary file name.
            tmp_dir: Custom temporary directory. Defaults to system temp dir.

        Raises:
            ValueError: If prefix or suffix contain path separators.
        """
        if os.path.sep in prefix or os.path.sep in suffix:
            raise ValueError("Prefix and suffix must not contain path separators")
        if '/' in prefix or '/' in suffix:
            raise ValueError("Prefix and suffix must not contain '/'")

        self.prefix = prefix
        self.suffix = suffix
        self.tmp_dir = tmp_dir or tempfile.gettempdir()
        self._validate_tmp_dir()

    def _validate_tmp_dir(self) -> None:
        """
        Validate that the temporary directory is safe to use.

        Checks:
            - Directory exists and is a directory
            - Directory is not world-writable (or is sticky)
            - Directory is not a symlink

        Raises:
            TmpFileError: If the directory fails validation.
        """
        try:
            # Use lstat to avoid following symlinks
            dir_stat = os.lstat(self.tmp_dir)
        except OSError as e:
            raise TmpFileError(f"Cannot stat temp directory '{self.tmp_dir}': {e}")

        # Check if it's a directory
        if not stat.S_ISDIR(dir_stat.st_mode):
            raise TmpFileError(f"Temp path '{self.tmp_dir}' is not a directory")

        # Check if it's a symlink (potential attack)
        if stat.S_ISLNK(dir_stat.st_mode):
            raise SymlinkAttackError(
                f"Temp directory '{self.tmp_dir}' is a symlink - possible attack"
            )

        # Check directory permissions
        # On Unix, /tmp is typically 1777 (sticky bit set), which is acceptable
        # A non-sticky world-writable directory is dangerous
        is_world_writable = bool(dir_stat.st_mode & stat.S_IWOTH)
        has_sticky_bit = bool(dir_stat.st_mode & stat.S_ISVTX)

        if is_world_writable and not has_sticky_bit:
            logger.warning(
                f"Temp directory '{self.tmp_dir}' is world-writable without sticky bit. "
                "This may allow other users to manipulate files."
            )

    def _check_for_symlink(self, filepath: str) -> None:
        """
        Check if a path is or contains a symlink (symlink attack detection).

        Args:
            filepath: The file path to check.

        Raises:
            SymlinkAttackError: If a symlink is detected at the target path.
        """
        try:
            file_stat = os.lstat(filepath)
            if stat.S_ISLNK(file_stat.st_mode):
                raise SymlinkAttackError(
                    f"Path '{filepath}' is a symlink - possible symlink attack"
                )
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise TmpFileError(f"Error checking path '{filepath}': {e}")

    def create_secure_file(self, content: Optional[bytes] = None) -> str:
        """
        Create a temporary file securely using atomic operations.

        This method uses O_CREAT | O_EXCL to atomically create the file,
        eliminating the TOCTOU window. If the file already exists, the
        operation fails (O_EXCL ensures this).

        Args:
            content: Optional initial content to write to the file.

        Returns:
            Path to the created temporary file.

        Raises:
            TocTOURaceConditionError: If the file already exists (race detected).
            TmpFileError: If file creation fails for other reasons.
        """
        # Use tempfile.mkstemp which uses O_CREAT | O_EXCL internally
        # This is the secure way to create temp files
        try:
            fd, filepath = tempfile.mkstemp(
                prefix=self.prefix,
                suffix=self.suffix,
                dir=self.tmp_dir,
            )
        except OSError as e:
            raise TmpFileError(f"Failed to create secure temp file: {e}")

        try:
            # Set secure permissions immediately after creation
            os.fchmod(fd, self.SECURE_FILE_MODE)

            # Write content if provided
            if content is not None:
                if isinstance(content, str):
                    content = content.encode('utf-8')
                os.write(fd, content)

            logger.debug(f"Created secure temp file: {filepath}")
            return filepath

        except OSError as e:
            # Clean up on failure
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(filepath)
            except OSError:
                pass
            raise TmpFileError(f"Failed to initialize temp file '{filepath}': {e}")

        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    def open_existing_secure(self, filepath: str, mode: str = 'r') -> IO[Any]:
        """
        Open an existing temporary file securely.

        This method performs symlink checks before opening and uses
        O_NOFOLLOW to prevent symlink following.

        Args:
            filepath: Path to the file to open.
            mode: File open mode ('r', 'w', 'rb', 'wb', etc.).

        Returns:
            A file object.

        Raises:
            SymlinkAttackError: If the path is a symlink.
            TmpFileError: If the file cannot be opened safely.
            FileNotFoundError: If the file does not exist.
        """
        # Check for symlink before opening
        self._check_for_symlink(filepath)

        # Verify file exists (without following symlinks)
        try:
            file_stat = os.lstat(filepath)
        except OSError as e:
            if e.errno == errno.ENOENT:
                raise FileNotFoundError(f"File not found: {filepath}")
            raise TmpFileError(f"Cannot stat file '{filepath}': {e}")

        # Verify it's a regular file
        if not stat.S_ISREG(file_stat.st_mode):
            raise TmpFileError(f"Path '{filepath}' is not a regular file")

        # Check file permissions - warn if world-readable/writable
        if file_stat.st_mode & stat.S_IWOTH:
            logger.warning(f"File '{filepath}' is world-writable")

        # Open the file with O_NOFOLLOW to prevent symlink attacks
        # Build flags based on mode
        flags = os.O_NOFOLLOW  # Prevent symlink following

        if 'r' in mode and 'w' not in mode and 'a' not in mode:
            flags |= os.O_RDONLY
        elif 'w' in mode:
            flags |= os.O_WRONLY
            if '+' in mode:
                flags |= os.O_RDWR
        elif 'a' in mode:
            flags |= os.O_WRONLY | os.O_APPEND
            if '+' in mode:
                flags |= os.O_RDWR
        else:
            flags |= os.O_RDONLY

        if 'b