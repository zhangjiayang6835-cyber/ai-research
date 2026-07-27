#!/usr/bin/env python3
"""
bug-jwt-kid-injection-path-traversal-sec.py

Security fix for JWT Kid Injection → Path Traversal → Secret Key Leak vulnerability.

This module provides a hardened JWT implementation that prevents attackers from
exploiting the 'kid' (Key ID) header parameter to traverse the file system and
read arbitrary files as the secret key.

Vulnerability Details (Issue #1489):
- The original JWT verification logic reads secret keys from the filesystem
  using a user-controlled 'kid' header value without proper validation.
- An attacker can inject malicious 'kid' values like "../../etc/passwd" or
  absolute paths to read sensitive files.
- If the attacker can read a known file, they can forge valid JWT tokens.

Mitigations implemented:
1. Strict validation of the 'kid' header parameter.
2. Path traversal prevention (no '..', no absolute paths, no null bytes).
3. Whitelist-based key file naming convention.
4. Configurable key directory with safe path construction.
5. Size limits and character set restrictions.
6. Optional key ID to filename mapping (indirection layer).
"""

import os
import re
import json
import hmac
import hashlib
import base64
import logging
from typing import Optional, Dict, Any, Tuple
from pathlib import Path

# Configure logging
logger = logging.getLogger(__name__)

# Constants for security constraints
MAX_KID_LENGTH = 64
MAX_KEY_FILE_SIZE = 1024 * 64  # 64 KB max for key files
ALLOWED_KID_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]+$')
DEFAULT_KEY_DIRECTORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'keys')

# Supported HMAC algorithms mapped to their hash functions
HMAC_ALGORITHMS = {
    'HS256': hashlib.sha256,
    'HS384': hashlib.sha384,
    'HS512': hashlib.sha.sha512,
}


class JWTSecurityError(Exception):
    """Base exception for JWT security-related errors."""
    pass


class InvalidKeyIDError(JWTSecurityError):
    """Raised when the key ID (kid) fails validation."""
    pass


class KeyNotFoundError(JWTSecurityError):
    """Raised when the key file cannot be found."""
    pass


class JWTValidationError(JWTSecurityError):
    """Raised when JWT token validation fails."""
    pass


class SecureJWTHandler:
    """
    A secure JWT handler that mitigates kid injection and path traversal attacks.

    This class enforces strict validation on the 'kid' header parameter and safely
    constructs file paths to prevent directory traversal.

    Attributes:
        key_directory (Path): The base directory containing key files.
        key_mapping (dict): Optional mapping of kid values to filenames.
        allowed_kids (set): Optional whitelist of permitted kid values.
    """

    def __init__(
        self,
        key_directory: str = DEFAULT_KEY_DIRECTORY,
        key_mapping: Optional[Dict[str, str]] = None,
        allowed_kids: Optional[set] = None,
        default_algorithm: str = 'HS256'
    ):
        """
        Initialize the secure JWT handler.

        Args:
            key_directory: Path to the directory containing key files.
            key_mapping: Optional dict mapping kid values to actual filenames.
                         If provided, only mapped kids are allowed.
            allowed_kids: Optional set of whitelisted kid values.
            default_algorithm: Default HMAC algorithm to use.

        Raises:
            ValueError: If the key directory is invalid or doesn't exist.
        """
        self.key_directory = Path(key_directory).resolve()
        self.key_mapping = key_mapping or {}
        self.allowed_kids = allowed_kids or set()
        self.default_algorithm = default_algorithm

        # Validate key directory
        if not self.key_directory.is_dir():
            logger.warning(f"Key directory does not exist: {self.key_directory}")
            # Create the directory if it doesn't exist
            try:
                self.key_directory.mkdir(parents=True, exist_ok=True)
                logger.info(f"Created key directory: {self.key_directory}")
            except OSError as e:
                raise ValueError(f"Cannot create key directory {self.key_directory}: {e}")

        # Verify the resolved directory is within expected bounds
        # This prevents symlink attacks on the directory itself
        if not os.access(str(self.key_directory), os.R_OK):
            raise ValueError(f"Key directory is not readable: {self.key_directory}")

        logger.debug(f"SecureJWTHandler initialized with key directory: {self.key_directory}")

    def validate_kid(self, kid: str) -> bool:
        """
        Validate the 'kid' header parameter to prevent injection attacks.

        Security checks performed:
        1. kid must be a string.
        2. kid must not be empty.
        3. kid length must not exceed MAX_KID_LENGTH.
        4. kid must only contain alphanumeric characters, underscores, and hyphens.
        5. kid must not contain path separators (/ or \\).
        6. kid must not contain '..' sequences.
        7. kid must not contain null bytes.
        8. If a whitelist is set, kid must be in the whitelist.
        9. If a key mapping is set, kid must be in the mapping.

        Args:
            kid: The key ID to validate.

        Returns:
            True if the kid is valid.

        Raises:
            InvalidKeyIDError: If the kid fails any validation check.
        """
        if kid is None:
            raise InvalidKeyIDError("Key ID (kid) is None")

        if not isinstance(kid, str):
            raise InvalidKeyIDError(f"Key ID (kid) must be a string, got {type(kid).__name__}")

        # Check for empty kid
        if not kid or kid.strip() == '':
            raise InvalidKeyIDError("Key ID (kid) is empty")

        # Check length
        if len(kid) > MAX_KID_LENGTH:
            raise InvalidKeyIDError(
                f"Key ID (kid) exceeds maximum length of {MAX_KID_LENGTH} characters"
            )

        # Check for null bytes
        if '\x00' in kid:
            raise InvalidKeyIDError("Key ID (kid) contains null bytes")

        # Check for path traversal patterns
        if '..' in kid:
            raise InvalidKeyIDError("Key ID (kid) contains path traversal sequence '..'")

        # Check for path separators
        if '/' in kid or '\\' in kid:
            raise InvalidKeyIDError("Key ID (kid) contains path separator")

        # Check against allowed character set
        if not ALLOWED_KID_PATTERN.match(kid):
            raise InvalidKeyIDError(
                f"Key ID (kid) contains invalid characters. "
                f"Only alphanumeric characters, underscores, and hyphens are allowed."
            )

        # Check whitelist if configured
        if self.allowed_kids and kid not in self.allowed_kids:
            raise InvalidKeyIDError(
                f"Key ID (kid) '{kid}' is not in the allowed whitelist"
            )

        # Check key mapping if configured
        if self.key_mapping and kid not in self.key_mapping:
            raise InvalidKeyIDError(
                f"Key ID (kid) '{kid}' is not in the key mapping"
            )

        return True

    def _resolve_key_filename(self, kid: str) -> str:
        """
        Safely resolve the key filename from the kid value.

        If a key mapping exists, use the mapped filename.
        Otherwise, construct the filename safely.

        Args:
            kid: The validated key ID.

        Returns:
            The filename to use for the key.
        """
        if self.key_mapping:
            mapped_filename = self.key_mapping.get(kid)
            if mapped_filename is None:
                raise InvalidKeyIDError(f"No mapping found for kid: {kid}")
            # Validate the mapped filename as well
            if not ALLOWED_KID_PATTERN.match(mapped_filename):
                raise InvalidKeyIDError(
                    f"Mapped filename contains invalid characters: {mapped_filename}"
                )
            return mapped_filename

        return kid

    def get_secret_key(self, kid: str) -> bytes:
        """
        Safely retrieve the secret key from the filesystem.

        This method constructs the key file path safely to prevent path traversal:
        1. Validates the kid parameter.
        2. Resolves the filename (with optional mapping).
        3. Constructs the full path and verifies it's within the key directory.
        4. Reads the key file with size limits.

        Args:
            kid: The key ID used to locate the key file.

        Returns:
            The secret key as bytes.

        Raises:
            InvalidKeyIDError: If the kid is invalid.
            KeyNotFoundError: If the key file doesn't exist.
            JWTSecurityError: If a path traversal attempt is detected or read fails.
        """
        # Step 1: Validate the kid
        self.validate_kid(kid)

        # Step 2: Resolve the filename
        filename = self._resolve_key_filename(kid)

        # Step 3: Construct the full path safely
        key_file_path = (self.key_directory / filename).resolve()

        # Step 4: Verify the resolved path is within the key directory
        # This is the critical security check against path traversal
        try:
            key_file_path.relative_to(self.key_directory)
        except ValueError:
            raise JWTSecurityError(
                f"Path traversal detected: resolved path '{key_file_path}' "
                f"is outside the key directory '{