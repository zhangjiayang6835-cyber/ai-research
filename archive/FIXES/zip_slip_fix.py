"""
Fix for Issue #958 — Zip Slip → Arbitrary File Write via Archive Extraction $150
=================================================================================

Vulnerability
-------------
ZIP file extraction does not validate whether filenames contain `../`.
An attacker can create a ZIP file with entries like
`../../etc/cron.d/malicious` that overwrites system files.

Root Cause
----------
ZIP entries are extracted to the target directory without validating
that the resulting path stays within the intended extraction directory.

Fix Strategy
------------
1. Normalize all output paths using os.path.realpath/abspath.
2. Verify the extracted path is within the target directory.
3. Skip/reject entries containing `..` path traversal.
4. Validate filenames against a blocklist of sensitive paths.
5. Limit file size and total extraction size.

Acceptance Criteria
-------------------
- [x] Extraction path validated to be within target directory
- [x] Canonical path checking used
- [x] Entries with `..` rejected/skipped
- [x] Sensitive file paths blocked
- [x] File size limits enforced
"""

from __future__ import annotations

import logging
import os
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Configuration
# =============================================================================

# Maximum file size per entry (100 MB)
MAX_FILE_SIZE: int = 100 * 1024 * 1024

# Maximum total extraction size (500 MB)
MAX_TOTAL_SIZE: int = 500 * 1024 * 1024

# Maximum number of entries
MAX_ENTRIES: int = 10000

# Sensitive paths that should never be overwritten
SENSITIVE_PATHS: Set[str] = frozenset({
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/cron.d/", "/etc/crontab",
    "/etc/ld.so.preload", "/etc/ld.so.conf",
    "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/",
    "/boot/", "/dev/", "/proc/", "/sys/",
    "~/.ssh/", "~/.bashrc", "~/.bash_profile",
    "~/.profile", "~/.zshrc", "~/.config/",
})

# Dangerous file extensions
DANGEROUS_EXTENSIONS: Set[str] = frozenset({
    ".exe", ".dll", ".so", ".dylib", ".sh", ".bash",
    ".pyc", ".pyo", ".pyd",
})


# =============================================================================
# Path Validation
# =============================================================================

@dataclass
class PathValidationResult:
    """Result of path validation."""
    valid: bool
    safe_path: Optional[Path] = None
    error: Optional[str] = None


def validate_extraction_path(
    entry_path: str,
    target_dir: Path,
) -> PathValidationResult:
    """Validate that a ZIP entry path is safe for extraction.
    
    Checks:
    1. No path traversal (..)
    2. No absolute paths
    3. Resulting path is within target directory
    4. No symlink traversal
    
    Args:
        entry_path: The path from the ZIP entry.
        target_dir: The intended extraction directory.
    
    Returns:
        PathValidationResult with the safe resolved path.
    """
    if not entry_path:
        return PathValidationResult(valid=False, error="Empty entry path")
    
    # Resolve target directory
    try:
        target_dir = target_dir.resolve()
    except (OSError, ValueError):
        return PathValidationResult(valid=False, error="Invalid target directory")
    
    # Reject absolute paths in ZIP entries
    if os.path.isabs(entry_path):
        return PathValidationResult(
            valid=False,
            error=f"Absolute path rejected: {entry_path}",
        )
    
    # Normalize the entry path
    normalized = os.path.normpath(entry_path)
    
    # Check for path traversal
    if normalized.startswith("..") or "/.." in normalized:
        return PathValidationResult(
            valid=False,
            error=f"Path traversal detected: {entry_path}",
        )
    
    # Check for ".." in the raw path
    if ".." in entry_path.split("/"):
        return PathValidationResult(
            valid=False,
            error=f"Path traversal detected: {entry_path}",
        )
    
    # Build the full extraction path
    full_path = (target_dir / normalized).resolve()
    
    # Verify the resolved path is within the target directory
    try:
        full_path.relative_to(target_dir)
    except ValueError:
        return PathValidationResult(
            valid=False,
            error=f"Path escapes target directory: {entry_path}",
        )
    
    # Check for sensitive paths
    for sensitive in SENSITIVE_PATHS:
        if sensitive in str(full_path):
            return PathValidationResult(
                valid=False,
                error=f"Sensitive path blocked: {entry_path}",
            )
    
    return PathValidationResult(valid=True, safe_path=full_path)


# =============================================================================
# Secure ZIP Extraction
# =============================================================================

@dataclass
class ExtractionResult:
    """Result of ZIP extraction."""
    success: bool
    extracted_files: List[str] = field(default_factory=list)
    skipped_files: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    total_size: int = 0


class SecureZipExtractor:
    """Extracts ZIP archives safely, preventing Zip Slip attacks.
    
    Features:
    - Path traversal detection
    - Sensitive path blocking
    - File size limits
    - Total extraction size limits
    - Entry count limits
    """
    
    def __init__(self, target_dir: Optional[Path] = None):
        self.target_dir = Path(target_dir or os.getcwd())
    
    def extract(self, zip_path: Path) -> ExtractionResult:
        """Safely extract a ZIP archive.
        
        Args:
            zip_path: Path to the ZIP file.
        
        Returns:
            ExtractionResult with details of what was extracted.
        """
        result = ExtractionResult(success=False)
        
        if not zip_path.exists():
            result.success = False
            result.errors.append(f"ZIP file not found: {zip_path}")
            return result
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                # Check for potential issues
                for info in zf.infolist():
                    # Skip directories
                    if info.filename.endswith("/"):
                        continue
                    
                    # Validate path
                    path_result = validate_extraction_path(
                        info.filename, self.target_dir
                    )
                    
                    if not path_result.valid:
                        result.skipped_files.append(info.filename)
                        logger.warning(f"Skipped {info.filename}: {path_result.error}")
                        continue
                    
                    # Check file size
                    if info.file_size > MAX_FILE_SIZE:
                        result.skipped_files.append(info.filename)
                        logger.warning(f"Skipped {info.filename}: exceeds max file size")
                        continue
                    
                    # Check total size
                    if result.total_size + info.file_size > MAX_TOTAL_SIZE:
                        result.errors.append("Total extraction size limit reached")
                        break
                    
                    # Check entry count
                    if len(result.extracted_files) >= MAX_ENTRIES:
                        result.errors.append("Maximum entry count reached")
                        break
                    
                    # Safe to extract
                    safe_path = path_result.safe_path
                    if safe_path:
                        # Create parent directories
                        safe_path.parent.mkdir(parents=True, exist_ok=True)
                        
                        # Extract the file
                        try:
                            with zf.open(info.filename) as source:
                                with open(safe_path, 'wb') as target:
                                    # Read and write in chunks to avoid memory issues
                                    while True:
                                        chunk = source.read(8192)
                                        if not chunk:
                                            break
                                        target.write(chunk)
                            
                            result.extracted_files.append(info.filename)
                            result.total_size += info.file_size
                            
                        except (IOError, OSError) as e:
                            result.errors.append(f"Error extracting {info.filename}: {e}")
        
        except zipfile.BadZipFile:
            result.success = False
            result.errors.append("Invalid or corrupted ZIP file")
        except Exception as e:
            result.success = False
            result.errors.append(f"Extraction error: {e}")
        
        result.success = len(result.errors) == 0
        return result
    
    def extract_safe(self, zip_path: Path) -> ExtractionResult:
        """Extract with additional safety checks.
        
        Adds:
        - Symlink validation
        - Dangerous extension blocking
        """
        result = ExtractionResult(success=False)
        
        if not zip_path.exists():
            result.success = False
            result.errors.append(f"ZIP file not found: {zip_path}")
            return result
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                for info in zf.infolist():
                    if info.filename.endswith("/"):
                        continue
                    
                    # Check for symlinks
                    is_symlink = info.external_attr >> 16 & 0o120000  # S_IFLNK
                    if is_symlink:
                        result.skipped_files.append(info.filename)
                        logger.warning(f"Skipped symlink: {info.filename}")
                        continue
                    
                    # Check dangerous extensions
                    ext = os.path.splitext(info.filename)[1].lower()
                    if ext in DANGEROUS_EXTENSIONS:
                        result.skipped_files.append(info.filename)
                        logger.warning(f"Skipped dangerous file: {info.filename}")
                        continue
                    
                    # Standard path validation
                    path_result = validate_extraction_path(
                        info.filename, self.target_dir
                    )
                    
                    if not path_result.valid:
                        result.skipped_files.append(info.filename)
                        continue
                    
                    if info.file_size > MAX_FILE_SIZE:
                        result.skipped_files.append(info.filename)
                        continue
                    
                    if result.total_size + info.file_size > MAX_TOTAL_SIZE:
                        break
                    
                    if len(result.extracted_files) >= MAX_ENTRIES:
                        break
                    
                    safe_path = path_result.safe_path
                    if safe_path:
                        safe_path.parent.mkdir(parents=True, exist_ok=True)
                        with zf.open(info.filename) as source:
                            with open(safe_path, 'wb') as target:
                                shutil.copyfileobj(source, target)
                        
                        result.extracted_files.append(info.filename)
                        result.total_size += info.file_size
        
        except zipfile.BadZipFile:
            result.errors.append("Invalid or corrupted ZIP file")
        except Exception as e:
            result.errors.append(f"Extraction error: {e}")
        
        result.success = len(result.errors) == 0
        return result


# =============================================================================
# Self-Test
# =============================================================================

import shutil
import tempfile

def run_self_test() -> List[str]:
    """Run self-test to verify the fix works."""
    errors = []
    
    with tempfile.TemporaryDirectory() as tmpdir:
        target = Path(tmpdir) / "extract"
        target.mkdir()
        extractor = SecureZipExtractor(target)
        
        # Test 1: Normal file
        normal_zip = Path(tmpdir) / "normal.zip"
        with zipfile.ZipFile(normal_zip, 'w') as zf:
            zf.writestr("hello.txt", "Hello World")
        
        result = extractor.extract(normal_zip)
        assert result.success, "Test 1 failed: Normal extraction should succeed"
        assert "hello.txt" in result.extracted_files
        print("✓ Test 1: Normal file extracted safely")
        
        # Test 2: Path traversal in ZIP
        evil_zip = Path(tmpdir) / "evil.zip"
        with zipfile.ZipFile(evil_zip, 'w') as zf:
            zf.writestr("../../etc/passwd", "root:fake")
        
        result = extractor.extract(evil_zip)
        assert "../../etc/passwd" in result.skipped_files
        print("✓ Test 2: Path traversal blocked")
        
        # Test 3: Absolute path
        abs_zip = Path(tmpdir) / "abs.zip"
        with zipfile.ZipFile(abs_zip, 'w') as zf:
            zf.writestr("/etc/passwd", "root:fake")
        
        result = extractor.extract(abs_zip)
        assert "/etc/passwd" in result.skipped_files
        print("✓ Test 3: Absolute path rejected")
        
        # Test 4: Path validation
        result = validate_extraction_path("../escape.txt", target)
        assert not result.valid
        print("✓ Test 4: Path validation detects traversal")
        
        # Test 5: Normal path passes validation
        result = validate_extraction_path("data/file.txt", target)
        assert result.valid
        print("✓ Test 5: Normal path passes validation")
        
        # Test 6: Empty path rejected
        result = validate_extraction_path("", target)
        assert not result.valid
        print("✓ Test 6: Empty path rejected")
        
        # Test 7: Deeply nested path
        result = validate_extraction_path("a/b/c/../../../etc/passwd", target)
        assert not result.valid
        print("✓ Test 7: Deeply nested traversal detected")
    
    return errors


if __name__ == "__main__":
    errors = run_self_test()
    if errors:
        print(f"\nFAILED: {len(errors)} test(s) failed:")
        for e in errors:
            print(f"  - {e}")
    else:
        print("\nAll self-tests passed!")
