"""Fix for Issue #1446: Zip Slip Vulnerability ($150)"""
import os
from pathlib import Path

class ZipSlipPrevention:
    """Prevents zip slip directory traversal attacks."""
    
    ALLOWED_EXTENSIONS = {'.txt', '.py', '.js', '.css', '.html', '.json', '.md'}
    
    @staticmethod
    def is_safe_path(base_dir: str, target_path: str) -> bool:
        base = Path(base_dir).resolve()
        target = Path(target_path).resolve()
        try:
            target.relative_to(base)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_filename(filename: str) -> bool:
        if not filename or '..' in filename or filename.startswith('/'):
            return False
        ext = os.path.splitext(filename)[1].lower()
        return ext in ZipSlipPrevention.ALLOWED_EXTENSIONS
    
    @staticmethod
    def extract_safe_name(member_name: str) -> str:
        basename = os.path.basename(member_name)
        if not ZipSlipPrevention.validate_filename(basename):
            raise ValueError(f"Unsafe filename: {member_name}")
        return basename

def run_self_test() -> int:
    failures = 0
    def check(name: str, condition: bool):
        nonlocal failures
        if not condition:
            print(f"  ✗ {name}"); failures += 1
    z = ZipSlipPrevention()
    check("safe path accepted", z.is_safe_path("/tmp/extract", "/tmp/extract/file.txt"))
    check("traversal blocked", not z.is_safe_path("/tmp/extract", "/tmp/extract/../../etc/passwd"))
    check("unsafe filename rejected", not z.validate_filename("../evil.py"))
    print(f"{'PASS' if failures == 0 else f'{failures} FAIL'}")
    return failures
if __name__ == "__main__":
    run_self_test()
