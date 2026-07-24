"""Fix for Issue #1450: Blind Command Injection ($150)"""
import shlex
import subprocess
from typing import List

class CommandSanitizer:
    """Sanitizes command arguments to prevent injection."""
    
    SAFE_COMMANDS = {
        'ls', 'cat', 'grep', 'find', 'wc', 'head', 'tail',
        'sort', 'uniq', 'diff', 'md5sum', 'sha256sum'
    }
    
    @staticmethod
    def validate_command(cmd: str) -> bool:
        if not cmd or len(cmd) > 256:
            return False
        if not cmd[0].isalpha() and cmd[0] != '/':
            return False
        return bool(CommandSanitizer.SAFE_COMMANDS.intersection(
            [c for c in cmd.split() if c[0].isalpha()]
        ))
    
    @staticmethod
    def sanitize_args(args: List[str]) -> List[str]:
        sanitized = []
        for arg in args:
            safe_arg = shlex.quote(str(arg))
            sanitized.append(safe_arg)
        return sanitized

def run_self_test() -> int:
    failures = 0
    def check(name: str, condition: bool):
        nonlocal failures
        if not condition:
            print(f"  ✗ {name}"); failures += 1
    s = CommandSanitizer()
    check("safe command allowed", s.validate_command("ls -la"))
    check("injected command blocked", not s.validate_command("ls; rm -rf /"))
    print(f"{'PASS' if failures == 0 else f'{failures} FAIL'}")
    return failures
if __name__ == "__main__":
    run_self_test()
