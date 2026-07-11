"""
buffer_overflow_fix.py — Stack Buffer Overflow via gets() → ROP Chain Fix

漏洞背景:
- 使用gets()等不安全函数导致栈缓冲区溢出
- 攻击者可覆盖返回地址构造ROP链
- 修复需要: 使用安全函数 + 栈保护 + ASLR

本模块实现安全的C/C++代码编写指南和栈溢出防护。
"""

import re
from typing import List, Dict, Optional


class BufferOverflowError(Exception):
    """缓冲区溢出异常"""
    pass


UNSAFE_FUNCTIONS = frozenset({
    "gets", "strcpy", "strcat", "sprintf", "scanf",
    "sscanf", "fscanf", "vsprintf", "vscanf",
    "vsscanf", "vfscanf", "gets_s",
})

SAFE_ALTERNATIVES = {
    "gets": "fgets",
    "strcpy": "strncpy",
    "strcat": "strncat",
    "sprintf": "snprintf",
    "scanf": "fscanf with size limit",
}


class CodeSecurityScanner:
    """代码安全扫描器"""
    
    @staticmethod
    def scan_for_unsafe_functions(code: str) -> List[Dict]:
        """扫描不安全函数调用"""
        findings = []
        
        for line_num, line in enumerate(code.split("\n"), 1):
            for func in UNSAFE_FUNCTIONS:
                pattern = rf"\b{func}\s*\("
                if re.search(pattern, line):
                    safe_alt = SAFE_ALTERNATIVES.get(func, "unknown")
                    findings.append({
                        "line": line_num,
                        "function": func,
                        "safe_alternative": safe_alt,
                        "code": line.strip(),
                    })
        
        return findings


class StackProtection:
    """栈保护机制"""
    
    @staticmethod
    def enable_stack_canary() -> str:
        """启用栈金丝雀"""
        return "-fstack-protector-strong"
    
    @staticmethod
    def enable_aslr() -> str:
        """启用ASLR"""
        return "-pie -fPIE"
    
    @staticmethod
    def disable_exec_stack() -> str:
        """禁用可执行栈"""
        return "-z noexecstack"
    
    @staticmethod
    def get_secure_compiler_flags() -> List[str]:
        """获取安全编译选项"""
        return [
            "-fstack-protector-strong",
            "-fstack-clash-protection",
            "-D_FORTIFY_SOURCE=2",
            "-O2",
            "-Wl,-z,relro",
            "-Wl,-z,now",
            "-Wl,-z,noexecstack",
            "-pie",
            "-fPIE",
        ]


if __name__ == "__main__":
    scanner = CodeSecurityScanner()
    
    test_code = """
    char buf[64];
    gets(buf);  // unsafe
    strcpy(buf, user_input);  // unsafe
    snprintf(buf, sizeof(buf), "%s", user_input);  // safe
    """
    
    findings = scanner.scan_for_unsafe_functions(test_code)
    for f in findings:
        print(f"Line {f['line']}: {f['function']}() -> use {f['safe_alternative']}")
    
    print(f"\nSecure compiler flags: {' '.join(StackProtection.get_secure_compiler_flags())}")
    
    print("\nBuffer Overflow Protection:")
    print("- Unsafe function detection")
    print("- Stack canary protection")
    print("- ASLR/PIE support")
    print("- NX bit enforcement")
    print("- FORTIFY_SOURCE")
