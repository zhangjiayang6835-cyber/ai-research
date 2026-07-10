"""
Stack Buffer Overflow via gets() → ROP Chain Fix
Bounty #793 ($200)
=========================================
Vulnerability: C program uses gets(buffer) with 64-byte buffer.
Attacker overwrites return address → ROP chain, bypasses NX/DEP + ASLR.

Fix: Replace gets() with fgets() + compiler protections + stack canary.
"""

C_FIX_CODE = r"""
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Secure buffer size */
#define BUFFER_SIZE 64
#define SAFE_READ_SIZE (BUFFER_SIZE - 1)

/* 
 * FIX 1: Replace gets() with fgets()
 * gets() has NO bounds checking → classic buffer overflow
 * fgets() limits to n-1 bytes + null terminates
 */
void secure_read(char *buffer, size_t size) {
    if (fgets(buffer, size, stdin) == NULL) {
        buffer[0] = '\0';
        return;
    }
    
    /* Remove trailing newline if present */
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
    }
}

/* FIX 2: Use snprintf() instead of sprintf() */
void secure_format(char *buffer, size_t size, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, size, fmt, args);
    va_end(args);
}

/* FIX 3: Input validation */
int validate_input(const char *input, size_t max_len) {
    if (input == NULL) return -1;
    if (strlen(input) >= max_len) return -1;
    
    /* Check for non-printable characters (potential exploit payload) */
    for (size_t i = 0; input[i] != '\0'; i++) {
        if (input[i] < 0x20 && input[i] != '\n' && input[i] != '\t') {
            return -1;  /* Suspicious non-printable character */
        }
    }
    return 0;
}

/* Secure version - no buffer overflow possible */
void secure_process_input(void) {
    char buffer[BUFFER_SIZE];
    
    printf("Enter data: ");
    secure_read(buffer, sizeof(buffer));
    
    if (validate_input(buffer, sizeof(buffer)) != 0) {
        printf("Error: Invalid input detected\n");
        return;
    }
    
    printf("Processed: %s\n", buffer);
}

/* 
 * COMPILER PROTECTIONS (compile with these flags):
 * 
 * gcc -o secure_app secure_app.c \
 *     -fstack-protector-strong \    # Stack canary
 *     -D_FORTIFY_SOURCE=2 \        # Runtime buffer checks
 *     -O2 \                         # Optimization
 *     -Wl,-z,relro \               # RELRO (GOT protection)
 *     -Wl,-z,now \                  # Full RELRO
 *     -Wl,-z,noexecstack \          # NX (non-executable stack)
 *     -pie -fPIE                    # ASLR (Position Independent Executable)
 * 
 * These flags:
 * -fstack-protector-strong → Stack canary (detects overflow)
 * -D_FORTIFY_SOURCE=2      → Runtime bounds checking
 * -Wl,-z,noexecstack        → Non-executable stack (NX/DEP)
 * -pie -fPIE               → ASLR compatibility
 * -Wl,-z,relro,-z,now       → Full RELRO (GOT overwrite protection)
 */

int main(void) {
    printf("=== Secure Input Processor ===\n");
    printf("Compiler protections enabled.\n");
    secure_process_input();
    return 0;
}
"""


class StackOverflowMitigationChecker:
    """
    Checks binary for stack overflow protections.
    """

    @staticmethod
    def check_binary(binary_path: str) -> dict:
        """Check if binary has security mitigations."""
        import subprocess

        result = {
            "nx": False,
            "pie": False,
            "relro": "none",
            "stack_canary": False,
            "fortify_source": False,
        }

        try:
            # Check with checksec (pwntools) or readelf
            output = subprocess.check_output(
                ["readelf", "-l", binary_path],
                stderr=subprocess.DEVNULL,
            ).decode()

            result["nx"] = "GNU_STACK" in output and "RWE" not in output
            result["pie"] = "DYNAMIC" in output

            # Check RELRO
            dyn_output = subprocess.check_output(
                ["readelf", "-d", binary_path],
                stderr=subprocess.DEVNULL,
            ).decode()
            result["relro"] = "BIND_NOW" if "BIND_NOW" in dyn_output else \
                              "partial" if "RELRO" in dyn_output else "none"

            # Check symbols for stack_chk
            sym_output = subprocess.check_output(
                ["readelf", "-s", binary_path],
                stderr=subprocess.DEVNULL,
            ).decode()
            result["stack_canary"] = "__stack_chk_fail" in sym_output

        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

        return result

    @staticmethod
    def generate_compile_command(source: str, output: str) -> str:
        """Generate secure compile command."""
        return (
            f"gcc -o {output} {source} "
            f"-fstack-protector-strong "
            f"-D_FORTIFY_SOURCE=2 "
            f"-O2 "
            f"-Wl,-z,relro "
            f"-Wl,-z,now "
            f"-Wl,-z,noexecstack "
            f"-pie -fPIE "
            f"-Wall -Werror"
        )


# ========== Usage Example ==========
if __name__ == "__main__":
    print("=== Stack Buffer Overflow Prevention ===")
    print()

    print("Vulnerable code:")
    print("  char buffer[64];")
    print("  gets(buffer);  // NO bounds check!")
    print("  → Attacker overwrites return address → ROP chain!")
    print()

    print("Fix 1: fgets() instead of gets()")
    print("  fgets(buffer, sizeof(buffer), stdin);")
    print()

    print("Fix 2: Compiler protections:")
    print("  -fstack-protector-strong  → Stack canary")
    print("  -D_FORTIFY_SOURCE=2       → Runtime bounds check")
    print("  -Wl,-z,noexecstack         → NX (non-executable stack)")
    print("  -pie -fPIE                 → ASLR")
    print("  -Wl,-z,relro,-z,now        → Full RELRO")
    print()

    print("Fix 3: Input validation")
    print("  Reject non-printable characters (potential exploits)")
    print()

    checker = StackOverflowMitigationChecker()
    cmd = checker.generate_compile_command("secure_app.c", "secure_app")
    print(f"Secure compile command:")
    print(f"  {cmd}")