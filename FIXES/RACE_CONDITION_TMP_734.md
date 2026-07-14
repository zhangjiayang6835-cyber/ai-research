# Fix: Race Condition in /tmp File Handling (TOCTOU)

## Vulnerability

The script checks if `/tmp/lock` doesn't exist, then creates and writes data to it. Between the check and the creation, an attacker can replace the path with a symlink pointing to `/etc/passwd`, leading to arbitrary file write.

## Attack Vector

```python
# VULNERABLE: TOCTOU race condition
import os

lock_path = "/tmp/lock"
if not os.path.exists(lock_path):   # T1: check
    with open(lock_path, "w") as f:  # T2: use (attacker swaps /tmp/lock → /etc/passwd here)
        f.write("data")
```

## Fix Implementation

### 1. Atomic File Creation with O_EXCL
Use `os.open()` with `O_CREAT | O_EXCL` flags for atomic creation.

### 2. Secure Temporary Directory
Use `tempfile.mkstemp()` or a dedicated secure directory.

### 3. Strict File Permissions
Set file permissions to 0600 and verify file ownership.

## References
- CWE-367: TOCTOU Race Condition
- CWE-59: Improper Link Resolution Before File Access
