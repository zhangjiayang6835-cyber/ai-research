# Race Condition in /tmp File Handling (TOCTOU)

## Description
Time-of-check to time-of-use race in temporary file handling. Code checks file properties then performs operations, but an attacker swaps the file (symlink attack) between check and use.

## Impact
Privilege escalation, arbitrary file write, denial of service.

## Remediation
Use mkstemp for atomic temp file creation, open files with O_NOFOLLOW to prevent symlink attacks, use atomic operations, avoid file-existence checks before opening.