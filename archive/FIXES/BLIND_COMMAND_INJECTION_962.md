# Fix: Blind Command Injection via Email Header

## Vulnerability
Email sending function passes user-supplied Subject directly to sendmail: sendmail -s "{subject}" {email}. Attackers inject ;id > /tmp/out in the Subject to execute arbitrary commands.

## Fix Implementation
1. Use email library API instead of shell commands
2. Sanitize all email header inputs
3. Escape shell special characters

## References
- CWE-78: Improper Neutralization of Special Elements used in an OS Command
- CWE-88: Argument Injection or Modification
