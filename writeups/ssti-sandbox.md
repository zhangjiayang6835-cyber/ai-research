# SSTI in Email Template Engine

## Description
Email template engine processes user input without sanitization. Attacker injects template syntax to execute code. In Jinja2, attacker uses class attribute traversal to access subclasses and execute commands.

## Impact
Remote Code Execution, server-side file access, credential theft.

## Remediation
Use sandboxed template environments, never pass user input directly to template engine, validate input by stripping template syntax characters, use allowlists for template functions.