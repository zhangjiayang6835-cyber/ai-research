# Fix: SSTI in Email Template Engine → Sandbox Escape

## Vulnerability
Email template engine uses user input directly: Hello {{user_input}}. Server uses Jinja2 Sandbox. Attacker can escape sandbox via __class__.__mro__[1].__subclasses__() chain to achieve RCE.

## Fix Implementation
1. Do not expose template engine to users
2. Use precompiled templates with variable substitution only
3. Disable __class__, __mro__, __subclasses__ access

## References
- CWE-1336: Improper Neutralization of Special Elements used in a Template Engine
- CWE-94: Improper Control of Generation of Code
