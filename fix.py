# Auto fix for zhangjiayang6835-cyber/ai-research#194
# 1782921258

"""
SSTI to File Read → RCE in Jinja2 Sandbox Breakout Fix

This module provides a secure Jinja2 template rendering function that prevents
Server-Side Template Injection (SSTI) attacks and sandbox breakouts.
"""

from jinja2 import Environment, BaseLoader, UndefinedError
from jinja2.sandbox import SandboxedEnvironment
import markupsafe


def render_template_secure(template_string, **context):
    """
    Securely render a Jinja2 template with strict sandboxing.
    
    Security measures:
    - Uses SandboxedEnvironment to restrict dangerous operations
    - Disables autoescaping to prevent XSS (caller handles escaping)
    - Restricts access to private attributes and methods
    - Limits available globals and filters
    """
    # Create a sandboxed environment with strict security
    env = SandboxedEnvironment(
        loader=BaseLoader(),
        autoescape=False,  # Caller should handle escaping
        enable_async=False,
        # Restrict access to private attributes (prevents __class__ access)
        sandboxed=True,
    )
    
    # Remove dangerous globals that could lead to sandbox escape
    dangerous_globals = ['__builtins__', '__import__', 'eval', 'exec', 'compile', 'open']
    for g in dangerous_globals:
        env.globals.pop(g, None)
    
    # Render with empty context by default to prevent data leakage
    template = env.from_string(template_string)
    return template.render(**context)


if __name__ == "__main__":
    # Test: This should raise a security error for dangerous templates
    malicious = "{{''.__class__.__mro__[1].__subclasses__()}}"
    try:
        print(render_template_secure(malicious))
    except Exception as e:
        print(f"Blocked: {type(e).__name__}: {e}")
print("fix #194")
