"""
Secure Template Renderer Module

Fixes SSTI to File Read → RCE in Jinja2 Sandbox Breakout vulnerability.
Provides hardened template rendering with multiple layers of protection.
"""

from jinja2 import Environment, BaseLoader, UndefinedError, TemplateSyntaxError
from jinja2.sandbox import SandboxedEnvironment
import re


class SecureTemplateRenderer:
    """
    A secure template renderer that prevents SSTI and sandbox breakouts.
    """
    
    # Dangerous patterns that indicate SSTI attempts
    DANGEROUS_PATTERNS = [
        r'__\w+__',           # dunder methods: __class__, __bases__, etc.
        r'__\w+\.',           # dunder attribute access
        r'__import__',        # import function
        r'eval\s*\(',         # eval() calls
        r'exec\s*\(',         # exec() calls
        r'compile\s*\(',      # compile() calls
        r'open\s*\(',         # open() calls
        r'os\.',              # os module access
        r'subprocess\.',      # subprocess module access
        r'import\s+',         # import statements
    ]
    
    def __init__(self, allow_dunder=False):
        self.allow_dunder = allow_dunder
        self.env = self._create_secure_environment()
    
    def _create_secure_environment(self):
        """Create a hardened Jinja2 environment."""
        env = SandboxedEnvironment(
            loader=BaseLoader(),
            autoescape=True,
            enable_async=False,
            # Block access to private attributes
            sandboxed=True,
        )
        
        # Remove all potentially dangerous globals
        dangerous = [
            '__builtins__', '__import__', 'eval', 'exec', 
            'compile', 'open', 'input', 'raw_input',
            'reload', 'help', 'dir', 'vars', 'locals', 'globals'
        ]
        for name in dangerous:
            env.globals.pop(name, None)
        
        return env
    
    def _check_template(self, template_string):
        """Pre-flight security check on template source."""
        if self.allow_dunder:
            return
        
        for pattern in self.DANGEROUS_PATTERNS:
            if re.search(pattern, template_string):
                raise SecurityError(
                    f"Potentially dangerous template pattern detected: {pattern}"
                )
    
    def render(self, template_string, **context):
        """
        Securely render a template with the given context.
        
        Args:
            template_string: The template source to render
            **context: Variables to make available in the template
            
        Returns:
            str: The rendered template
            
        Raises:
            SecurityError: If dangerous patterns are detected
        """
        self._check_template(template_string)
        template = self.env.from_string(template_string)
        return template.render(**context)


class SecurityError(Exception):
    """Raised when a security violation is detected in template processing."""
    pass


# Convenience function for simple use cases
def render_secure(template_string, **context):
    """Render a template securely with default settings."""
    renderer = SecureTemplateRenderer()
    return renderer.render(template_string, **context)