Based on the issue description about "Blind RCE via Server-Side Template Injection in Sandboxed Env", I need to identify the relevant files in this repository. The issue mentions a sandboxed environment with template injection vulnerability. Looking at the repo structure, the `eval-engine` directory likely contains the sandbox execution code, and there are existing fix files like `fix-sidecar-injection.py` and `fix-ssrf-aws-metadata.py`.

Let me examine the existing fix files and the eval-engine to understand the pattern and create a proper fix for SSTI (Server-Side Template Injection).

The issue is about Blind RCE via SSTI in a sandboxed environment. I'll create a fix that:
1. Sanitizes template inputs to prevent SSTI
2. Uses a safe templating approach that doesn't allow arbitrary code execution
3. Implements proper sandboxing for template rendering

Let me check the existing fix files for patterns:

```diff
--- /dev/null
+++ b/fix-ssti-sandbox.py
@@ -0,0 +1,178 @@
+#!/usr/bin/env python3
+"""
+Fix: Blind RCE via Server-Side Template Injection in Sandboxed Environment
+
+This module provides a secure template rendering solution that prevents
+Server-Side Template Injection (SSTI) attacks by:
+1. Using a restricted sandboxed Jinja2 environment
+2. Stripping dangerous constructs from user-supplied templates
+3. Implementing strict input validation
+4. Using AST-based template parsing to detect malicious patterns
+"""
+
+import re
+import ast
+import string
+from typing import Any, Dict, Optional, Set
+
+# ---------------------------------------------------------------------------
+# Safe Template Engine using Python's string.Template (no code execution)
+# ---------------------------------------------------------------------------
+
+class SafeTemplateEngine:
+    """
+    A secure template engine that uses Python's built-in string.Template
+    for simple variable substitution WITHOUT any code execution capability.
+    
+    Unlike Jinja2, Django templates, or other full-featured template engines,
+    string.Template only supports $variable substitution and does NOT allow:
+    - Arbitrary Python code execution
+    - Object attribute traversal
+    - Function calls
+    - Import statements
+    - Control flow (loops, conditionals)
+    """
+    
+    # Allowed variable name pattern: alphanumeric + underscore only
+    ALLOWED_VARIABLE_PATTERN = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')
+    
+    # Maximum template length to prevent DoS
+    MAX_TEMPLATE_LENGTH = 10000
+    
+    # Maximum number of substitutions
+    MAX_SUBSTITUTIONS = 100
+    
+    def __init__(self):
+        self._safe_vars: Dict[str, str] = {}
+    
+    def set_variable(self, name: str, value: Any) -> None:
+        """Set a safe variable for template substitution."""
+        if not self.ALLOWED_VARIABLE_PATTERN.match(name):
+            raise ValueError(f"Invalid variable name: {name}")
+        # Convert all values to strings to prevent object injection
+        self._safe_vars[name] = str(value)
+    
+    def render(self, template: str) -> str:
+        """
+        Safely render a template by substituting variables.
+        Uses string.Template which has NO code execution capability.
+        """
+        if len(template) > self.MAX_TEMPLATE_LENGTH:
+            raise ValueError("Template exceeds maximum allowed length")
+        
+        # Count substitutions to prevent DoS
+        substitution_count = template.count('$')
+        if substitution_count > self.MAX_SUBSTITUTIONS:
+            raise ValueError("Too many substitutions in template")
+        
+        # Use string.Template with safe substitution (leaves invalid
+        # placeholders as-is instead of raising errors that could leak info)
+        tmpl = string.Template(template)
+        try:
+            result = tmpl.safe_substitute(self._safe_vars)
+        except Exception as e:
+            raise ValueError(f"Template rendering error: {type(e).__name__}")
+        
+        return result
+
+
+# ---------------------------------------------------------------------------
+# Jinja2 Sandbox (if Jinja2 must be used)
+# ---------------------------------------------------------------------------
+
+class Jinja2SandboxedEnvironment:
+    """
+    A heavily restricted Jinja2 environment that prevents SSTI/RCE.
+    
+    Security measures:
+    1. Disabled all built-in functions and imports
+    2. Removed access to __builtins__, __class__, __bases__, __subclasses__
+    3. Blocked attribute traversal beyond first level
+    4. Disabled all filters except safe ones (upper, lower, title, etc.)
+    5. No access to request, config, or any global objects
+    6. AST-based pre-scanning for malicious patterns
+    """
+    
+    # Dangerous patterns to detect in templates BEFORE rendering
+    DANGEROUS_PATTERNS = [
+        # Python code execution
+        r'\b__builtins__\b',
+        r'\b__class__\b',
+        r'\b__bases__\b',
+        r'\b__subclasses__\b',
+        r'\b__mro__\b',
+        r'\b__globals__\b',
+        r'\b__dict__\b',
+        r'\b__import__\b',
+        r'\bimport\s+\w+',
+        r'\bexec\b',
+        r'\beval\b',
+        r'\bcompile\b',
+        r'\bopen\b',
+        r'\bfile\b',
+        r'\bgetattr\b',
+        r'\bsetattr\b',
+        r'\bdelattr\b',
+        r'\bchr\b',
+        r'\bord\b',
+        
+        # Object traversal chains
+        r'\.__\w+__',
+        r'\._\w+',  # Private attributes
+        
+        # Common SSTI payloads
+        r'\{\{.*\.__\w+__.*\}\}',
+        r'\{\%.*import.*\%\}',
+        r'\{\%.*exec.*\%\}',
+        r'\{\{.*request\b.*\}\}',
+        r'\{\{.*config\b.*\}\}',
+        r'\{\{.*self\b.*\}\}',
+        r'\{\{.*lipsum\b.*\}\}',
+        r'\{\{.*cycler\b.*\}\}',
+        r'\{\{.*joiner\b.*\}\}',
+        r'\{\{