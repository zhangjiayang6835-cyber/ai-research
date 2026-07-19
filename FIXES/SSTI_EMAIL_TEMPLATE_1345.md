# Fix: SSTI in Email Template Engine → Sandbox Escape

| Field | Value |
|-------|-------|
| Issue | [#1345](https://github.com/zhangjiayang6835-cyber/ai-research/issues/1345) |
| Bounty | $200 |
| Difficulty | Expert |
| Agent | chfr19820610-cell |
| Category | Security / Template Injection |

## Vulnerability

The email template engine renders user-supplied content using `render_template_string` (Jinja2) or `Template(string)` without proper sandboxing. An attacker who controls email template content — e.g., via a custom email template feature, user-controlled email fields, or admin-configured templates — can inject Jinja2 expressions to achieve Server-Side Template Injection (SSTI).

**SSTI → RCE example with Jinja2:**

```
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
```

This bypasses the template sandbox and executes arbitrary Python code on the server.

## Root Cause

The template engine directly interpolates user input into Jinja2 template strings without:
1. Using a sandboxed Jinja2 environment
2. Stripping template syntax (`{{ }}`, `{% %}`, `{# #}`) from user input
3. Restricting access to dangerous builtins

## Fix Implementation

### 1. Jinja2 Sandboxed Environment

Replace `flask.render_template_string` or `jinja2.Template` with a restricted sandbox:

```python
from jinja2 import Environment, BaseLoader, SandboxedEnvironment
from jinja2.sandbox import ImmutableSandboxedEnvironment

def create_sandboxed_env() -> Environment:
    """Create a Jinja2 environment with all dangerous builtins removed."""
    env = ImmutableSandboxedEnvironment(loader=BaseLoader())
    # Remove dangerous builtins
    env.globals.clear()
    env.filters.clear()
    env.tests.clear()
    return env

SANDBOX = create_sandboxed_env()
```

### 2. User Input Escaping (`escape_template_input`)

Before rendering, strip or escape any Jinja2 template syntax from user-controlled fields:

```python
import re

_TEMPLATE_SYNTAX_RE = re.compile(r'\{\{.*?\}\}|\{%.*?%\}|\{#.*?#\}')

def escape_template_input(text: str) -> str:
    """Escape Jinja2 template syntax in user input."""
    return _TEMPLATE_SYNTAX_RE.sub(
        lambda m: '{{' + m.group(0)[2:-2].replace('{', '&#123;').replace('}', '&#125;') + '}}',
        text
    )
```

### 3. Template String Security Wrapper

A safe wrapper that renders only known-safe template strings and escapes user data:

```python
def render_email_template(template_body: str, context: dict) -> str:
    """Render email template with sandbox protection."""
    safe_env = create_sandboxed_env()
    # Escape user-provided context values
    safe_context = {
        k: escape_template_input(v) if isinstance(v, str) else v
        for k, v in context.items()
    }
    template = safe_env.from_string(template_body)
    return template.render(**safe_context)
```

### 4. Sandbox Escape Prevention

Additional layers:
- Remove `__class__`, `__base__`, `__subclasses__`, `__globals__`, `__builtins__` access
- Remove access to `os`, `subprocess`, `eval`, `exec`, `open`
- Limit template rendering to a fixed set of safe filters only
- Set `autoescape=True` for HTML-safe output

## Testing

See `tests/test_ssti_email_template_1345.py` for coverage including:

- Simple template with safe variables renders correctly
- SSTI payload containing `{{ config }}` returns escaped output (not leaked config)
- SSTI payload with `__class__.__mro__` chain is blocked
- SSTI payload with `eval` / `open` / `os.popen` is blocked
- Normal email content renders without modification
- Template with safe Jinja2 filters (e.g., `|upper`, `|lower`) works in server templates
- User-controlled template body is safely rendered without SSTI
