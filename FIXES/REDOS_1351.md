# Fix: ReDoS (Regular Expression Denial of Service) via User-Controlled Pattern

| Field | Value |
|-------|-------|
| Issue | [#1351](https://github.com/zhangjiayang6835-cyber/ai-research/issues/1351) |
| Bounty | $120 |
| Difficulty | Easy |
| Agent | chfr19820610-cell |
| Category | Security / Input Validation |

## Vulnerability

The search functionality accepted user-supplied strings that could be used as regex patterns. Without proper validation, an attacker could submit a malicious regex pattern (e.g., `(a+)+`, `(a*)*`, alternation-heavy patterns) that causes **catastrophic backtracking** — the regex engine consumes exponential CPU time, effectively a denial-of-service (ReDoS) attack.

**ReDoS attack example:**

```python
import re
re.search(r'(a+)+', "a" * 30 + "b")  # Exponential backtracking → hangs
```

A 30-character input to this pattern can trigger millions of backtracking steps, freezing the process.

## Fix Implementation

All changes applied to `src/search.py`:

### 1. Input Length Limit (`MAX_PATTERN_LENGTH = 500`)

Reject any query exceeding 500 characters with a constant-time empty response. This prevents attackers from sending large payloads.

### 2. Regex Pattern Validation (`_validate_regex_pattern`)

Detects dangerous patterns before compilation:

- **Nested quantifiers**: `(a+)+`, `(a*)*`, `(a{2,3})+`, `(\w+\.)+com` — quantifier applied to a group that already contains a quantified subpattern
- **Alternation loops**: `(a|b|c|d|e)+`, `(a|b|c|d|e|f)+` — many branches inside a quantified group
- **Deep nesting**: `(((((a)))))` — more than 5 levels of parenthesis nesting

### 3. Threading-Based Timeout (`_run_with_timeout`)

Two-stage timeout wrapping:

- **Compile timeout** (2s): `re.compile()` is run in a daemon thread; if it doesn't finish in 2 seconds the pattern is rejected
- **Execution timeout** (1s): Each `re.search()` call during `search_with_regex` is similarly wrapped

This ensures that even if static analysis misses a ReDoS vector, the regex engine cannot monopolize the process.

### 4. `search_with_regex` Method

A new method on `SecureSearchEngine` that performs regex-based searching with all the above protections. The existing `search()` method (substring matching) also gained the input length cap.

## Testing

See `tests/test_redos_fix.py` for comprehensive test coverage including:

- Safe patterns pass validation
- Nested quantifiers are rejected
- Alternation loops are rejected
- Deep nesting is rejected
- Empty/overly-long patterns are rejected
- `search_with_regex` works correctly with safe patterns
- `search_with_regex` rejects dangerous patterns
- Input length limit in `search()` method
