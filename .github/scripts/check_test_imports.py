"""Compile only the modules the test suite actually imports.

`python -m compileall fixes src` fails on pre-existing broken files in those
directories, which makes the check useless as a signal: it reports failures that
have nothing to do with the change under test. What matters here is whether the
modules under test can be parsed at all — if one of them has a syntax error,
pytest would otherwise fail with a confusing collection error instead of a clear
one.

So: read the `from fixes...` / `from src...` imports out of tests/, resolve each
to a file, and compile just those.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
IMPORT_RE = re.compile(r"^\s*from\s+((?:fixes|src)(?:\.[A-Za-z_][\w]*)*)\s+import\b", re.M)


def modules_under_test():
    """Every fixes.* / src.* module named in a test's import statements."""
    names = set()
    for test in (ROOT / "tests").glob("test_*.py"):
        text = test.read_text(encoding="utf-8", errors="replace")
        names.update(IMPORT_RE.findall(text))
    return sorted(names)


def main() -> int:
    names = modules_under_test()
    if not names:
        print("no fixes.* or src.* imports found in tests/ — nothing to check")
        return 0

    missing, broken, ok = [], [], 0
    for name in names:
        path = ROOT.joinpath(*name.split("."))
        candidate = path.with_suffix(".py")
        package_init = path / "__init__.py"

        if candidate.is_file():
            source_path = candidate
        elif package_init.is_file():
            source_path = package_init
        else:
            missing.append(name)
            continue

        source = source_path.read_text(encoding="utf-8", errors="replace")
        try:
            compile(source, str(source_path), "exec")
            ok += 1
        except SyntaxError as exc:
            broken.append((name, source_path, exc))

    print(f"checked {len(names)} module(s) imported by tests: {ok} ok, "
          f"{len(broken)} broken, {len(missing)} missing")

    for name, path, exc in broken:
        rel = path.relative_to(ROOT)
        print(f"\nSyntaxError in {rel} (imported as {name}):")
        print(f"  line {exc.lineno}: {exc.text.rstrip() if exc.text else ''}")
        print(f"  {exc.msg}")

    if missing:
        print("\nimported by a test but no module file found:")
        for name in missing:
            print(f"  {name}")

    return 1 if broken or missing else 0


if __name__ == "__main__":
    sys.exit(main())
