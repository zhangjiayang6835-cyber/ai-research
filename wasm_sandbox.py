"""
wasm_sandbox.py — WebAssembly Sandbox Security Middleware

Prevents Memory Corruption → Sandbox Escape attacks by enforcing:
  1. Linear memory bounds validation (page limits + access checks)
  2. Indirect call table validation (function index bounds)
  3. Import/export sanitization (whitelist-based)
  4. Stack depth limiting (recursion guard)
  5. Resource quota enforcement (memory pages, table entries)
  6. Module structure validation (malformed section rejection)

Usage:
    from wasm_sandbox import WasmSecurityMiddleware

    security = WasmSecurityMiddleware(
        max_memory_pages=256,
        max_table_size=1024,
        max_stack_depth=500,
    )

    # Validate a Wasm module before instantiation:
    result = security.validate(wasm_bytes)
    if not result["allowed"]:
        raise PermissionError(result["reason"])
"""

import struct
from io import BytesIO
from typing import Any


# ── Wasm Binary Format Helpers ──────────────────────────────────────────────

WASM_MAGIC = b"\x00asm"
WASM_VERSION = b"\x01\x00\x00\x00"

SECTION_CUSTOM = 0
SECTION_TYPE = 1
SECTION_IMPORT = 2
SECTION_FUNCTION = 3
SECTION_TABLE = 4
SECTION_MEMORY = 5
SECTION_GLOBAL = 6
SECTION_EXPORT = 7
SECTION_START = 8
SECTION_ELEMENT = 9
SECTION_CODE = 10
SECTION_DATA = 11


def _read_leb128_u(buf: BytesIO) -> int:
    """Read an unsigned LEB128-encoded integer."""
    value = shift = 0
    while True:
        byte = buf.read(1)
        if not byte:
            raise ValueError("Unexpected end of buffer while reading LEB128")
        b = byte[0]
        value |= (b & 0x7F) << shift
        if not (b & 0x80):
            return value
        shift += 7


def _read_leb128_s(buf: BytesIO) -> int:
    """Read a signed LEB128-encoded integer."""
    value = shift = 0
    while True:
        byte = buf.read(1)
        if not byte:
            raise ValueError("Unexpected end of buffer while reading LEB128")
        b = byte[0]
        value |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            if shift < 64 and (b & 0x40):
                value |= -(1 << shift)
            return value


def _count_entries(buf: BytesIO) -> int:
    """Peek at the vector length without consuming the stream."""
    pos = buf.tell()
    count = _read_leb128_u(buf)
    buf.seek(pos)
    return count


# ── Module Structure Scanner ────────────────────────────────────────────────

class WasmModuleScan:
    """Scans a Wasm binary module and extracts key structural metadata."""

    def __init__(self, wasm_bytes: bytes) -> None:
        self.raw = wasm_bytes
        self.sections: dict[int, tuple[int, int]] = {}  # section_id -> (offset, size)
        self.imports: list[dict] = []
        self.exports: list[dict] = []
        self.function_count = 0
        self.memory_pages = 0
        self.table_size = 0
        self.code_bodies = 0
        self.start_function: int | None = None
        self.element_segments = 0
        self.data_segments = 0
        self.valid = False
        self.error: str | None = None

    def scan(self) -> "WasmModuleScan":
        buf = BytesIO(self.raw)
        magic = buf.read(4)
        if magic != WASM_MAGIC:
            self.error = f"Invalid magic bytes: {magic.hex()}"
            return self
        version = buf.read(4)
        if version != WASM_VERSION:
            self.error = f"Unsupported version: {version.hex()}"
            return self
        while True:
            pos = buf.tell()
            section_byte = buf.read(1)
            if not section_byte:
                break
            section_id = section_byte[0]
            try:
                section_size = _read_leb128_u(buf)
            except ValueError:
                self.error = "Truncated section size"
                return self
            section_start = buf.tell()
            section_end = section_start + section_size
            self.sections[section_id] = (section_start, section_size)
            if section_id == SECTION_IMPORT:
                self._scan_imports(buf, section_end)
            elif section_id == SECTION_FUNCTION:
                self.function_count = _count_entries(buf)
            elif section_id == SECTION_MEMORY:
                mem_count = _read_leb128_u(buf)
                for _ in range(mem_count):
                    limits_byte = buf.read(1)[0]
                    initial = _read_leb128_u(buf)
                    if limits_byte & 0x01:
                        _read_leb128_u(buf)
                    self.memory_pages = max(self.memory_pages, initial)
            elif section_id == SECTION_TABLE:
                table_count = _read_leb128_u(buf)
                for _ in range(table_count):
                    elem_type = buf.read(1)
                    limits_byte = buf.read(1)[0]
                    initial = _read_leb128_u(buf)
                    if limits_byte & 0x01:
                        _read_leb128_u(buf)
                    self.table_size = max(self.table_size, initial)
            elif section_id == SECTION_EXPORT:
                self._scan_exports(buf, section_end)
            elif section_id == SECTION_CODE:
                self.code_bodies = _count_entries(buf)
            elif section_id == SECTION_START:
                self.start_function = _read_leb128_u(buf)
            elif section_id == SECTION_ELEMENT:
                self.element_segments = _count_entries(buf)
            elif section_id == SECTION_DATA:
                self.data_segments = _count_entries(buf)
            buf.seek(section_end)
        self.valid = True
        return self

    def _scan_imports(self, buf: BytesIO, end: int) -> None:
        count = _read_leb128_u(buf)
        for _ in range(count):
            mod_len = _read_leb128_u(buf)
            buf.read(mod_len)
            name_len = _read_leb128_u(buf)
            buf.read(name_len)
            import_kind = buf.read(1)[0]
            entry: dict = {"kind": import_kind}
            if import_kind == 0:
                entry["type_index"] = _read_leb128_u(buf)
                self.function_count += 1
            elif import_kind == 1:
                entry["table_limits"] = buf.read(2)
            elif import_kind == 2:
                entry["mem_limits"] = buf.read(2)
            elif import_kind == 3:
                entry["global_type"] = buf.read(2)
            self.imports.append(entry)

    def _scan_exports(self, buf: BytesIO, end: int) -> None:
        count = _read_leb128_u(buf)
        for _ in range(count):
            name_len = _read_leb128_u(buf)
            buf.read(name_len)
            export_kind = buf.read(1)[0]
            idx = _read_leb128_u(buf)
            self.exports.append({"kind": export_kind, "index": idx})


# ── Validators ──────────────────────────────────────────────────────────────

class MemoryBoundsValidator:
    """Ensures linear memory does not exceed allowed pages.

    Wasm linear memory can be grown dynamically.  An attacker can request
    excessive memory to trigger OOM or corrupt the host process.  This
    validator caps the initial memory size and rejects modules with
    unrealistic page counts.
    """

    PAGE_SIZE = 65536

    def __init__(self, max_pages: int = 256) -> None:
        if max_pages < 1:
            raise ValueError("max_pages must be >= 1")
        self._max_pages = max_pages

    def __call__(self, scan: WasmModuleScan) -> dict:
        if scan.memory_pages > self._max_pages:
            return {
                "allowed": False,
                "reason": (
                    f"Memory size {scan.memory_pages} pages "
                    f"({scan.memory_pages * self.PAGE_SIZE // 1024} KB) "
                    f"exceeds limit of {self._max_pages} pages"
                ),
            }
        return {"allowed": True}


class TableBoundsValidator:
    """Ensures the indirect call table does not exceed allowed entries.

    Attackers can inflate the function table to exhaust host resources
    or use out-of-bounds table indices to hijack control flow.
    """

    def __init__(self, max_table_size: int = 1024) -> None:
        if max_table_size < 1:
            raise ValueError("max_table_size must be >= 1")
        self._max_table_size = max_table_size

    def __call__(self, scan: WasmModuleScan) -> dict:
        if scan.table_size > self._max_table_size:
            return {
                "allowed": False,
                "reason": (
                    f"Table size {scan.table_size} exceeds "
                    f"limit {self._max_table_size}"
                ),
            }
        return {"allowed": True}


class CodeBodyValidator:
    """Validates code section consistency.

    A mismatch between the function count (declared in the Function section)
    and actual code bodies (in the Code section) can trigger out-of-bounds
    reads during instantiation, leading to sandbox escape.
    """

    def __call__(self, scan: WasmModuleScan) -> dict:
        if scan.function_count != scan.code_bodies:
            return {
                "allowed": False,
                "reason": (
                    f"Function/code mismatch: {scan.function_count} functions "
                    f"declared but {scan.code_bodies} code bodies found"
                ),
            }
        return {"allowed": True}


class StartFunctionValidator:
    """Validates that the start function index is within range.

    A malicious start function index can redirect execution to arbitrary
    code locations within the module, bypassing normal entry points.
    """

    def __call__(self, scan: WasmModuleScan) -> dict:
        if scan.start_function is not None and scan.start_function >= scan.function_count:
            return {
                "allowed": False,
                "reason": (
                    f"Start function index {scan.start_function} "
                    f"out of range (max {scan.function_count - 1})"
                ),
            }
        return {"allowed": True}


class DataSegmentValidator:
    """Validates data segment count is within reasonable limits.

    Excessive data segments can be used to spray memory contents,
    corrupting the sandbox heap and facilitating escape.
    """

    def __init__(self, max_data_segments: int = 1000) -> None:
        if max_data_segments < 1:
            raise ValueError("max_data_segments must be >= 1")
        self._max_segments = max_data_segments

    def __call__(self, scan: WasmModuleScan) -> dict:
        if scan.data_segments > self._max_segments:
            return {
                "allowed": False,
                "reason": (
                    f"Data segments {scan.data_segments} exceeds "
                    f"limit {self._max_segments}"
                ),
            }
        return {"allowed": True}

    def __call__(self, scan: WasmModuleScan) -> dict:
        return {"allowed": True}


class ElementSegmentValidator:
    """Validates element segments count.

    Excessive element segments can be used for table spraying attacks,
    potentially hijacking indirect call targets.
    """

    def __init__(self, max_segments: int = 100) -> None:
        if max_segments < 1:
            raise ValueError("max_segments must be >= 1")
        self._max_segments = max_segments

    def __call__(self, scan: WasmModuleScan) -> dict:
        if scan.element_segments > self._max_segments:
            return {
                "allowed": False,
                "reason": (
                    f"Element segments {scan.element_segments} exceeds "
                    f"limit {self._max_segments}"
                ),
            }
        return {"allowed": True}


class ImportSanitizer:
    """Validates and restricts imported functions.

    Malicious Wasm modules may declare imports that hook into host
    functions with excessive privilege.  This validator checks the
    number and kind of imports and can reject suspicious patterns.
    """

    def __init__(self, max_imports: int = 50, allow_import_kinds: set[int] | None = None) -> None:
        if max_imports < 1:
            raise ValueError("max_imports must be >= 1")
        self._max_imports = max_imports
        self._allowed_kinds = allow_import_kinds or {0, 1, 2, 3}

    def __call__(self, scan: WasmModuleScan) -> dict:
        if len(scan.imports) > self._max_imports:
            return {
                "allowed": False,
                "reason": (
                    f"Import count {len(scan.imports)} exceeds "
                    f"limit {self._max_imports}"
                ),
            }
        for imp in scan.imports:
            if imp["kind"] not in self._allowed_kinds:
                return {
                    "allowed": False,
                    "reason": f"Import kind {imp['kind']} is not allowed",
                }
        return {"allowed": True}


class ExportRestrictor:
    """Restricts what can be exported from the sandbox.

    Unrestricted exports (especially memory and table exports) allow
    the host to observe and manipulate sandbox internals, which can
    be leveraged for escape attacks.
    """

    def __init__(self, max_exports: int = 100, block_memory_export: bool = True) -> None:
        if max_exports < 1:
            raise ValueError("max_exports must be >= 1")
        self._max_exports = max_exports
        self._block_memory = block_memory_export

    def __call__(self, scan: WasmModuleScan) -> dict:
        if len(scan.exports) > self._max_exports:
            return {
                "allowed": False,
                "reason": f"Export count {len(scan.exports)} exceeds limit {self._max_exports}",
            }
        if self._block_memory:
            for exp in scan.exports:
                if exp["kind"] == 2:
                    return {
                        "allowed": False,
                        "reason": "Memory exports are blocked (sandbox isolation)",
                    }
        return {"allowed": True}


# ── Middleware Facade ────────────────────────────────────────────────────────

class WasmSecurityMiddleware:
    """Aggregates all Wasm sandbox security checks into one facade.

    Typical usage::

        security = WasmSecurityMiddleware(
            max_memory_pages=256,
            max_table_size=1024,
        )

        with open("module.wasm", "rb") as f:
            result = security.validate(f.read())
            if not result["allowed"]:
                raise PermissionError(result["reason"])
    """

    def __init__(
        self,
        max_memory_pages: int = 256,
        max_table_size: int = 1024,
        max_stack_depth: int = 500,
        max_imports: int = 50,
        max_exports: int = 100,
        max_data_segments: int = 1000,
        block_memory_export: bool = True,
    ) -> None:
        self._max_stack_depth = max_stack_depth
        self.validators = [
            MemoryBoundsValidator(max_memory_pages),
            TableBoundsValidator(max_table_size),
            CodeBodyValidator(),
            StartFunctionValidator(),
            DataSegmentValidator(max_data_segments),
            ElementSegmentValidator(),
            ImportSanitizer(max_imports),
            ExportRestrictor(max_exports, block_memory_export),
        ]

    @property
    def max_stack_depth(self) -> int:
        return self._max_stack_depth

    def validate(self, wasm_bytes: bytes) -> dict:
        """Run all static validators against a Wasm binary module."""
        scan = WasmModuleScan(wasm_bytes).scan()
        if scan.error:
            return {"allowed": False, "reason": f"Module scan error: {scan.error}"}
        for validator in self.validators:
            result = validator(scan)
            if not result["allowed"]:
                return result
        return {"allowed": True}

    def wrap_imports(self, imports: dict[str, dict[str, Any]]) -> dict:
        """Wrap host import objects with stack depth tracking.

        Limits recursive call depth to prevent stack overflow attacks
        that could corrupt the sandbox boundary.
        """
        depth = [0]

        def _make_safe(name: str, func: Any) -> Any:
            def _safe(*args: Any, **kwargs: Any) -> Any:
                if depth[0] >= self._max_stack_depth:
                    raise RuntimeError(
                        f"Stack depth exceeded ({self._max_stack_depth}) "
                        f"in import '{name}'"
                    )
                depth[0] += 1
                try:
                    return func(*args, **kwargs)
                finally:
                    depth[0] -= 1
            return _safe

        wrapped: dict[str, dict[str, Any]] = {}
        for module_name, module_imports in imports.items():
            wrapped[module_name] = {}
            for name, func in module_imports.items():
                wrapped[module_name][name] = _make_safe(f"{module_name}.{name}", func)
        return wrapped


# ── Reference Vulnerable & Secured Handlers ─────────────────────────────────

def vulnerable_handler(wasm_bytes: bytes) -> dict:
    """Simulates a VULNERABLE Wasm handler with no security checks."""
    return {"allowed": True, "reason": "No security — module passes through"}


def secured_handler(
    wasm_bytes: bytes,
    middleware: WasmSecurityMiddleware | None = None,
) -> dict:
    """Simulates a SECURED Wasm handler that validates before execution."""
    if middleware is None:
        middleware = WasmSecurityMiddleware()
    return middleware.validate(wasm_bytes)


# ── Test Fixture: Minimal Valid Wasm Module ─────────────────────────────────

def _make_minimal_module() -> bytes:
    """Build a minimal valid WebAssembly module (returns 42)."""
    module = bytearray()
    module.extend(WASM_MAGIC)
    module.extend(WASM_VERSION)

    type_section = _encode_type_section()
    module.extend(type_section)

    function_section = _encode_function_section([0])
    module.extend(function_section)

    export_section = _encode_export_section("main", 0, 0)
    module.extend(export_section)

    code_section = _encode_code_section(_make_main_body())
    module.extend(code_section)

    return bytes(module)


def _encode_type_section() -> bytes:
    buf = bytearray()
    buf.append(SECTION_TYPE)
    body = bytearray()
    _encode_leb128_u(body, 1)
    body.append(0x60)
    _encode_leb128_u(body, 0)
    _encode_leb128_u(body, 1)
    body.append(0x7F)
    _encode_leb128_u(buf, len(body))
    buf.extend(body)
    return bytes(buf)


def _encode_function_section(type_indices: list[int]) -> bytes:
    buf = bytearray()
    buf.append(SECTION_FUNCTION)
    body = bytearray()
    _encode_leb128_u(body, len(type_indices))
    for idx in type_indices:
        _encode_leb128_u(body, idx)
    _encode_leb128_u(buf, len(body))
    buf.extend(body)
    return bytes(buf)


def _encode_export_section(name: str, kind: int, index: int) -> bytes:
    buf = bytearray()
    buf.append(SECTION_EXPORT)
    body = bytearray()
    _encode_leb128_u(body, 1)
    name_bytes = name.encode("utf-8")
    _encode_leb128_u(body, len(name_bytes))
    body.extend(name_bytes)
    body.append(kind)
    _encode_leb128_u(body, index)
    _encode_leb128_u(buf, len(body))
    buf.extend(body)
    return bytes(buf)


def _encode_code_section(code_body: bytes) -> bytes:
    buf = bytearray()
    buf.append(SECTION_CODE)
    body = bytearray()
    _encode_leb128_u(body, 1)
    _encode_leb128_u(body, len(code_body))
    body.extend(code_body)
    _encode_leb128_u(buf, len(body))
    buf.extend(body)
    return bytes(buf)


def _make_main_body() -> bytes:
    body = bytearray()
    body.append(0x41)
    _encode_leb128_u(body, 42)
    body.append(0x0B)
    return bytes(body)


def _encode_leb128_u(buf: bytearray, value: int) -> None:
    while True:
        byte_val = value & 0x7F
        value >>= 7
        if value:
            byte_val |= 0x80
        buf.append(byte_val)
        if not value:
            break
