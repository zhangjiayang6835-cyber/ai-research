"""
Tests for wasm_sandbox.py — validates that all security layers
correctly block WebAssembly Memory Corruption → Sandbox Escape attacks.
"""

import pytest

from wasm_sandbox import (
    CodeBodyValidator,
    DataSegmentValidator,
    ElementSegmentValidator,
    ExportRestrictor,
    ImportSanitizer,
    MemoryBoundsValidator,
    StartFunctionValidator,
    TableBoundsValidator,
    WasmModuleScan,
    WasmSecurityMiddleware,
    secured_handler,
    vulnerable_handler,
    _make_minimal_module,
)

# ── Helpers ──────────────────────────────────────────────────────────────────


def _leb128_bytes(value: int) -> bytes:
    """Encode an integer as unsigned LEB128."""
    buf = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            b |= 0x80
        buf.append(b)
        if not value:
            break
    return bytes(buf)


def _enc_section(section_id: int, body: bytes) -> bytes:
    buf = bytearray()
    buf.append(section_id)
    buf.extend(_leb128_bytes(len(body)))
    buf.extend(body)
    return bytes(buf)


def _vec(items: list[bytes]) -> bytes:
    buf = bytearray()
    buf.extend(_leb128_bytes(len(items)))
    for item in items:
        buf.extend(item)
    return bytes(buf)


def _enc_functype(param_count: int, result_types: list[int]) -> bytes:
    buf = bytearray([0x60])
    buf.extend(_leb128_bytes(param_count))
    for _ in range(param_count):
        buf.append(0x7F)
    buf.extend(_leb128_bytes(len(result_types)))
    for r in result_types:
        buf.append(r)
    return bytes(buf)


def _mem_type(pages: int) -> bytes:
    return bytes([0x00]) + _leb128_bytes(pages)


def _table_type(size: int) -> bytes:
    return bytes([0x70, 0x00]) + _leb128_bytes(size)


def _enc_export(name: str, kind: int, index: int) -> bytes:
    name_bytes = name.encode()
    buf = bytearray()
    buf.extend(_leb128_bytes(len(name_bytes)))
    buf.extend(name_bytes)
    buf.append(kind)
    buf.extend(_leb128_bytes(index))
    return bytes(buf)


def _main_body() -> bytes:
    return bytes([0x41]) + _leb128_bytes(42) + bytes([0x0B])


def _make_module(sections: list[tuple[int, bytes]]) -> bytes:
    module = bytearray(b"\x00asm\x01\x00\x00\x00")
    for sid, body in sections:
        module.extend(_enc_section(sid, body))
    return bytes(module)


def _make_memory_module(pages: int = 1) -> bytes:
    return _make_module([
        (1, _vec([_enc_functype(0, [])])),
        (3, _vec([_leb128_bytes(0)])),
        (5, _vec([_mem_type(pages)])),
        (7, _vec([_enc_export("main", 0, 0)])),
        (10, _vec([_main_body()])),
    ])


def _make_table_module(size: int = 1) -> bytes:
    return _make_module([
        (1, _vec([_enc_functype(0, [])])),
        (3, _vec([_leb128_bytes(0)])),
        (4, _vec([_table_type(size)])),
        (7, _vec([_enc_export("main", 0, 0)])),
        (10, _vec([_main_body()])),
    ])


def _make_import_module(import_count: int = 1) -> bytes:
    imp_body = bytearray()
    imp_body.extend(_leb128_bytes(import_count))
    for _ in range(import_count):
        name = b"env"
        imp_body.extend(_leb128_bytes(len(name)))
        imp_body.extend(name)
        fname = b"print"
        imp_body.extend(_leb128_bytes(len(fname)))
        imp_body.extend(fname)
        imp_body.append(0)
        imp_body.extend(_leb128_bytes(0))
    return _make_module([
        (1, _vec([_enc_functype(0, [0x7F])])),
        (2, bytes(imp_body)),
        (3, _vec([_leb128_bytes(0)])),
        (7, _vec([_enc_export("main", 0, 0)])),
        (10, _vec([_main_body()])),
    ])


# ── 1. Module Scan Tests ────────────────────────────────────────────────────


class TestModuleScan:
    def test_valid_minimal_module(self):
        scan = WasmModuleScan(_make_minimal_module()).scan()
        assert scan.valid is True
        assert scan.error is None

    def test_invalid_magic(self):
        scan = WasmModuleScan(b"\x00\x00\x00\x00" + b"\x01\x00\x00\x00").scan()
        assert scan.valid is False
        assert scan.error is not None

    def test_invalid_version(self):
        scan = WasmModuleScan(b"\x00asm\xff\xff\xff\xff").scan()
        assert scan.valid is False
        assert scan.error is not None

    def test_truncated_module(self):
        scan = WasmModuleScan(b"\x00asm\x01\x00\x00\x00\x01").scan()
        assert scan.valid is False
        assert scan.error is not None

    def test_memory_scan(self):
        module = _make_memory_module(pages=64)
        scan = WasmModuleScan(module).scan()
        assert scan.memory_pages == 64

    def test_table_scan(self):
        module = _make_table_module(size=128)
        scan = WasmModuleScan(module).scan()
        assert scan.table_size == 128

    def test_import_scan(self):
        module = _make_import_module(import_count=3)
        scan = WasmModuleScan(module).scan()
        assert len(scan.imports) == 3
        assert scan.imports[0]["kind"] == 0

    def test_function_code_consistency(self):
        module = _make_minimal_module()
        scan = WasmModuleScan(module).scan()
        assert scan.function_count == scan.code_bodies


# ── 2. Memory Bounds Tests ──────────────────────────────────────────────────


class TestMemoryBounds:
    def test_reasonable_memory_allowed(self):
        module = _make_memory_module(pages=64)
        scan = WasmModuleScan(module).scan()
        result = MemoryBoundsValidator(max_pages=256)(scan)
        assert result["allowed"] is True

    def test_excessive_memory_rejected(self):
        module = _make_memory_module(pages=512)
        scan = WasmModuleScan(module).scan()
        result = MemoryBoundsValidator(max_pages=256)(scan)
        assert result["allowed"] is False
        assert "Memory size" in result["reason"]

    def test_no_memory_allowed(self):
        module = _make_minimal_module()
        scan = WasmModuleScan(module).scan()
        result = MemoryBoundsValidator()(scan)
        assert result["allowed"] is True


# ── 3. Table Bounds Tests ───────────────────────────────────────────────────


class TestTableBounds:
    def test_reasonable_table_allowed(self):
        module = _make_table_module(size=64)
        scan = WasmModuleScan(module).scan()
        result = TableBoundsValidator(max_table_size=1024)(scan)
        assert result["allowed"] is True

    def test_excessive_table_rejected(self):
        module = _make_table_module(size=99999)
        scan = WasmModuleScan(module).scan()
        result = TableBoundsValidator(max_table_size=1024)(scan)
        assert result["allowed"] is False
        assert "Table size" in result["reason"]

    def test_no_table_allowed(self):
        module = _make_minimal_module()
        scan = WasmModuleScan(module).scan()
        result = TableBoundsValidator()(scan)
        assert result["allowed"] is True


# ── 4. Code Body Consistency ────────────────────────────────────────────────


class TestCodeBody:
    def test_matching_ok(self):
        module = _make_minimal_module()
        scan = WasmModuleScan(module).scan()
        result = CodeBodyValidator()(scan)
        assert result["allowed"] is True


# ── 5. Start Function Tests ─────────────────────────────────────────────────


class TestStartFunction:
    def test_no_start_function_ok(self):
        scan = WasmModuleScan(_make_minimal_module()).scan()
        result = StartFunctionValidator()(scan)
        assert result["allowed"] is True


# ── 6. Import Sanitization Tests ────────────────────────────────────────────


class TestImportSanitizer:
    def test_normal_imports_allowed(self):
        scan = WasmModuleScan(_make_import_module(5)).scan()
        result = ImportSanitizer(max_imports=50)(scan)
        assert result["allowed"] is True

    def test_excessive_imports_rejected(self):
        scan = WasmModuleScan(_make_import_module(100)).scan()
        result = ImportSanitizer(max_imports=50)(scan)
        assert result["allowed"] is False
        assert "Import count" in result["reason"]

    def test_no_imports_ok(self):
        scan = WasmModuleScan(_make_minimal_module()).scan()
        result = ImportSanitizer()(scan)
        assert result["allowed"] is True


# ── 7. Export Restriction Tests ──────────────────────────────────────────────


class TestExportRestrictor:
    def test_normal_exports_allowed(self):
        module = _make_minimal_module()
        scan = WasmModuleScan(module).scan()
        result = ExportRestrictor(max_exports=100)(scan)
        assert result["allowed"] is True

    def test_invalid_max_exports(self):
        with pytest.raises(ValueError):
            ExportRestrictor(max_exports=0)


# ── 8. Integration Tests — Full Middleware ──────────────────────────────────


class TestMiddleware:
    def test_valid_module_passes(self):
        mw = WasmSecurityMiddleware()
        module = _make_minimal_module()
        result = mw.validate(module)
        assert result["allowed"] is True

    def test_vulnerable_handler_allows_everything(self):
        result = vulnerable_handler(b"anything goes here")
        assert result["allowed"] is True

    def test_secured_handler_passes_valid(self):
        result = secured_handler(_make_minimal_module())
        assert result["allowed"] is True

    def test_secured_handler_rejects_large_memory(self):
        module = _make_memory_module(pages=9999)
        mw = WasmSecurityMiddleware(max_memory_pages=256)
        result = mw.validate(module)
        assert result["allowed"] is False

    def test_secured_handler_rejects_large_table(self):
        module = _make_table_module(size=99999)
        mw = WasmSecurityMiddleware(max_table_size=1024)
        result = mw.validate(module)
        assert result["allowed"] is False

    def test_secured_handler_rejects_too_many_imports(self):
        module = _make_import_module(100)
        mw = WasmSecurityMiddleware(max_imports=50)
        result = mw.validate(module)
        assert result["allowed"] is False

    def test_secured_handler_rejects_invalid_magic(self):
        mw = WasmSecurityMiddleware()
        result = mw.validate(b"\x00\x00\x00\x00\x01\x00\x00\x00")
        assert result["allowed"] is False
        assert "Module scan error" in result["reason"]

    def test_stack_depth_tracking(self):
        mw = WasmSecurityMiddleware(max_stack_depth=5)
        assert mw.max_stack_depth == 5

    def test_import_wrapping_safe_call_works(self):
        mw = WasmSecurityMiddleware()
        wrapped = mw.wrap_imports({"env": {"add": lambda a, b: a + b}})
        result = wrapped["env"]["add"](2, 3)
        assert result == 5

    def test_secured_handler_small_memory_rejected(self):
        mw = WasmSecurityMiddleware(max_memory_pages=1)
        module = _make_memory_module(pages=2)
        result = mw.validate(module)
        assert result["allowed"] is False

    def test_malformed_truncated_rejected(self):
        mw = WasmSecurityMiddleware()
        result = mw.validate(b"\x00asm\x01\x00\x00\x00\x01")
        assert result["allowed"] is False


# ── 9. Edge Cases ──────────────────────────────────────────────────────────


class TestEdgeCases:
    def test_empty_bytes(self):
        mw = WasmSecurityMiddleware()
        result = mw.validate(b"")
        assert result["allowed"] is False

    def test_very_small_module(self):
        mw = WasmSecurityMiddleware()
        result = mw.validate(b"\x00asm")
        assert result["allowed"] is False

    def test_invalid_config_values(self):
        with pytest.raises(ValueError):
            MemoryBoundsValidator(max_pages=0)
        with pytest.raises(ValueError):
            TableBoundsValidator(max_table_size=0)
        with pytest.raises(ValueError):
            ImportSanitizer(max_imports=0)
        with pytest.raises(ValueError):
            ExportRestrictor(max_exports=0)
        with pytest.raises(ValueError):
            DataSegmentValidator(max_data_segments=0)

    def test_minimal_module_is_valid(self):
        module = _make_minimal_module()
        mw = WasmSecurityMiddleware()
        result = mw.validate(module)
        assert result["allowed"] is True

    def test_import_wrapping_does_not_block_normal_calls(self):
        mw = WasmSecurityMiddleware(max_stack_depth=3)

        def normal(a, b):
            return a + b

        wrapped = mw.wrap_imports({"env": {"normal": normal}})
        assert wrapped["env"]["normal"](1, 2) == 3
