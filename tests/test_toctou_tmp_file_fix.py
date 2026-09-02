from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

import pytest

from fixes.toctou_tmp_file_fix import (
    SecureTempFile,
    ToctouSecurityError,
    create_named_lock,
    create_secure_temp_file,
    release_named_lock,
)


def test_create_secure_temp_file_writes_payload():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = create_secure_temp_file(b"job-payload", prefix="job_", directory=tmpdir)
        try:
            assert Path(path).read_bytes() == b"job-payload"
            assert path.startswith(tmpdir)
        finally:
            Path(path).unlink(missing_ok=True)


def test_secure_temp_file_has_owner_only_permissions():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = create_secure_temp_file(b"x", directory=tmpdir)
        try:
            mode = stat.S_IMODE(os.stat(path).st_mode)
            assert mode == stat.S_IRUSR | stat.S_IWUSR
            assert os.stat(path).st_uid == os.getuid()
        finally:
            Path(path).unlink(missing_ok=True)


def test_named_lock_is_exclusive():
    with tempfile.TemporaryDirectory() as tmpdir:
        lock_path = Path(tmpdir) / "app.lock"
        fd = create_named_lock(lock_path)
        try:
            with pytest.raises(FileExistsError, match="lock already exists"):
                create_named_lock(lock_path)
        finally:
            release_named_lock(lock_path, fd)


def test_named_lock_does_not_follow_existing_symlink():
    with tempfile.TemporaryDirectory() as tmpdir:
        victim = Path(tmpdir) / "victim.txt"
        victim.write_text("original", encoding="utf-8")
        lock_path = Path(tmpdir) / "app.lock"
        lock_path.symlink_to(victim)

        with pytest.raises(FileExistsError):
            create_named_lock(lock_path)

        assert victim.read_text(encoding="utf-8") == "original"


def test_secure_temp_file_context_manager_cleans_up():
    with tempfile.TemporaryDirectory() as tmpdir:
        with SecureTempFile(prefix="job_", directory=tmpdir) as handle:
            handle.write(b"done")
            created = handle.path
            assert created is not None
            assert Path(created).exists()

        assert created is not None
        assert not Path(created).exists()


def test_release_named_lock_allows_reacquire():
    with tempfile.TemporaryDirectory() as tmpdir:
        lock_path = Path(tmpdir) / "app.lock"
        fd = create_named_lock(lock_path)
        release_named_lock(lock_path, fd)

        fd2 = create_named_lock(lock_path)
        release_named_lock(lock_path, fd2)


def test_create_secure_temp_file_rejects_non_bytes():
    with pytest.raises(TypeError, match="data must be bytes"):
        create_secure_temp_file("not-bytes")  # type: ignore[arg-type]
