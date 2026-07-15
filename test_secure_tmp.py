"""
Tests for TOCTOU fix.
"""

import os
import tempfile
import secure_tmp


def test_secure_read_nonexistent():
    result = secure_tmp.secure_read_file("/tmp/nonexistent_file_12345")
    assert result is None


def test_secure_write_and_read():
    data = "test data 123"
    path = secure_tmp.secure_write_tmp(data)
    assert os.path.exists(path)
    
    result = secure_tmp.secure_read_file(path)
    assert result == data
    
    os.unlink(path)


def test_atomic_replace():
    src = tempfile.mktemp()
    dst = tempfile.mktemp()
    
    with open(src, 'w') as f:
        f.write("new content")
    
    secure_tmp.atomic_replace(src, dst)
    
    with open(dst, 'r') as f:
        assert f.read() == "new content"
    
    os.unlink(dst)