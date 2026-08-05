import os
import unittest
import tempfile
import stat
import time
from fixes.bug_1503_fix import SecureTempFile, SecureFileLock

class TestBug1503Fix(unittest.TestCase):
    def test_secure_temp_file_creation_and_permissions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create secure temp file
            with SecureTempFile(prefix="test_toctou_", dir=tmpdir) as f:
                path = f.get_path()
                self.assertTrue(os.path.exists(path))
                
                # Check permissions (must be 0600)
                st = os.stat(path)
                mode = stat.S_IMODE(st.st_mode)
                self.assertEqual(mode, stat.S_IRUSR | stat.S_IWUSR)
                
                # Write and read data
                test_data = b"secure data content"
                f.write(test_data)
                
                read_data = f.read()
                self.assertEqual(read_data, test_data)
                
            # Verify file is deleted on exit
            self.assertFalse(os.path.exists(path))

    def test_secure_file_lock_mutual_exclusion(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            lock_path = os.path.join(tmpdir, "test.lock")
            lock1 = SecureFileLock(lock_path)
            lock2 = SecureFileLock(lock_path)
            
            # Lock 1 acquires successfully
            self.assertTrue(lock1.acquire(timeout=1.0))
            
            # Lock 2 fails to acquire since Lock 1 holds it
            self.assertFalse(lock2.acquire(timeout=0.1))
            
            # Release Lock 1
            lock1.release()
            
            # Lock 2 can now acquire successfully
            self.assertTrue(lock2.acquire(timeout=1.0))
            lock2.release()

if __name__ == "__main__":
    unittest.main()
