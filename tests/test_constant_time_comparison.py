"""
Tests for constant-time comparison utilities.
"""

import unittest
import time

from src.constant_time_comparison import secure_compare, insecure_compare


class TestConstantTimeComparison(unittest.TestCase):
    
    def test_secure_compare_equal(self):
        """Test that secure_compare returns True for equal inputs."""
        self.assertTrue(secure_compare(b"secret", b"secret"))
    
    def test_secure_compare_different(self):
        """Test that secure_compare returns False for different inputs."""
        self.assertFalse(secure_compare(b"secret", b"public"))
    
    def test_secure_compare_different_lengths(self):
        """Test that secure_compare handles different length inputs."""
        self.assertFalse(secure_compare(b"secret", b"secre"))
    
    def test_secure_compare_empty(self):
        """Test that secure_compare handles empty inputs."""
        self.assertTrue(secure_compare(b"", b""))
        self.assertFalse(secure_compare(b"", b"x"))
    
    def test_secure_compare_timing(self):
        """Verify that secure_compare runs in constant time regardless of match position."""
        # This is a basic sanity check - real timing tests require statistical analysis
        secret = b"x" * 100
        similar = b"x" * 99 + b"y"
        different = b"y" + b"x" * 99
        
        # Run multiple times to get average timing
        def measure_time(a, b, iterations=10000):
            start = time.perf_counter()
            for _ in range(iterations):
                secure_compare(a, b)
            return time.perf_counter() - start
        
        # All cases should take roughly similar time
        t1 = measure_time(secret, secret)
        t2 = measure_time(secret, similar)
        t3 = measure_time(secret, different)
        
        # The timing difference should be minimal (within 50% of each other)
        max_time = max(t1, t2, t3)
        min_time = min(t1, t2, t3)
        self.assertLess(max_time / min_time, 2.0, "Timing difference too large - potential side channel")


if __name__ == '__main__':
    unittest.main()