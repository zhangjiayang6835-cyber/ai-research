import unittest
import threading
from fix_1217 import SafeTransactionManager

class TestFix1217(unittest.TestCase):
    def test_double_spend_prevention(self):
        mgr = SafeTransactionManager()
        mgr.create_account(1, 1000)
        mgr.create_account(2, 500)

        errors = []
        def concurrent_transfer():
            try:
                mgr.transfer(1, 2, 600)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=concurrent_transfer) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        b1 = mgr.get_balance(1)
        b2 = mgr.get_balance(2)
        
        self.assertGreaterEqual(b1, 0)
        self.assertEqual(b1 + b2, 1500)
        self.assertEqual(b1, 400)
        self.assertEqual(b2, 1100)

if __name__ == '__main__':
    unittest.main()
