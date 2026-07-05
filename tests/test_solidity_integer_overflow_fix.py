import unittest

from fixes.solidity_integer_overflow_fix import (
    UINT256_MAX,
    ArithmeticSafetyError,
    SecureTokenLedger,
    safe_add,
    safe_sub,
    validate_solidity_token_source,
    vulnerable_uint256_add,
)


class SolidityIntegerOverflowFixTests(unittest.TestCase):
    def test_vulnerable_wraparound_is_blocked_by_safe_add(self):
        self.assertEqual(vulnerable_uint256_add(UINT256_MAX, 1), 0)

        with self.assertRaises(ArithmeticSafetyError):
            safe_add(UINT256_MAX, 1)

    def test_safe_sub_blocks_underflow(self):
        with self.assertRaises(ArithmeticSafetyError):
            safe_sub(0, 1)

    def test_transfer_preserves_balances_and_total_supply(self):
        ledger = SecureTokenLedger(cap=100, balances={"alice": 10, "bob": 5}, total_supply=15)

        ledger.transfer("alice", "bob", 4)

        self.assertEqual(ledger.balance_of("alice"), 6)
        self.assertEqual(ledger.balance_of("bob"), 9)
        self.assertEqual(ledger.total_supply, 15)

    def test_transfer_rejects_token_theft_underflow(self):
        ledger = SecureTokenLedger(cap=100, balances={"alice": 3, "attacker": 0}, total_supply=3)

        with self.assertRaises(ArithmeticSafetyError):
            ledger.transfer("alice", "attacker", 4)

        self.assertEqual(ledger.balance_of("alice"), 3)
        self.assertEqual(ledger.balance_of("attacker"), 0)

    def test_constructor_rejects_overflowed_supply_state(self):
        with self.assertRaises(ArithmeticSafetyError):
            SecureTokenLedger(
                cap=UINT256_MAX,
                balances={"alice": 1, "bob": UINT256_MAX},
                total_supply=UINT256_MAX + 1,
            )

    def test_mint_rejects_supply_cap_overflow(self):
        ledger = SecureTokenLedger(cap=10, balances={"alice": 9}, total_supply=9)

        with self.assertRaises(ArithmeticSafetyError):
            ledger.mint("alice", 2)

        self.assertEqual(ledger.total_supply, 9)
        self.assertEqual(ledger.balance_of("alice"), 9)

    def test_solidity_source_checker_accepts_checked_transfer(self):
        source = """
        pragma solidity ^0.8.20;
        contract SecureToken {
            mapping(address => uint256) private balances;
            function transfer(address to, uint256 amount) external returns (bool) {
                require(balances[msg.sender] >= amount, "insufficient balance");
                balances[msg.sender] -= amount;
                balances[to] += amount;
                return true;
            }
        }
        """

        self.assertEqual(validate_solidity_token_source(source), [])

    def test_solidity_source_checker_flags_legacy_unchecked_transfer(self):
        source = """
        pragma solidity ^0.7.6;
        contract VulnerableToken {
            mapping(address => uint256) private balances;
            function transfer(address to, uint256 amount) external returns (bool) {
                unchecked {
                    balances[msg.sender] -= amount;
                    balances[to] += amount;
                }
                return true;
            }
        }
        """

        findings = validate_solidity_token_source(source)

        self.assertIn("Solidity pragma must require compiler >=0.8.0", findings)
        self.assertIn("unchecked blocks must not wrap token arithmetic", findings)
        self.assertIn("transfer must check sender balance before subtraction", findings)

    def test_solidity_source_checker_rejects_upper_bound_only_pragma(self):
        source = """
        pragma solidity <0.8.0;
        contract LegacyToken {
            mapping(address => uint256) private balances;
            function transfer(address to, uint256 amount) external returns (bool) {
                require(balances[msg.sender] >= amount, "insufficient balance");
                balances[msg.sender] -= amount;
                balances[to] += amount;
                return true;
            }
        }
        """

        self.assertIn(
            "Solidity pragma must require compiler >=0.8.0",
            validate_solidity_token_source(source),
        )


if __name__ == "__main__":
    unittest.main()
