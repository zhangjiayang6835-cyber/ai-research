import unittest
from decimal import Decimal

from fixes.defi_reentrancy_withdraw_fix import (
    InsufficientFunds,
    InvalidAmount,
    ReentrancyBlocked,
    SafeWithdrawVault,
    VulnerableWithdrawVault,
)


class SafeWithdrawVaultTests(unittest.TestCase):
    def test_vulnerable_pattern_allows_double_transfer(self) -> None:
        vault = VulnerableWithdrawVault()
        vault.deposit("attacker", "100")
        transfers = []
        reentered = False

        def malicious_transfer(account: str, amount: Decimal) -> None:
            nonlocal reentered
            transfers.append((account, amount))
            if not reentered:
                reentered = True
                vault.withdraw("attacker", "100", malicious_transfer)

        vault.withdraw("attacker", "100", malicious_transfer)

        self.assertEqual(transfers, [
            ("attacker", Decimal("100")),
            ("attacker", Decimal("100")),
        ])
        self.assertEqual(vault.balance_of("attacker"), Decimal("0"))

    def test_safe_vault_blocks_reentrant_withdraw(self) -> None:
        vault = SafeWithdrawVault()
        vault.deposit("attacker", "100")
        transfers = []
        blocked = []

        def malicious_transfer(account: str, amount: Decimal) -> None:
            transfers.append((account, amount))
            try:
                vault.withdraw("attacker", "100", malicious_transfer)
            except ReentrancyBlocked as exc:
                blocked.append(str(exc))

        vault.withdraw("attacker", "100", malicious_transfer)

        self.assertEqual(transfers, [("attacker", Decimal("100"))])
        self.assertEqual(blocked, ["reentrant withdraw blocked"])
        self.assertEqual(vault.balance_of("attacker"), Decimal("0"))

    def test_balance_is_debited_before_external_transfer(self) -> None:
        vault = SafeWithdrawVault()
        vault.deposit("alice", "100")
        observed_balance = []

        def transfer(account: str, _amount: Decimal) -> None:
            observed_balance.append(vault.balance_of(account))

        vault.withdraw("alice", "30", transfer)

        self.assertEqual(observed_balance, [Decimal("70")])
        self.assertEqual(vault.balance_of("alice"), Decimal("70"))

    def test_failed_transfer_rolls_back_balance_and_releases_lock(self) -> None:
        vault = SafeWithdrawVault()
        vault.deposit("alice", "100")

        def failing_transfer(_account: str, _amount: Decimal) -> None:
            raise RuntimeError("payment provider failed")

        with self.assertRaises(RuntimeError):
            vault.withdraw("alice", "50", failing_transfer)

        self.assertEqual(vault.balance_of("alice"), Decimal("100"))
        vault.withdraw("alice", "25", lambda _account, _amount: None)
        self.assertEqual(vault.balance_of("alice"), Decimal("75"))

    def test_cross_account_reentrancy_is_blocked(self) -> None:
        vault = SafeWithdrawVault()
        vault.deposit("attacker", "100")
        vault.deposit("victim", "100")
        blocked = []

        def malicious_transfer(_account: str, _amount: Decimal) -> None:
            try:
                vault.withdraw("victim", "100", lambda _a, _m: None)
            except ReentrancyBlocked as exc:
                blocked.append(str(exc))

        vault.withdraw("attacker", "100", malicious_transfer)

        self.assertEqual(blocked, ["reentrant withdraw blocked"])
        self.assertEqual(vault.balance_of("attacker"), Decimal("0"))
        self.assertEqual(vault.balance_of("victim"), Decimal("100"))

    def test_rejects_invalid_amounts(self) -> None:
        vault = SafeWithdrawVault()

        for bad in ("0", "-1", "NaN", "Infinity", True, "not-a-number"):
            with self.subTest(amount=bad):
                with self.assertRaises(InvalidAmount):
                    vault.deposit("alice", bad)

    def test_rejects_insufficient_funds_without_mutation(self) -> None:
        vault = SafeWithdrawVault()
        vault.deposit("alice", "10")

        with self.assertRaises(InsufficientFunds):
            vault.withdraw("alice", "11", lambda _account, _amount: None)

        self.assertEqual(vault.balance_of("alice"), Decimal("10"))

    def test_transfer_must_be_callable(self) -> None:
        vault = SafeWithdrawVault()
        vault.deposit("alice", "10")

        with self.assertRaises(TypeError):
            vault.withdraw("alice", "1", None)  # type: ignore[arg-type]

        self.assertEqual(vault.balance_of("alice"), Decimal("10"))


if __name__ == "__main__":
    unittest.main()
