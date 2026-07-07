"""Regression tests for issue #200 distributed transaction double spending."""

from __future__ import annotations

import unittest
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from threading import Barrier

from fixes.distributed_double_spend_fix import (
    Account,
    DistributedLedger,
    DoubleSpendGuardError,
    vulnerable_transfer_without_lock,
)


class DistributedDoubleSpendFixTests(unittest.TestCase):
    def test_vulnerable_snapshot_flow_double_spends_under_race(self) -> None:
        accounts = {
            "alice": Account("alice", 100),
            "bob": Account("bob", 0),
            "carol": Account("carol", 0),
        }
        barrier = Barrier(2)

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(
                vulnerable_transfer_without_lock,
                accounts,
                source_id="alice",
                destination_id="bob",
                amount=60,
                race_barrier=barrier,
            )
            second = pool.submit(
                vulnerable_transfer_without_lock,
                accounts,
                source_id="alice",
                destination_id="carol",
                amount=60,
                race_barrier=barrier,
            )

        self.assertTrue(first.result())
        self.assertTrue(second.result())
        self.assertEqual(accounts["alice"].balance, 40)
        self.assertEqual(accounts["bob"].balance + accounts["carol"].balance, 120)

    def test_guarded_ledger_allows_only_one_concurrent_spend(self) -> None:
        accounts = {
            "alice": Account("alice", 100),
            "bob": Account("bob", 0),
            "carol": Account("carol", 0),
        }
        ledger = DistributedLedger(accounts)
        barrier = Barrier(2)

        def spend(destination: str, key: str):
            barrier.wait()
            return ledger.transfer(
                idempotency_key=key,
                source_id="alice",
                destination_id=destination,
                amount=60,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(spend, "bob", "spend-bob"),
                pool.submit(spend, "carol", "spend-carol"),
            ]

        successes = []
        failures = []
        for future in futures:
            try:
                successes.append(future.result())
            except DoubleSpendGuardError as exc:
                failures.append(str(exc))

        self.assertEqual(len(successes), 1)
        self.assertEqual(failures, ["insufficient funds"])
        self.assertEqual(accounts["alice"].balance, 40)
        self.assertEqual(accounts["bob"].balance + accounts["carol"].balance, 60)
        self.assertEqual(sum(account.balance for account in accounts.values()), 100)

    def test_idempotent_retry_returns_original_result_without_second_debit(self) -> None:
        accounts = {
            "alice": Account("alice", 100),
            "bob": Account("bob", 0),
        }
        ledger = DistributedLedger(accounts)

        first = ledger.transfer(
            idempotency_key="txn-1",
            source_id="alice",
            destination_id="bob",
            amount=25,
            expected_source_version=0,
        )
        second = ledger.transfer(
            idempotency_key="txn-1",
            source_id="alice",
            destination_id="bob",
            amount=25,
            expected_source_version=0,
        )

        self.assertEqual(first, second)
        self.assertEqual(accounts["alice"].balance, 75)
        self.assertEqual(accounts["bob"].balance, 25)
        self.assertEqual(accounts["alice"].version, 1)

    def test_conflicting_idempotency_key_reuse_is_rejected(self) -> None:
        accounts = {
            "alice": Account("alice", 100),
            "bob": Account("bob", 0),
            "carol": Account("carol", 0),
        }
        ledger = DistributedLedger(accounts)
        ledger.transfer(
            idempotency_key="txn-conflict",
            source_id="alice",
            destination_id="bob",
            amount=10,
        )

        with self.assertRaisesRegex(DoubleSpendGuardError, "reused"):
            ledger.transfer(
                idempotency_key="txn-conflict",
                source_id="alice",
                destination_id="carol",
                amount=10,
            )

    def test_stale_version_is_rejected_before_debit(self) -> None:
        accounts = {
            "alice": Account("alice", 100, version=3),
            "bob": Account("bob", 0),
        }
        ledger = DistributedLedger(accounts)

        with self.assertRaisesRegex(DoubleSpendGuardError, "stale source"):
            ledger.transfer(
                idempotency_key="txn-stale",
                source_id="alice",
                destination_id="bob",
                amount=10,
                expected_source_version=2,
            )

        self.assertEqual(accounts["alice"].balance, 100)
        self.assertEqual(accounts["bob"].balance, 0)

    def test_opposing_transfers_do_not_deadlock(self) -> None:
        accounts = {
            "alice": Account("alice", 100),
            "bob": Account("bob", 100),
        }
        ledger = DistributedLedger(accounts)
        barrier = Barrier(2)

        def transfer(source: str, destination: str, key: str):
            barrier.wait()
            return ledger.transfer(
                idempotency_key=key,
                source_id=source,
                destination_id=destination,
                amount=20,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(transfer, "alice", "bob", "a-to-b")
            second = pool.submit(transfer, "bob", "alice", "b-to-a")

        self.assertEqual(first.result().amount, 20)
        self.assertEqual(second.result().amount, 20)
        self.assertEqual(accounts["alice"].balance, 100)
        self.assertEqual(accounts["bob"].balance, 100)

    def test_invalid_amounts_are_rejected(self) -> None:
        ledger = DistributedLedger({"alice": Account("alice", 100), "bob": Account("bob", 0)})

        for amount in (0, -1, True, "10", Decimal("1.5")):
            with self.subTest(amount=amount):
                with self.assertRaises(DoubleSpendGuardError):
                    ledger.transfer(
                        idempotency_key=f"bad-{amount}",
                        source_id="alice",
                        destination_id="bob",
                        amount=amount,  # type: ignore[arg-type]
                    )


if __name__ == "__main__":
    unittest.main()
