"""
Fix for Issue — Race Condition in Distributed Transaction -> Double Spend
=========================================================================

Vulnerability
-------------
The payment system performed "check balance -> deduct -> confirm" as three
separate, non-atomic steps:

    balance = db.get_balance(account_id)          # 1. check
    if balance >= amount:
        db.set_balance(account_id, balance - amt)  # 2. deduct
        db.confirm(transaction_id)                 # 3. confirm

An attacker sends many concurrent requests for the same account. Because the
read (step 1) and the write (step 2) are not atomic, multiple concurrent
requests can all read the same starting balance, all pass the check, and all
write a deduction -- draining the account far below zero (double spend).

Root cause: no transactional boundary around the read-check-write sequence,
no row-level lock serializing concurrent writers, and no server-side
invariant ("balance must never go negative") enforced at write time.

Fix strategy
------------
1. **Database transaction + row-level lock**: the entire
   check -> deduct -> confirm sequence executes inside a single transaction
   that acquires an exclusive row-level lock on the account
   (``SELECT ... FOR UPDATE`` semantics). Concurrent requests against the
   same account serialize instead of racing; only one transaction can hold
   the lock at a time.
2. **Optimistic-lock version number**: the ``Account`` model carries a
   monotonically increasing ``version`` column. Every update is conditioned
   on the version last read (``UPDATE ... WHERE id = ? AND version = ?``).
   If another transaction already mutated the row, the version will have
   moved and the update is rejected/retried -- defense in depth even across
   separate DB connections/replicas where the row lock alone might not be
   visible.
3. **Post-deduction negative-balance check**: after computing the new
   balance and before committing, the transaction verifies
   ``new_balance >= 0``. If not, the whole transaction is rolled back and
   the debit is rejected -- this is the last line of defense even if the
   lock/version protections were somehow bypassed.
4. Bounded retry on optimistic-lock conflicts so transient contention
   degrades gracefully instead of corrupting state or hanging.

The module below is dependency-free (uses only ``threading`` + ``dataclasses``)
and simulates a relational store with row-level locking and optimistic
versioning so it can be exercised and unit-tested without a real database.
The same transaction shape maps directly onto SQL:

    BEGIN;
    SELECT balance, version FROM accounts WHERE id = :id FOR UPDATE;
    -- application checks balance >= amount
    UPDATE accounts
       SET balance = balance - :amount, version = version + 1
     WHERE id = :id AND version = :expected_version AND balance - :amount >= 0;
    -- if affected rows == 0 -> conflict/insufficient funds, ROLLBACK + retry/reject
    COMMIT;
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Dict


class InsufficientFundsError(RuntimeError):
    """Raised when a debit would drive the account balance negative."""


class OptimisticLockError(RuntimeError):
    """Raised when the account's version changed between read and write."""


class AccountNotFoundError(RuntimeError):
    """Raised when the referenced account does not exist."""


@dataclass
class Account:
    """Account model with an optimistic-lock ``version`` column.

    ``version`` increments on every successful mutation. Callers must supply
    the version they last read; a stale version means another transaction
    already modified the row and the caller must re-read and retry.
    """

    id: str
    balance: int  # smallest currency unit (e.g. cents) to avoid float issues
    version: int = 0
    # Per-account lock simulates a database row-level lock (SELECT ... FOR UPDATE).
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)


class AccountStore:
    """In-memory stand-in for the accounts table.

    Provides transactional debit semantics: row-level lock + optimistic
    version check + post-deduction negative-balance guard, all inside a
    single critical section per account (the transactional boundary).
    """

    def __init__(self) -> None:
        self._accounts: Dict[str, Account] = {}
        self._table_lock = threading.Lock()  # guards the accounts dict itself

    def create_account(self, account_id: str, balance: int) -> Account:
        with self._table_lock:
            account = Account(id=account_id, balance=balance, version=0)
            self._accounts[account_id] = account
            return account

    def get_account_snapshot(self, account_id: str) -> Account:
        """Read-only snapshot (balance/version) for callers that need to
        display current state. NOT used for the transactional debit path."""
        with self._table_lock:
            account = self._accounts.get(account_id)
        if account is None:
            raise AccountNotFoundError(f"account {account_id!r} not found")
        return account

    def debit(self, account_id: str, amount: int, *, expected_version: int | None = None) -> Account:
        """Atomically debit ``amount`` from the account.

        Implements: BEGIN TRANSACTION -> SELECT ... FOR UPDATE ->
        check balance -> UPDATE (guarded by version + non-negative balance)
        -> COMMIT, all inside the account's row-level lock.

        Raises:
            AccountNotFoundError: unknown account.
            OptimisticLockError: ``expected_version`` was supplied and does
                not match the current row version (row was mutated by
                another transaction between read and write).
            InsufficientFundsError: the debit would make the balance
                negative.
        """
        if amount <= 0:
            raise ValueError("amount must be positive")

        with self._table_lock:
            account = self._accounts.get(account_id)
        if account is None:
            raise AccountNotFoundError(f"account {account_id!r} not found")

        # --- BEGIN TRANSACTION -------------------------------------------------
        # Row-level lock: only one concurrent transaction may read+write this
        # account's balance/version at a time. This is the direct analogue of
        # `SELECT balance, version FROM accounts WHERE id = ? FOR UPDATE`.
        with account._lock:
            # Optimistic-lock check: if the caller read a version and it no
            # longer matches, another committed transaction already changed
            # this row -- reject so the caller can re-read and retry.
            if expected_version is not None and account.version != expected_version:
                raise OptimisticLockError(
                    f"version mismatch for account {account_id!r}: "
                    f"expected {expected_version}, found {account.version}"
                )

            new_balance = account.balance - amount

            # Post-deduction negative-balance check: never commit a debit
            # that would leave the account negative, regardless of what the
            # pre-check believed.
            if new_balance < 0:
                # ROLLBACK -- no mutation has happened, state is untouched.
                raise InsufficientFundsError(
                    f"debit of {amount} would leave account {account_id!r} "
                    f"negative (balance={account.balance})"
                )

            # COMMIT: apply the deduction and bump the optimistic-lock version.
            account.balance = new_balance
            account.version += 1
            return account
        # --- END TRANSACTION -----------------------------------------------

    def debit_with_retry(
        self,
        account_id: str,
        amount: int,
        *,
        max_retries: int = 3,
    ) -> Account:
        """Convenience wrapper: read current version, attempt debit, retry a
        bounded number of times on optimistic-lock conflicts.

        This mirrors the typical application-level retry loop used with a
        real database when an ``UPDATE ... WHERE version = ?`` affects zero
        rows because of a concurrent writer.
        """
        last_error: Exception | None = None
        for _ in range(max_retries):
            snapshot = self.get_account_snapshot(account_id)
            try:
                return self.debit(account_id, amount, expected_version=snapshot.version)
            except OptimisticLockError as exc:
                last_error = exc
                continue
        assert last_error is not None
        raise last_error


# ---------------------------------------------------------------------------
# Example of the vulnerable ('before') vs. patched ('after') handler shape.
# ---------------------------------------------------------------------------


def process_payment_vulnerable(store: AccountStore, account_id: str, amount: int) -> bool:
    """DO NOT USE -- kept only to document/reproduce the original bug in tests.

    Reproduces the non-atomic check -> deduct -> confirm race by reading the
    balance, sleeping-equivalent (context switch window), then writing
    without any lock or version guard.
    """
    account = store.get_account_snapshot(account_id)  # step 1: check (unlocked read)
    if account.balance >= amount:  # window where other threads can race here
        account.balance -= amount  # step 2: deduct (unsynchronized write)
        account.version += 1  # step 3: confirm
        return True
    return False


def process_payment_secure(store: AccountStore, account_id: str, amount: int) -> Account:
    """Hardened replacement: single transactional, row-locked, version-checked,
    negative-balance-guarded debit."""
    return store.debit_with_retry(account_id, amount)


# ---------------------------------------------------------------------------
# Self-tests -- run `python fixes/payment_race_condition_fix.py`
# ---------------------------------------------------------------------------


def _run_self_tests() -> None:
    # 1. Happy path: a single valid debit succeeds and updates balance/version.
    store = AccountStore()
    store.create_account("acc1", balance=100)
    account = process_payment_secure(store, "acc1", 40)
    assert account.balance == 60, account.balance
    assert account.version == 1, account.version

    # 2. Concurrency: 50 threads race to debit an account that can only
    #    afford a handful of debits. Balance must never go negative, and the
    #    number of successful debits must exactly match what the balance
    #    allows.
    store2 = AccountStore()
    store2.create_account("acc2", balance=100)
    debit_amount = 10
    num_threads = 50
    successes = []
    lock = threading.Lock()

    def worker():
        try:
            process_payment_secure(store2, "acc2", debit_amount)
            with lock:
                successes.append(True)
        except (InsufficientFundsError, OptimisticLockError):
            with lock:
                successes.append(False)

    threads = [threading.Thread(target=worker) for _ in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    final = store2.get_account_snapshot("acc2")
    assert final.balance >= 0, f"balance went negative: {final.balance}"
    expected_successes = 100 // debit_amount  # exactly 10 debits should succeed
    actual_successes = sum(1 for s in successes if s)
    assert actual_successes == expected_successes, (
        f"expected {expected_successes} successful debits, got {actual_successes}"
    )
    assert final.balance == 100 - actual_successes * debit_amount

    # 3. Optimistic-lock version mismatch is detected.
    store3 = AccountStore()
    store3.create_account("acc3", balance=50)
    snapshot = store3.get_account_snapshot("acc3")
    # Simulate another transaction mutating the row first.
    store3.debit("acc3", 10, expected_version=snapshot.version)
    try:
        store3.debit("acc3", 5, expected_version=snapshot.version)  # stale version
    except OptimisticLockError:
        pass
    else:  # pragma: no cover
        raise AssertionError("stale version was accepted")

    # 4. Negative-balance guard rejects an over-large debit outright.
    store4 = AccountStore()
    store4.create_account("acc4", balance=20)
    try:
        store4.debit("acc4", 21)
    except InsufficientFundsError:
        pass
    else:  # pragma: no cover
        raise AssertionError("debit exceeding balance was accepted")
    unchanged = store4.get_account_snapshot("acc4")
    assert unchanged.balance == 20 and unchanged.version == 0

    print("payment_race_condition_fix: all 4 self-tests passed")


if __name__ == "__main__":  # pragma: no cover
    _run_self_tests()
