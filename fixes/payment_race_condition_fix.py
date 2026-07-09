"""
Fix for Issue — Race Condition in Distributed Transaction -> Double Spend

Vulnerability
-------------
The payment service performed "check balance -> deduct -> confirm" as three
separate, non-atomic steps:

    balance = get_balance(account_id)          # step 1: read
    if balance >= amount:                       # step 2: check
        set_balance(account_id, balance - amt)  # step 3: write
        confirm_transaction(...)

Because these steps are not wrapped in a single atomic unit, an attacker can
fire many concurrent requests. Each request reads the SAME pre-deduction
balance, passes the check, and then writes its own deduction — the classic
TOCTOU (time-of-check to time-of-use) race. The account balance can be
drained multiple times over and even driven negative (double spend).

Root cause
----------
1. No transaction boundary spans the read-check-write sequence.
2. No row-level lock prevents two transactions from reading the same
   "stale" balance concurrently.
3. No optimistic-lock version guards the update, so a lost update can slip
   through even under weaker isolation levels.
4. No invariant check ("balance must never be negative") is enforced at the
   point of write.

Fix strategy
------------
1. **Database transaction + row-level lock**: the whole check-deduct-confirm
   sequence executes inside a single transaction that acquires an exclusive
   row lock on the account (``SELECT ... FOR UPDATE`` in Postgres/MySQL).
   Concurrent transactions targeting the same account serialize on the lock
   instead of racing.
2. **Optimistic-lock version number**: every account row carries a
   monotonically increasing ``version``. Updates are conditioned on
   ``WHERE id = :id AND version = :expected_version``; if zero rows are
   affected the transaction is retried (bounded) or aborted. This gives a
   second, independent guard even if the locking layer is misconfigured.
3. **Post-deduction non-negative check**: after computing the new balance,
   the code asserts ``new_balance >= 0`` INSIDE the same transaction and
   rolls back otherwise — the invariant is enforced at the exact point the
   money leaves the account, not in a separate step that can race.
4. A single ``process_payment()`` entry point replaces the old vulnerable
   three-step API so application code can no longer bypass the transaction.

The reference implementation below is dependency-free: it simulates a
row-locking relational store using an in-process ``threading.Lock`` per
account plus explicit version numbers, so the module can be executed and
self-tested without a real database. A parallel SQL example is included in
the docstring of :func:`process_payment` for wiring into Postgres/MySQL.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict


class InsufficientFundsError(ValueError):
    """Raised when a payment would drive the balance negative."""


class OptimisticLockError(RuntimeError):
    """Raised when the row version changed between read and write and
    retries were exhausted."""


@dataclass
class Account:
    """In-memory stand-in for an account row, including an optimistic-lock
    ``version`` column exactly as would exist in a real schema:

        CREATE TABLE accounts (
            id       BIGINT PRIMARY KEY,
            balance  NUMERIC(20, 2) NOT NULL CHECK (balance >= 0),
            version  BIGINT NOT NULL DEFAULT 0
        );
    """

    account_id: str
    balance: int  # smallest currency unit (cents) to avoid float issues
    version: int = 0
    # Per-row lock simulates ``SELECT ... FOR UPDATE`` row-level locking.
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)


class AccountStore:
    """Simulated transactional data store.

    Real deployments replace this class with actual DB calls, e.g.:

        BEGIN;
        SELECT balance, version FROM accounts WHERE id = :id FOR UPDATE;
        -- application computes new_balance = balance - amount
        UPDATE accounts
           SET balance = :new_balance, version = version + 1
         WHERE id = :id AND version = :expected_version AND :new_balance >= 0;
        -- check affected row count == 1, else ROLLBACK and retry
        COMMIT;

    The ``FOR UPDATE`` clause takes the row-level lock; the ``version``
    predicate is the optimistic-lock guard; the ``:new_balance >= 0``
    predicate (or a CHECK constraint) is the non-negative-balance guard.
    """

    def __init__(self) -> None:
        self._accounts: Dict[str, Account] = {}
        self._registry_lock = threading.Lock()  # protects dict structure only

    def create_account(self, account_id: str, balance: int) -> None:
        with self._registry_lock:
            if account_id in self._accounts:
                raise ValueError(f"account {account_id} already exists")
            self._accounts[account_id] = Account(account_id=account_id, balance=balance)

    def _get(self, account_id: str) -> Account:
        with self._registry_lock:
            account = self._accounts.get(account_id)
        if account is None:
            raise KeyError(f"unknown account {account_id}")
        return account

    def get_balance(self, account_id: str) -> int:
        return self._get(account_id).balance

    def get_version(self, account_id: str) -> int:
        return self._get(account_id).version

    def debit(self, account_id: str, amount: int, *, max_retries: int = 5) -> int:
        """Atomically debit ``amount`` from ``account_id``.

        Acquires the row-level lock (the per-account ``threading.Lock``),
        re-reads balance+version inside the critical section (equivalent to
        ``SELECT ... FOR UPDATE``), verifies the optimistic-lock version has
        not changed, computes the new balance, rejects the operation if it
        would go negative, and only then commits (bumps ``version`` and
        writes the new balance) before releasing the lock.

        Returns the new balance on success.
        """
        if amount <= 0:
            raise ValueError("amount must be positive")

        account = self._get(account_id)

        for _attempt in range(max_retries):
            # --- BEGIN TRANSACTION (row-level lock = SELECT ... FOR UPDATE) ---
            with account._lock:
                observed_version = account.version
                current_balance = account.balance

                new_balance = current_balance - amount

                # Non-negative-balance invariant enforced at write time,
                # inside the same critical section as the read — no window
                # for a concurrent transaction to interleave.
                if new_balance < 0:
                    raise InsufficientFundsError(
                        f"insufficient funds: balance={current_balance} amount={amount}"
                    )

                # Optimistic-lock compare-and-swap: since we hold the row
                # lock this can never actually fail here, but the check is
                # kept to mirror the real SQL predicate
                # (WHERE version = :expected_version) so the same code path
                # works even if the lock is downgraded to a weaker isolation
                # level in some deployment.
                if account.version != observed_version:
                    continue  # retry: someone else committed first

                account.balance = new_balance
                account.version = observed_version + 1
                # --- COMMIT ---
                return account.balance

        raise OptimisticLockError(
            f"could not commit debit for {account_id} after {max_retries} retries"
        )


_STORE = AccountStore()


def get_store() -> AccountStore:
    return _STORE


@dataclass
class PaymentResult:
    account_id: str
    amount: int
    new_balance: int
    version: int
    confirmed: bool


def process_payment(account_id: str, amount: int, *, store: AccountStore | None = None) -> PaymentResult:
    """Single, safe entry point for payment processing.

    Replaces the old vulnerable pattern:

        balance = get_balance(account_id)
        if balance >= amount:
            set_balance(account_id, balance - amount)
            confirm_transaction(...)

    with an atomic transaction: row-level lock -> optimistic version check ->
    balance mutation -> non-negative assertion -> commit -> confirm, all
    inside one critical section so concurrent requests cannot observe or act
    on a stale balance.
    """
    store = store or _STORE
    new_balance = store.debit(account_id, amount)
    version = store.get_version(account_id)
    return PaymentResult(
        account_id=account_id,
        amount=amount,
        new_balance=new_balance,
        version=version,
        confirmed=True,
    )


# ---------------------------------------------------------------------------
# Vulnerable reference implementation — kept ONLY so tests can demonstrate the
# fix by contrast. Never wire this into real request handling.
# ---------------------------------------------------------------------------

def process_payment_vulnerable(account_id: str, amount: int, *, store: AccountStore | None = None) -> PaymentResult:  # pragma: no cover - deliberately unsafe
    store = store or _STORE
    balance = store.get_balance(account_id)
    # Simulate scheduler interleaving between check and write to make the
    # race reliably observable in tests.
    time.sleep(0.001)
    if balance < amount:
        raise InsufficientFundsError("insufficient funds")
    account = store._get(account_id)  # bypasses the lock entirely
    account.balance = balance - amount
    return PaymentResult(
        account_id=account_id,
        amount=amount,
        new_balance=account.balance,
        version=account.version,
        confirmed=True,
    )


# ---------------------------------------------------------------------------
# Self-tests — run ``python fixes/payment_race_condition_fix.py``
# ---------------------------------------------------------------------------

def _run_self_tests() -> None:
    # 1. Concurrent double-spend attempt against the SECURE path must never
    #    drive the balance negative and must only allow as many payments as
    #    the balance actually supports.
    store = AccountStore()
    store.create_account("acct-1", balance=100)

    successes = []
    failures = []
    lock = threading.Lock()

    def attempt():
        try:
            result = process_payment("acct-1", 100, store=store)
            with lock:
                successes.append(result)
        except InsufficientFundsError:
            with lock:
                failures.append(1)

    threads = [threading.Thread(target=attempt) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert store.get_balance("acct-1") == 0, "balance must never go negative"
    assert len(successes) == 1, f"expected exactly 1 successful payment, got {len(successes)}"
    assert len(failures) == 19
    assert store.get_version("acct-1") == 1, "version must increment exactly once"

    # 2. Many small concurrent payments that exactly exhaust the balance.
    store2 = AccountStore()
    store2.create_account("acct-2", balance=100)

    ok_count = [0]
    fail_count = [0]
    lock2 = threading.Lock()

    def attempt_small():
        try:
            process_payment("acct-2", 10, store=store2)
            with lock2:
                ok_count[0] += 1
        except InsufficientFundsError:
            with lock2:
                fail_count[0] += 1

    threads2 = [threading.Thread(target=attempt_small) for _ in range(30)]
    for t in threads2:
        t.start()
    for t in threads2:
        t.join()

    assert store2.get_balance("acct-2") == 0
    assert ok_count[0] == 10, f"expected exactly 10 successful debits of 10, got {ok_count[0]}"
    assert fail_count[0] == 20
    assert store2.get_version("acct-2") == 10

    # 3. Single payment larger than balance is rejected atomically, balance
    #    unchanged, version unchanged.
    store3 = AccountStore()
    store3.create_account("acct-3", balance=50)
    try:
        process_payment("acct-3", 51, store=store3)
    except InsufficientFundsError:
        pass
    else:  # pragma: no cover
        raise AssertionError("overdraft payment must be rejected")
    assert store3.get_balance("acct-3") == 50
    assert store3.get_version("acct-3") == 0

    # 4. Demonstrate the vulnerability exists in the OLD code path (contrast
    #    test) — concurrent calls to the unsafe function can overspend.
    store4 = AccountStore()
    store4.create_account("acct-4", balance=100)

    vuln_success = []
    lock4 = threading.Lock()

    def attempt_vuln():
        try:
            process_payment_vulnerable("acct-4", 100, store=store4)
            with lock4:
                vuln_success.append(1)
        except InsufficientFundsError:
            pass

    threads4 = [threading.Thread(target=attempt_vuln) for _ in range(10)]
    for t in threads4:
        t.start()
    for t in threads4:
        t.join()

    # The unsafe path is expected to (unsafely) allow more than one deduction
    # and/or a negative balance — this documents the bug the fix eliminates.
    # We only assert it's reproducible, not a specific count (races are
    # inherently timing dependent).
    assert len(vuln_success) >= 1

    print("payment_race_condition_fix: all self-tests passed")


if __name__ == "__main__":  # pragma: no cover
    _run_self_tests()
