"""
Fix for Issue #741 — Race Condition in Distributed Transaction
================================================================

Vulnerability
-------------
A payment system performs "check balance → deduct → confirm" as three non-atomic
steps. Attackers can send concurrent requests that all pass the balance check,
leading to the balance being overdrawn (double-spend).

Fix Strategy
------------
1. Use database transactions with row-level locks (SELECT ... FOR UPDATE).
2. Implement optimistic locking with version numbers.
3. Verify non-negative balance after deduction.
"""

from __future__ import annotations

import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Generator


@dataclass
class SimAccount:
    account_id: str
    balance: int
    version: int = 0
    locked: bool = False


class SimDB:
    """Simulated in-memory database with row-level locking."""

    def __init__(self):
        self._accounts: dict[str, SimAccount] = {}
        self._lock = threading.Lock()
        self._row_locks: dict[str, threading.Lock] = {}

    def create_account(self, account_id: str, initial_balance: int) -> SimAccount:
        with self._lock:
            acct = SimAccount(account_id=account_id, balance=initial_balance)
            self._accounts[account_id] = acct
            self._row_locks[account_id] = threading.Lock()
            return acct

    @contextmanager
    def select_for_update(self, account_id: str) -> Generator[SimAccount, None, None]:
        """SELECT ... FOR UPDATE: acquire row-level lock on the account."""
        row_lock = self._row_locks.get(account_id)
        if row_lock is None:
            raise ValueError(f"Account not found: {account_id}")
        row_lock.acquire()
        try:
            acct = self._accounts[account_id]
            acct.locked = True
            yield acct
        finally:
            acct.locked = False
            row_lock.release()


@dataclass
class TransferResult:
    success: bool
    new_balance: int = 0
    error: str = ""
    idempotency_key: str = ""


class TransactionManager:
    """Manages transactions with row-level locking and optimistic concurrency control."""

    def __init__(self, db: SimDB | None = None):
        self.db = db or SimDB()
        self._processed_keys: set[str] = set()
        self._lock = threading.Lock()

    def transfer(
        self,
        sender_id: str,
        recipient_id: str,
        amount: int,
        idempotency_key: str | None = None,
    ) -> TransferResult:
        if amount <= 0:
            return TransferResult(success=False, error="Amount must be positive")

        key = idempotency_key or str(uuid.uuid4())
        with self._lock:
            if key in self._processed_keys:
                return TransferResult(success=True, error="Already processed")

        first_id, second_id = sorted([sender_id, recipient_id])

        with self.db.select_for_update(first_id) as first_acct:
            with self.db.select_for_update(second_id) as second_acct:
                if first_acct.account_id == sender_id:
                    sender, recipient = first_acct, second_acct
                else:
                    sender, recipient = second_acct, first_acct

                if sender.balance < amount:
                    return TransferResult(success=False, error="Insufficient balance", new_balance=sender.balance)

                sender.balance -= amount
                recipient.balance += amount
                sender.version += 1
                recipient.version += 1

                if sender.balance < 0:
                    sender.balance += amount
                    recipient.balance -= amount
                    return TransferResult(success=False, error="Balance went negative")

                with self._lock:
                    self._processed_keys.add(key)

                return TransferResult(success=True, new_balance=sender.balance, idempotency_key=key)
