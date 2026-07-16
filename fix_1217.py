"""
Fix for Issue #1217 — Race Condition in Distributed Transaction

Vulnerability
-------------
Payment system's "check balance -> deduct -> confirm" is non-atomic.
Attacker sends concurrent requests, each passing balance check,
resulting in double spend (balance goes negative).

Fix
---
- Use database transactions with row-level locks
- Implement optimistic locking with version numbers
- Check non-negative balance after deduction
"""

import threading
from contextlib import contextmanager
from typing import Optional
import sqlite3


class SafeTransactionManager:
    """Manages distributed transactions with race condition protection."""

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()

    def _init_schema(self):
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY,
                balance INTEGER NOT NULL DEFAULT 0,
                version INTEGER NOT NULL DEFAULT 1
            )
        """)
        self._conn.commit()

    def create_account(self, account_id: int, initial_balance: int = 1000):
        self._conn.execute(
            "INSERT OR IGNORE INTO accounts (id, balance, version) VALUES (?, ?, 1)",
            (account_id, initial_balance)
        )
        self._conn.commit()

    @contextmanager
    def transaction(self):
        cursor = self._conn.cursor()
        cursor.execute("BEGIN IMMEDIATE")
        try:
            yield cursor
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        finally:
            cursor.close()

    def transfer(self, from_id: int, to_id: int, amount: int) -> bool:
        with self.transaction() as cursor:
            cursor.execute(
                "SELECT balance, version FROM accounts WHERE id = ?",
                (from_id,)
            )
            row = cursor.fetchone()
            if not row:
                return False
            balance, version = row
            if balance < amount:
                return False
            cursor.execute(
                "UPDATE accounts SET balance = balance - ?, version = version + 1 "
                "WHERE id = ? AND version = ?",
                (amount, from_id, version)
            )
            if cursor.rowcount == 0:
                return False
            cursor.execute(
                "UPDATE accounts SET balance = balance + ? WHERE id = ?",
                (amount, to_id)
            )
            cursor.execute(
                "SELECT balance FROM accounts WHERE id = ?",
                (from_id,)
            )
            new_balance = cursor.fetchone()[0]
            if new_balance < 0:
                raise ValueError(f"Negative balance detected: {new_balance}")
        return True

    def get_balance(self, account_id: int) -> Optional[int]:
        cursor = self._conn.cursor()
        cursor.execute("SELECT balance FROM accounts WHERE id = ?", (account_id,))
        row = cursor.fetchone()
        return row[0] if row else None


if __name__ == "__main__":
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
    print(f"Account 1: {b1}, Account 2: {b2}")
    assert b1 >= 0, f"Negative balance: {b1}"
    assert b1 + b2 == 1500, "Money conservation violated"
    print("PASS: No double spend detected")