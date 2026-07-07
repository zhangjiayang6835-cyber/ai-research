"""Fix for issue #200: distributed transaction race double spending.

The vulnerable pattern is a read-check-write balance update performed without
an account-level lock or idempotency record. Two concurrent requests can both
observe the same source balance, both decide the transfer is affordable, then
write back from the stale snapshot. That lets the source spend the same funds
twice while only one debit is visible.

This module provides a small dependency-free ledger guard that can be adapted
to a database transaction, wallet service, or message-driven payment worker:

* acquire per-account locks in stable order to prevent race windows and
  deadlocks;
* require a caller-supplied idempotency key for every transfer;
* reject conflicting reuse of an idempotency key;
* optionally enforce optimistic source/destination versions;
* debit and credit in one critical section.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal
from threading import Lock
from time import sleep
from typing import Iterator, MutableMapping


class DoubleSpendGuardError(ValueError):
    """Raised when a transfer would break double-spend protections."""


@dataclass
class Account:
    """Minimal account record with integer minor-unit balance and version."""

    account_id: str
    balance: int
    version: int = 0


@dataclass(frozen=True)
class TransferResult:
    """Stable result returned for a successful idempotent transfer."""

    idempotency_key: str
    source_id: str
    destination_id: str
    amount: int
    source_balance: int
    destination_balance: int
    source_version: int
    destination_version: int


@dataclass
class _IdempotencyEntry:
    fingerprint: tuple[str, str, int]
    result: TransferResult | None = None


class DistributedLedger:
    """Thread-safe transfer guard for distributed wallet/account services."""

    def __init__(self, accounts: MutableMapping[str, Account]):
        self.accounts = accounts
        self._global_lock = Lock()
        self._idempotency_lock = Lock()
        self._account_locks: dict[str, Lock] = {}
        self._idempotency: dict[str, _IdempotencyEntry] = {}

    def transfer(
        self,
        *,
        idempotency_key: str,
        source_id: str,
        destination_id: str,
        amount: int | Decimal,
        expected_source_version: int | None = None,
        expected_destination_version: int | None = None,
    ) -> TransferResult:
        """Move funds exactly once for a unique idempotency key.

        Repeating the same request after success returns the original result
        without another debit. Reusing the key for a different transfer is
        rejected because that would let clients overwrite audit history.
        """

        cents = _normalize_minor_units(amount)
        if source_id == destination_id:
            raise DoubleSpendGuardError("source and destination must differ")

        fingerprint = (source_id, destination_id, cents)
        entry = self._reserve_idempotency_key(idempotency_key, fingerprint)
        if entry.result is not None:
            return entry.result

        try:
            with self._locked_accounts(source_id, destination_id):
                source = self._get_account(source_id)
                destination = self._get_account(destination_id)

                if (
                    expected_source_version is not None
                    and source.version != expected_source_version
                ):
                    raise DoubleSpendGuardError("stale source account version")
                if (
                    expected_destination_version is not None
                    and destination.version != expected_destination_version
                ):
                    raise DoubleSpendGuardError("stale destination account version")
                if source.balance < cents:
                    raise DoubleSpendGuardError("insufficient funds")

                source.balance -= cents
                destination.balance += cents
                source.version += 1
                destination.version += 1

                result = TransferResult(
                    idempotency_key=idempotency_key,
                    source_id=source_id,
                    destination_id=destination_id,
                    amount=cents,
                    source_balance=source.balance,
                    destination_balance=destination.balance,
                    source_version=source.version,
                    destination_version=destination.version,
                )

            with self._idempotency_lock:
                self._idempotency[idempotency_key].result = result
            return result
        except Exception:
            with self._idempotency_lock:
                current = self._idempotency.get(idempotency_key)
                if current is entry and current.result is None:
                    del self._idempotency[idempotency_key]
            raise

    def _reserve_idempotency_key(
        self, idempotency_key: str, fingerprint: tuple[str, str, int]
    ) -> _IdempotencyEntry:
        clean_key = idempotency_key.strip()
        if not clean_key:
            raise DoubleSpendGuardError("idempotency key is required")

        with self._idempotency_lock:
            existing = self._idempotency.get(clean_key)
            if existing is not None:
                if existing.fingerprint != fingerprint:
                    raise DoubleSpendGuardError("idempotency key reused with different transfer")
                if existing.result is None:
                    raise DoubleSpendGuardError("idempotent transfer already in progress")
                return existing

            entry = _IdempotencyEntry(fingerprint=fingerprint)
            self._idempotency[clean_key] = entry
            return entry

    @contextmanager
    def _locked_accounts(self, source_id: str, destination_id: str) -> Iterator[None]:
        account_ids = sorted({source_id, destination_id})
        locks = [self._lock_for(account_id) for account_id in account_ids]
        for lock in locks:
            lock.acquire()
        try:
            yield
        finally:
            for lock in reversed(locks):
                lock.release()

    def _lock_for(self, account_id: str) -> Lock:
        with self._global_lock:
            return self._account_locks.setdefault(account_id, Lock())

    def _get_account(self, account_id: str) -> Account:
        try:
            return self.accounts[account_id]
        except KeyError as exc:
            raise DoubleSpendGuardError(f"unknown account: {account_id}") from exc


def vulnerable_transfer_without_lock(
    accounts: MutableMapping[str, Account],
    *,
    source_id: str,
    destination_id: str,
    amount: int,
    race_barrier=None,
    write_delay_seconds: float = 0.001,
) -> bool:
    """Demonstrate the stale-snapshot bug the guard prevents."""

    source_snapshot = accounts[source_id].balance
    destination_snapshot = accounts[destination_id].balance

    if race_barrier is not None:
        race_barrier.wait()

    if source_snapshot < amount:
        return False

    sleep(write_delay_seconds)
    accounts[source_id].balance = source_snapshot - amount
    accounts[destination_id].balance = destination_snapshot + amount
    return True


def _normalize_minor_units(amount: int | Decimal) -> int:
    if isinstance(amount, bool):
        raise DoubleSpendGuardError("amount must be an integer minor-unit value")
    if isinstance(amount, Decimal):
        if amount != amount.to_integral_value():
            raise DoubleSpendGuardError("amount must not contain fractional minor units")
        amount = int(amount)
    if not isinstance(amount, int):
        raise DoubleSpendGuardError("amount must be an integer minor-unit value")
    if amount <= 0:
        raise DoubleSpendGuardError("amount must be positive")
    return amount


def _demo() -> None:
    accounts = {
        "alice": Account("alice", 100),
        "bob": Account("bob", 0),
    }
    ledger = DistributedLedger(accounts)
    result = ledger.transfer(
        idempotency_key="demo-1",
        source_id="alice",
        destination_id="bob",
        amount=25,
        expected_source_version=0,
    )
    print(result)


if __name__ == "__main__":
    _demo()
