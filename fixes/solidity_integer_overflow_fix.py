"""
Fix for Issue #259: Integer overflow in Solidity smart contract -> token theft.

Solidity contracts compiled before 0.8.0 can silently wrap uint256 arithmetic.
Attackers exploit that behavior to transfer more tokens than they own, overflow
recipient balances, or mint beyond the intended cap.

This module gives reviewers two practical pieces:

1. A minimal safe uint256/token-ledger model that rejects overflow and
   underflow before balances mutate.
2. A Solidity source checker that fails builds when token code relies on old
   compiler versions, unchecked arithmetic, inline assembly arithmetic, or
   transfer functions that do not perform explicit balance/cap checks.

The safe pattern is the same one a Solidity patch should use: Solidity >=0.8,
checked arithmetic, checks-effects ordering, and no `unchecked` block around
token balances or supply.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Mapping


UINT256_MAX = (1 << 256) - 1


class ArithmeticSafetyError(ValueError):
    """Raised when a token operation would overflow or underflow uint256."""


def require_uint256(value: int, *, name: str = "value") -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")
    if value < 0 or value > UINT256_MAX:
        raise ArithmeticSafetyError(f"{name} outside uint256 range")
    return value


def safe_add(a: int, b: int) -> int:
    a = require_uint256(a, name="a")
    b = require_uint256(b, name="b")
    if a > UINT256_MAX - b:
        raise ArithmeticSafetyError("uint256 addition overflow")
    return a + b


def safe_sub(a: int, b: int) -> int:
    a = require_uint256(a, name="a")
    b = require_uint256(b, name="b")
    if b > a:
        raise ArithmeticSafetyError("uint256 subtraction underflow")
    return a - b


@dataclass
class SecureTokenLedger:
    """Small reference ledger for checked token math.

    The model intentionally mirrors the critical ERC-20 balance transitions:
    debit the sender only after checking sufficient balance, credit the
    recipient only if that addition cannot overflow, and preserve total supply
    invariants after every operation.
    """

    cap: int = UINT256_MAX
    balances: dict[str, int] = field(default_factory=dict)
    total_supply: int = 0

    def __post_init__(self) -> None:
        self.cap = require_uint256(self.cap, name="cap")
        self.total_supply = require_uint256(self.total_supply, name="total_supply")
        if self.total_supply > self.cap:
            raise ArithmeticSafetyError("total supply exceeds cap")
        for account, balance in list(self.balances.items()):
            self._validate_account(account)
            self.balances[account] = require_uint256(balance, name=f"balance[{account}]")
        if sum(self.balances.values()) != self.total_supply:
            raise ArithmeticSafetyError("balances do not match total supply")

    def mint(self, account: str, amount: int) -> None:
        self._validate_account(account)
        amount = require_uint256(amount, name="amount")
        new_supply = safe_add(self.total_supply, amount)
        if new_supply > self.cap:
            raise ArithmeticSafetyError("mint exceeds token cap")
        self.balances[account] = safe_add(self.balance_of(account), amount)
        self.total_supply = new_supply
        self._assert_invariant()

    def transfer(self, sender: str, recipient: str, amount: int) -> None:
        self._validate_account(sender)
        self._validate_account(recipient)
        amount = require_uint256(amount, name="amount")
        if amount == 0:
            return

        sender_balance = self.balance_of(sender)
        recipient_balance = self.balance_of(recipient)

        new_sender_balance = safe_sub(sender_balance, amount)
        new_recipient_balance = safe_add(recipient_balance, amount)

        self.balances[sender] = new_sender_balance
        self.balances[recipient] = new_recipient_balance
        self._assert_invariant()

    def balance_of(self, account: str) -> int:
        self._validate_account(account)
        return self.balances.get(account, 0)

    @staticmethod
    def _validate_account(account: str) -> None:
        if not isinstance(account, str) or not account.strip():
            raise ValueError("account must be a non-empty string")

    def _assert_invariant(self) -> None:
        if any(balance < 0 or balance > UINT256_MAX for balance in self.balances.values()):
            raise ArithmeticSafetyError("balance outside uint256 range")
        if sum(self.balances.values()) != self.total_supply:
            raise ArithmeticSafetyError("total supply invariant violated")


def vulnerable_uint256_add(a: int, b: int) -> int:
    """Demonstrate pre-0.8 Solidity wraparound behavior for regression tests."""
    return (a + b) & UINT256_MAX


_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);", re.IGNORECASE)
_TRANSFER_RE = re.compile(r"function\s+transfer\s*\([^)]*\)\s*(?:public|external)[^{]*{(?P<body>.*?)}", re.DOTALL)
_ARITHMETIC_RE = re.compile(r"(balances?\s*\[[^\]]+\]\s*(?:\+\+|--|[+\-*/]=)|totalSupply\s*(?:\+\+|--|[+\-*/]=))")


def validate_solidity_token_source(source: str) -> list[str]:
    """Return security findings that must be fixed before deploying token code."""
    if not isinstance(source, str) or not source.strip():
        raise ValueError("source must be a non-empty Solidity source string")

    findings: list[str] = []
    pragma = _PRAGMA_RE.search(source)
    if pragma is None:
        findings.append("missing explicit Solidity pragma")
    elif not _allows_checked_arithmetic(pragma.group(1)):
        findings.append("Solidity pragma must require compiler >=0.8.0")

    lowered = source.casefold()
    if "unchecked" in lowered:
        findings.append("unchecked blocks must not wrap token arithmetic")
    if "assembly" in lowered:
        findings.append("inline assembly must not perform token arithmetic")

    for match in _ARITHMETIC_RE.finditer(source):
        start = max(0, match.start() - 80)
        line = source[start : match.end() + 80]
        if "unchecked" in line.casefold():
            findings.append("unchecked token balance/supply arithmetic detected")

    transfer = _TRANSFER_RE.search(source)
    if transfer:
        body = transfer.group("body")
        if not re.search(r"require\s*\(\s*balances?\s*\[[^\]]+\]\s*>?=\s*amount", body):
            findings.append("transfer must check sender balance before subtraction")
        if re.search(r"balances?\s*\[[^\]]+\]\s*-=\s*amount", body) and "require" not in body:
            findings.append("transfer subtracts without a balance require")
    else:
        findings.append("transfer function not found for balance safety review")

    return sorted(set(findings))


def _allows_checked_arithmetic(version_expr: str) -> bool:
    """Conservative pragma parser for common forms like ^0.8.20 or >=0.8.0."""
    constraints = re.findall(r"(>=|<=|>|<|\^|=)?\s*(\d+)\.(\d+)\.(\d+)", version_expr)
    if not constraints:
        return False

    has_checked_lower_bound = False
    for operator, major_s, minor_s, _patch_s in constraints:
        major, minor = int(major_s), int(minor_s)
        version_is_checked = major > 0 or (major == 0 and minor >= 8)
        operator = operator or ""

        if operator in {"", "=", "^", ">="} and version_is_checked:
            has_checked_lower_bound = True
        if operator == ">" and (major > 0 or (major == 0 and minor >= 7)):
            has_checked_lower_bound = True
        if operator in {"<", "<="} and not has_checked_lower_bound:
            return False

    return has_checked_lower_bound


def _demo() -> None:
    assert vulnerable_uint256_add(UINT256_MAX, 1) == 0
    try:
        safe_add(UINT256_MAX, 1)
    except ArithmeticSafetyError:
        pass
    else:
        raise AssertionError("overflow was not blocked")

    ledger = SecureTokenLedger(cap=100, balances={"alice": 10, "bob": 0}, total_supply=10)
    ledger.transfer("alice", "bob", 7)
    assert ledger.balance_of("alice") == 3
    assert ledger.balance_of("bob") == 7


if __name__ == "__main__":
    _demo()
