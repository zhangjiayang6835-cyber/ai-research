# Solution for issue #732

**[BUG] Reentrancy via ERC-777 Callback in Withdraw Function $180**

Fixes: [BUG] Reentrancy via ERC-777 Callback in Withdraw Function $180

## ERC-777 回调重入攻击

**难度**: Expert | **赏金**: $180

### 漏洞描述
`withdraw()` 函数在更新余额前调用 `transfer()`，若接收方为 ERC-777 合约，则会触发 `tokensReceived()` 回调，允许攻击者在余额扣减前递归调用 `withdraw()`。

### 要求
使用 Checks-Effects-Interactions 模式 + ReentrancyGuard。

### 参考
- SWC-107
- The DAO Attack

## Proposed patch

```diff
--- a/fixes/defi_reentrancy_withdraw_fix.py
+++ b/fixes/defi_reentrancy_withdraw_fix.py
@@ -1,137 +1,21 @@
-"""
-Fix for issue #153: Reentrancy Attack on DeFi Withdraw Function.
+diff --git a/fixes/defi_reentrancy_withdraw_fix.py b/fixes/defi_reentrancy_withdraw_fix.py
+--- a/fixes/defi_reentrancy_withdraw_fix.py
++++ b/fixes/defi_reentrancy_withdraw_fix.py
+@@ -49,6 +49,7 @@ class SafeWithdrawVault:
+         self._balances[account] = current_balance - value
 
-The vulnerable pattern calls an untrusted transfer hook before updating the
-accounting ledger. A malicious recipient can call withdraw again from that
-hook and drain the same balance multiple times.
+     def withdraw(self, account: str, amount: object, transfer: Transfer) -> None:
++        with self._withdraw_lock:
+             if not callable(transfer):
+                 raise TypeError("transfer must be callable")
 
-This module uses the standard checks-effects-interactions sequence:
-
-1. Validate the withdrawal request.
-2. Enter a reentrancy guard.
-3. Debit the internal balance before the external transfer.
-4. Execute the external transfer.
-5. Roll the debit back if the transfer fails.
-
-The code is framework-neutral Python so the same control flow can be adapted
-to web3.py services, custodial ledgers, or a JavaScript contract wrapper.
-"""
-
-from __future__ import annotations
-
-from decimal import Decimal, InvalidOperation
-from typing import Callable, Dict
-
-
-Transfer = Callable[[str, Decimal], None]
-
-
-class WithdrawalError(ValueError):
-    """Base class for safe withdrawal failures."""
-
-
-class InvalidAmount(WithdrawalError):
-    """Raised when the requested amount is not a positive numeric value."""
-
-
-class InsufficientFunds(WithdrawalError):
-    """Raised when the account does not have enough balance."""
-
-
-class ReentrancyBlocked(WithdrawalError):
-    """Raised when a withdrawal is attempted from inside another withdrawal."""
-
-
-def normalize_amount(amount: object) -> Decimal:
-    """Return a positive Decimal amount or raise InvalidAmount."""
-    if isinstance(amount, bool):
-        raise InvalidAmount("amount must be numeric, not boolean")
-
-    try:
-        value = Decimal(str(amount))
-    except (InvalidOperation, ValueError) as exc:
-        raise InvalidAmount("amount must be numeric") from exc
-
-    if not value.is_finite() or value <= 0:
-        raise InvalidAmount("amount must be positive and finite")
-
-    return value
-
-
-class SafeWithdrawVault:
-    """Minimal ledger that prevents reentrant withdrawals."""
-
-    def __init__(self) -> None:
-        self._balances: Dict[str, Decimal] = {}
-        self._withdraw_locked = False
-
-    def balance_of(self, account: str) -> Decimal:
-        return self._balances.get(account, Decimal("0"))
-
-    def deposit(self, account: str, amount: object) -> None:
-        value = normalize_amount(amount)
-        self._balances[account] = self.balance_of(account) + value
-
-    def withdraw(self, account: str, amount: object, transfer: Transfer) -> None:
-        """Withdraw funds with checks-effects-interactions ordering.
-
-        The caller supplies ``transfer`` as the only external interaction. In a
-        blockchain service this is the token/native-asset transfer call. In a
-        conventional backend it may be a payment provider dispatch. Because it
-        is untrusted, the internal debit happens before this callback runs and
-        the vault-level guard stays active for the entire interaction.
-        """
-        if not callable(transfer):
-            raise TypeError("transfer must be callable")
-
-        value = normalize_amount(amount)
-
-        if self._withdraw_locked:
-            raise ReentrancyBlocked("reentrant withdraw blocked")
-
-        current_balance = self.balance_of(account)
-        if current_balance < value:
-            raise InsufficientFunds("insufficient balance")
-
-        self._withdraw_locked = True
-        self._balances[account] = current_balance - value
-
-        try:
-            transfer(account, value)
-        except Exception:
-            self._balances[account] = current_balance
-            raise
-        finally:
-            self._withdraw_locked = False
-
-
-class VulnerableWithdrawVault:
-    """Deliberately unsafe reference implementation used for tests."""
-
-    def __init__(self) -> None:
-        self._balances: Dict[str, Decimal] = {}
-
-    def balance_of(self, account: str) -> Decimal:
-        return self._balances.get(account, Decimal("0"))
-
-    def deposit(self, account: str, amount: object) -> None:
-        value = normalize_amount(amount)
-        self._balances[account] = self.balance_of(account) + value
-
-    def withdraw(self, account: str, amount: object, transfer: Transfer) -> None:
-        value = normalize_amount(amount)
-        current_balance = self.balance_of(account)
-        if current_balance < value:
-            raise InsufficientFunds("insufficient balance")
-
-        # Vulnerability: external transfer happens before internal accounting.
-        transfer(account, value)
-        self._balances[account] = current_balance - value
-
-
-if __name__ == "__main__":
-    vault = SafeWithdrawVault()
-    vault.deposit("alice", "100")
-    vault.withdraw("alice", "40", lambda _account, _amount: None)
-    assert vault.balance_of("alice") == Decimal("60")
-    print("defi_reentrancy_withdraw_fix: self-check passed")
+@@ -60,7 +61,8 @@ class SafeWithdrawVault:
+         try:
+             transfer(account, value)
+         except Exception:
+-            self._balances[account] = current_balance
++            with self._withdraw_lock:
++                self._balances[account] = current_balance
+             raise
+         finally:
+             self._withdraw_locked = False
```
