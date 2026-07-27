"""
Bug Fix: Reentrancy via ERC-777 Callback in Withdraw Function

This module demonstrates and fixes the ERC-777 callback reentrancy vulnerability
in a withdrawal function. ERC-777 tokens support callbacks via the tokensReceived
hook, which can be exploited by attackers to re-enter the contract during token
transfers before state updates are completed.

Vulnerability:
- The withdraw function calls the ERC-777 token's send/operatorSend method
- ERC-777 triggers a tokensReceived callback to the recipient
- If state (e.g., balance) is updated AFTER the transfer, an attacker can
  re-enter the withdraw function and drain funds

Fix:
- Implement Checks-Effects-Interactions pattern
- Use ReentrancyGuard to prevent reentrant calls
- Update all state before any external calls

Bounty: $180
Difficulty: Expert
Issue: #1501
"""

import json
import hashlib
import logging
from enum import Enum
from typing import Dict, Optional, Any, List
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ReentrancyError(Exception):
    """Raised when a reentrant call is detected."""
    pass


class InsufficientBalanceError(Exception):
    """Raised when withdrawal amount exceeds available balance."""
    pass


class TokenStandard(Enum):
    """Supported token standards."""
    ERC20 = "ERC20"
    ERC777 = "ERC777"
    ERC721 = "ERC721"


class CallState(Enum):
    """States for the reentrancy guard."""
    IDLE = 0
    ENTERED = 1


@dataclass
class DepositRecord:
    """Represents a user deposit record."""
    user: str
    amount: int
    token_address: str
    timestamp: int
    token_standard: TokenStandard

    def to_dict(self) -> Dict[str, Any]:
        return {
            'user': self.user,
            'amount': self.amount,
            'token_address': self.token_address,
            'timestamp': self.timestamp,
            'token_standard': self.token_standard.value
        }


class ReentrancyGuard:
    """
    A reentrancy guard implementation that prevents reentrant calls
    to protected functions.

    This mimics the behavior of OpenZeppelin's ReentrancyGuard for
    Solidity contracts, adapted for Python simulation.
    """

    def __init__(self):
        self._state: CallState = CallState.IDLE

    @property
    def is_entered(self) -> bool:
        """Check if the guard is currently in an entered state."""
        return self._state == CallState.ENTERED

    def enter(self) -> None:
        """
        Enter a non-reentrant section.

        Raises:
            ReentrancyError: If a reentrant call is detected.
        """
        if self._state == CallState.ENTERED:
            logger.warning("Reentrant call detected and blocked!")
            raise ReentrancyError(
                "ReentrancyGuard: reentrant call detected. "
                "This function cannot be called recursively."
            )
        self._state = CallState.ENTERED

    def exit(self) -> None:
        """Exit a non-reentrant section, resetting the guard."""
        self._state = CallState.IDLE


class MockERC777Token:
    """
    Mock ERC-777 token contract simulation.

    ERC-777 introduces a tokensReceived hook that is called when tokens
    are sent to a recipient. This hook can be exploited for reentrancy
    if the calling contract doesn't protect against it.
    """

    def __init__(self, name: str = "TestERC777", symbol: str = "T777"):
        self.name = name
        self.symbol = symbol
        self.balances: Dict[str, int] = {}
        self.tokens_received_hooks: Dict[str, Any] = {}
        self._is_sending: bool = False

    def mint(self, to: str, amount: int) -> None:
        """Mint tokens to an address."""
        if amount < 0:
            raise ValueError("Cannot mint negative amount")
        self.balances[to] = self.balances.get(to, 0) + amount
        logger.info(f"Minted {amount} {self.symbol} to {to}")

    def balance_of(self, address: str) -> int:
        """Get the balance of an address."""
        return self.balances.get(address, 0)

    def send(self, sender: str, recipient: str, amount: int, data: bytes = b'') -> bool:
        """
        Send tokens from sender to recipient.

        In ERC-777, this triggers the tokensReceived callback on the recipient
        if they have registered a hook. This is the vector for reentrancy attacks.

        Args:
            sender: The address sending tokens.
            recipient: The address receiving tokens.
            amount: The amount of tokens to send.
            data: Arbitrary data passed to the recipient's hook.

        Returns:
            True if the transfer was successful.

        Raises:
            ValueError: If sender has insufficient balance.
        """
        if amount < 0:
            raise ValueError("Cannot send negative amount")

        sender_balance = self.balances.get(sender, 0)
        if sender_balance < amount:
            raise ValueError(
                f"Insufficient balance: has {sender_balance}, needs {amount}"
            )

        # Prevent nested sends (simulating EVM reentrancy context)
        if self._is_sending:
            logger.warning("Nested send detected - this is the reentrancy vector!")
            # In a real scenario, this would succeed and allow the exploit

        # Update balances BEFORE triggering callback (Checks-Effects)
        self.balances[sender] -= amount
        self.balances[recipient] = self.balances.get(recipient, 0) + amount

        logger.info(
            f"ERC-777 Transfer: {sender} -> {recipient}: {amount} {self.symbol}"
        )

        # Trigger tokensReceived callback (Interaction)
        # This is where reentrancy can occur
        self._is_sending = True
        try:
            hook = self.tokens_received_hooks.get(recipient)
            if hook is not None:
                logger.info(f"Triggering tokensReceived hook for {recipient}")
                hook(recipient, sender, amount, data)
        finally:
            self._is_sending = False

        return True

    def register_receiver_hook(self, address: str, callback: Any) -> None:
        """
        Register a tokensReceived hook for an address.

        In a real ERC-777 implementation, this would be done via the
        ERC1820 registry by setting an implementer for the tokensReceived interface.

        Args:
            address: The address to register the hook for.
            callback: A callable that accepts (recipient, sender, amount, data).
        """
        self.tokens_received_hooks[address] = callback


class VulnerableVault:
    """
    A vulnerable vault contract that is susceptible to ERC-777 reentrancy.

    The vulnerability exists because:
    1. The withdraw function sends tokens BEFORE updating the user's balance
    2. There is no reentrancy guard
    3. ERC-777 callbacks allow the recipient to execute arbitrary code during transfer
    """

    def __init__(self, token: MockERC777Token):
        self.token = token
        self.deposits: Dict[str, int] = {}
        self.vault_address = "VAULT_CONTRACT"

    def deposit(self, user: str, amount: int) -> None:
        """User deposits tokens into the vault."""
        if amount <= 0:
            raise ValueError("Deposit amount must be positive")

        user_balance = self.token.balance_of(user)
        if user_balance < amount:
            raise ValueError("Insufficient token balance for deposit")

        # Transfer tokens from user to vault
        self.token.send(user, self.vault_address, amount)

        # Update deposit record
        self.deposits[user] = self.deposits.get(user, 0) + amount
        logger.info(f"Deposit: {user} deposited {amount}. Total: {self.deposits[user]}")

    def withdraw(self, user: str, amount: int) -> bool:
        """
        VULNERABLE: Withdraw tokens from the vault.

        This function is vulnerable to reentrancy because:
        1. It checks the user's balance
        2. It sends tokens to the user (triggering ERC-777 callback)
        3. It THEN updates the user's balance

        An attacker can register a tokensReceived hook that calls withdraw()
        again before the balance is updated, draining the vault.

        Args:
            user: The address withdrawing funds.
            amount: The amount to withdraw.

        Returns:
            True if withdrawal was successful.
        """
        # CHECK
        if self.deposits.get(user, 0) < amount:
            raise InsufficientBalanceError(
                f"Insufficient deposit balance: has {self.deposits.get(user, 0)}, "
                f"needs {amount}"
            )

        # INTERACTION (VULNERABLE: This happens before state update!)
        # ERC-777 callback will be triggered here
        self.token.send(self.vault