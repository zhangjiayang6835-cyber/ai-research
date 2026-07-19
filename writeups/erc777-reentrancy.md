# Reentrancy via ERC-777 Callback in Withdraw

## Description
The withdraw function sends tokens before updating state. ERC-777 tokensReceived callback re-enters the withdraw function before the balance is updated, allowing repeated withdrawals.

## Impact
Drain all contract funds.

## Remediation
Use checks-effects-interactions pattern (update state before external calls), use ReentrancyGuard, avoid ERC-777 callbacks in critical paths, use pull payment pattern.