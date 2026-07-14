# Fix: Race Condition in Distributed Transaction → Double Spend

## Vulnerability
Payment system performs "check balance → deduct → confirm" as three non-atomic steps. Attackers send concurrent requests that all pass the balance check, allowing the balance to be overdrawn.

## Fix Implementation
1. Use database transactions with row-level locks
2. Implement optimistic locking with version numbers
3. Verify non-negative balance after deduction

## References
- CWE-362: Race Condition
