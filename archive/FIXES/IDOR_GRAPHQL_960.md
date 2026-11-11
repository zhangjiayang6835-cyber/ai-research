# Fix: IDOR in GraphQL Nested Query → Mass Data Leak

## Vulnerability
GraphQL query like user(id: 123) { orders { items { price } } } does not check whether the current user has permission to access that user's order data. Attackers can iterate through user IDs to get all users' order information.

## Fix Implementation
1. Implement DataLoader-level permission checks
2. Use auth context rather than client-provided IDs
3. Limit query rate

## References
- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-862: Missing Authorization
