# Fix: Java RMI Deserialization → Remote Code Execution

## Vulnerability
Java RMI endpoint is exposed on the public internet. Attackers use ysoserial to send crafted deserialization payloads that trigger Runtime.exec().

## Fix Implementation
1. Deploy SerialFilter / JEP 290 deserialization filter
2. Bind RMI to localhost only
3. Whitelist allowed classes for deserialization

## References
- CWE-502: Deserialization of Untrusted Data
- JEP 290: Filter Incoming Serialization Data
