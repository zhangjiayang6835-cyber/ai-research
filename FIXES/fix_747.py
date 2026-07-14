"""
Fix for Issue #747 — Java RMI Deserialization → Remote Code Execution
=======================================================================

Vulnerability
-------------
A Java RMI endpoint is exposed on the public internet. Attackers use ysoserial to
send crafted deserialization payloads that trigger Runtime.exec().

Fix Strategy
------------
1. Deploy SerialFilter (JEP 290) to restrict allowed classes for deserialization.
2. Bind the RMI registry to localhost only (127.0.0.1).
3. Use a whitelist of allowed serialization classes.
"""

from __future__ import annotations

from typing import Final

RMI_ALLOWED_CLASSES: Final[set[str]] = {
    "java.lang.String", "java.lang.Integer", "java.lang.Boolean",
    "java.lang.Long", "java.lang.Double", "java.util.ArrayList",
    "java.util.HashMap", "java.util.HashSet", "java.rmi.Remote",
    "java.rmi.server.ObjID", "java.rmi.server.RemoteObjectInvocationHandler",
    "javax.rmi.CORBA.Stub", "java.security.Permission", "java.security.Principal",
}

DANGEROUS_PATTERNS: Final[list[str]] = [
    "org.apache.commons.collections", "org.apache.commons.collections4",
    "com.sun.org.apache.xalan", "com.sun.org.apache.xpath",
    "java.lang.Runtime", "java.lang.ProcessBuilder", "java.lang.reflect.Proxy",
    "javax.management.BadAttributeValueExpException", "com.sun.rowset.JdbcRowSetImpl",
    "org.jboss.interceptor", "org.codehaus.groovy.runtime", "org.python.core",
    "org.springframework.aop", "com.mchange.v2.c3p0", "net.sf.ehcache",
    "javax.script.ScriptEngineManager",
]


class RMIDeserializationFilter:
    """JEP 290-style deserialization filter for RMI."""

    @staticmethod
    def check_deserialization(class_name: str) -> str:
        if class_name in RMI_ALLOWED_CLASSES:
            return "ALLOW"
        for pattern in DANGEROUS_PATTERNS:
            if pattern in class_name:
                return "REJECT"
        return "REJECT"


def restrict_rmi_bind_address() -> str:
    return "127.0.0.1"


def is_safe_bind_address(address: str) -> bool:
    return address in ("127.0.0.1", "localhost", "::1")
