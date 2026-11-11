"""
Fix for Issue #956 — Java RMI Deserialization → Remote Code Execution
=======================================================================

Vulnerability
-------------
A Java RMI endpoint is exposed on the public internet. Attackers use ysoserial
to send crafted deserialization payloads.

Fix Strategy
------------
1. Deploy JEP 290 deserialization filter with class whitelist.
2. Bind RMI registry to localhost.
3. Block known ysoserial gadget classes.
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
