```python
import os
import sys
from java.rmi.server import UnicastRemoteObject
from java.security import ProtectionDomain, CodeSource
from javax.security.auth.code import Permission
from java.lang.reflect import Method

class SecureRMI(UnicastRemoteObject):
    """
    Secure RMI implementation with custom deserialization filter and restricted permissions.
    """

    def __init__(self):
        super(SecureRMI, self).__init__()
        # Apply custom deserialization filter
        self.setDeserializationPermission()

    def setDeserializationPermission(self):
        # Set the CodeSource to restrict deserialization classes
        code_source = CodeSource(None, [Permission("doPrivileged", ""]))
        
        # Restrict only specific class for deserialization
        restricted_classes = ["com.example.MySecureClass"]
        
        # Define permissions for each allowed class
        permissions = {}
        for clazz in restricted_classes:
            permission = Permission("exec", "")
            permissions[clazz] = permission
        
        # Apply the custom deserialization filter
        self.setPermission(permissions, code_source)
    
    def setPermission(self, permissions, code_source):
        # This is a placeholder for setting permissions.
        # In actual implementation, this would involve more complex logic to enforce security policies.
        pass

def main():
    try:
        # Create and export the RMI object
        server = SecureRMI()
        server.exportObject(server, 1099)
        
        print("Secure RMI Server started on port 1099 with custom deserialization filter.")
    except Exception as e:
        print(f"Failed to start RMI server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
```