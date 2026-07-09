Based on the issue description, I need to fix a Java RMI deserialization vulnerability that could lead to Remote Code Execution. The requirements are:

1. Enable RMI SSL
2. Implement deserialization filters (JEP 290)
3. Restrict RMI binding address
4. Only allow whitelist classes for deserialization

Since the repository appears to be a Python-based AI research platform with security tasks, I need to create a fix that addresses the Java RMI vulnerability. Looking at the existing fix files (like `fix-ssrf-aws-metadata.py`, `fix-oauth2-pkce-interception.py`), I'll create a comprehensive Java RMI security fix.

Let me create the fix file and also update the relevant security configuration:

```diff
--- /dev/null
+++ b/fix-rmi-deserialization-rce.java
@@ -0,0 +1,156 @@
+import java.rmi.Remote;
+import java.rmi.RemoteException;
+import java.rmi.registry.LocateRegistry;
+import java.rmi.registry.Registry;
+import java.rmi.server.RMIClientSocketFactory;
+import java.rmi.server.RMIServerSocketFactory;
+import java.rmi.server.UnicastRemoteObject;
+import javax.rmi.ssl.SslRMIClientSocketFactory;
+import javax.rmi.ssl.SslRMIServerSocketFactory;
+import java.io.ObjectInputFilter;
+import java.io.ObjectInputStream;
+import java.net.InetAddress;
+import java.net.NetworkInterface;
+import java.util.Collections;
+import java.util.Enumeration;
+import java.util.HashSet;
+import java.util.Set;
+
+/**
+ * Secure RMI Server with:
+ * - SSL/TLS encryption for RMI communication
+ * - JEP 290 deserialization filter (whitelist-based)
+ * - Restricted binding to localhost/private interfaces only
+ * - Comprehensive class whitelist for deserialization
+ */
+public class SecureRMIServer {
+    
+    // Whitelist of allowed classes for deserialization
+    private static final Set<String> ALLOWED_CLASSES = Collections.unmodifiableSet(
+        new HashSet<String>() {{
+            // Java standard RMI classes
+            add("java.rmi.server.RemoteObject");
+            add("java.rmi.server.RemoteObjectInvocationHandler");
+            add("java.rmi.server.RemoteRef");
+            add("java.rmi.server.RemoteStub");
+            add("java.rmi.server.UnicastRemoteObject");
+            add("java.rmi.server.UnicastRef");
+            add("java.rmi.server.UnicastRef2");
+            add("java.rmi.activation.ActivationID");
+            add("java.rmi.MarshalledObject");
+            
+            // Java primitive wrappers and basic types
+            add("java.lang.String");
+            add("java.lang.Integer");
+            add("java.lang.Long");
+            add("java.lang.Boolean");
+            add("java.lang.Double");
+            add("java.lang.Float");
+            add("java.lang.Byte");
+            add("java.lang.Short");
+            add("java.lang.Character");
+            add("java.lang.Number");
+            add("java.lang.Object");
+            
+            // Java collections (safe for RMI parameters)
+            add("java.util.ArrayList");
+            add("java.util.HashMap");
+            add("java.util.HashSet");
+            add("java.util.LinkedList");
+            add("java.util.TreeMap");
+            add("java.util.Collections$UnmodifiableList");
+            add("java.util.Collections$UnmodifiableMap");
+            add("java.util.Collections$UnmodifiableSet");
+            
+            // Java arrays
+            add("[Ljava.lang.String;");
+            add("[Ljava.lang.Integer;");
+            add("[Ljava.lang.Object;");
+            add("[B"); // byte array
+            add("[I"); // int array
+            
+            // Application-specific classes (customize as needed)
+            add("java.rmi.RemoteException");
+            add("java.lang.Exception");
+            add("java.lang.RuntimeException");
+        }}
+    );
+    
+    /**
+     * Custom ObjectInputFilter implementing JEP 290
+     * Only allows deserialization of whitelisted classes
+     */
+    private static class WhitelistFilter implements ObjectInputFilter {
+        
+        @Override
+        public Status checkInput(FilterInfo filterInfo) {
+            if (filterInfo.serialClass() == null) {
+                return Status.UNDECIDED;
+            }
+            
+            String className = filterInfo.serialClass().getName();
+            
+            // Check against whitelist
+            if (ALLOWED_CLASSES.contains(className)) {
+                return Status.ALLOWED;
+            }
+            
+            // Allow array types of whitelisted classes
+            if (className.startsWith("[L") && className.endsWith(";")) {
+                String componentType = className.substring(2, className.length() - 1);
+                if (ALLOWED_CLASSES.contains(componentType)) {
+                    return Status.ALLOWED;
+                }
+            }
+            
+            // Reject everything else (including ysoserial gadgets)
+            System.err.println("[SECURITY] Blocked deserialization of: " + className);
+            return Status.REJECTED;
+        }
+    }
+    
+    /**
+     * Configure global deserialization filter via JEP 290
+     */
+    public static void configureGlobalFilter() {
+        // Set JEP 290 global filter
+        ObjectInputFilter.Config.setSerialFilter(new WhitelistFilter());
+        
+        // Set system property for additional security
+        System.setProperty("jdk.serialFilter", 
+            "java.rmi.server.*;java.lang.*;java.util.*;!*");
+        
+        System.out.println("[SECURITY] JEP 290 deserialization filter configured");
+    }
+    
+    /**
+     * Create RMI registry with SSL and restricted binding
+     */
+    public static Registry createSecureRegistry(int port) throws RemoteException {
+        // Configure SSL socket factories
+        RMIClientSocketFactory csf = new SslRMIClientSocketFactory();
+        RMIServerSocketFactory ssf = new SslRMIServerSocketFactory();
+        
+        // Restrict binding to localhost only (not 0.0.0.0)
+        String bindAddress = "127.0.0.1";
+        
+        System.setProperty("java.rmi.server.hostname", bindAddress);
+        System.setProperty("java.rmi.server.useLocalHostname", "true");
+        
+        // Create registry with SSL and restricted binding
+