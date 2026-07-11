import java.rmi.server.UnicastRemoteObject;
import java.security.AccessController;
import java.security.PrivilegedAction;

public class SafeUnicastRemoteObject extends UnicastRemoteObject {
    protected SafeUnicastRemoteObject() throws RemoteException {
        super();
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
                // Disable Runtime.exec()
                System.setSecurityManager(new SecurityManager() {
                    @Override
                    public void checkExec(String cmd) {
                        throw new SecurityException("Runtime.exec() is disabled");
                    }
                });
                return null;
            }
        });
    }
}