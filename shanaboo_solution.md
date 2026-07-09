Based on the issue description, this is a race condition in a distributed transaction system causing double-spending. I need to create a payment/transaction system with proper locking mechanisms. Since the repo structure shows various fix files and a `src` directory, I'll create the fix in the appropriate location.

Let me check what existing files might be relevant. The issue mentions a payment system with "check balance → deduct → confirm" operations. I'll create a comprehensive fix that implements:
1. Database transaction with row-level locking
2. Optimistic locking with version numbers
3. Balance non-negative check after deduction

```diff
--- /dev/null
+++ b/src/payment_service.py
@@ -0,0 +1,148 @@
+"""
+Distributed Transaction Payment Service with Race Condition Protection.
+
+Implements:
+- Database transaction with row-level locking (SELECT ... FOR UPDATE)
+- Optimistic locking with version numbers
+- Post-deduction balance non-negative check
+"""
+
+import threading
+import time
+from dataclasses import dataclass
+from typing import Optional
+from contextlib import contextmanager
+import sqlite3
+
+
+@dataclass
+class Account:
+    """Account model with optimistic lock version."""
+    id: int
+    balance: float
+    version: int
+
+
+class InsufficientFundsError(Exception):
+    """Raised when account has insufficient balance."""
+    pass
+
+
+class ConcurrentModificationError(Exception):
+    """Raised when optimistic lock conflict is detected."""
+    pass
+
+
+class PaymentService:
+    """
+    Thread-safe payment service with dual locking strategies.
+    
+    Strategy 1: Pessimistic Locking (SELECT ... FOR UPDATE)
+    - Uses database row-level locks to serialize access
+    - Prevents concurrent modifications entirely
+    
+    Strategy 2: Optimistic Locking (Version Number)
+    - Uses version column to detect concurrent modifications
+    - Retries on conflict instead of blocking
+    """
+    
+    def __init__(self, db_path: str = ":memory:", use_pessimistic: bool = True):
+        """
+        Initialize payment service.
+        
+        Args:
+            db_path: Path to SQLite database (use :memory: for testing)
+            use_pessimistic: True for pessimistic locking, False for optimistic
+        """
+        self.db_path = db_path
+        self.use_pessimistic = use_pessimistic
+        self._lock = threading.Lock()
+        self._init_db()
+    
+    def _init_db(self):
+        """Initialize database schema with version column for optimistic locking."""
+        with self._get_connection() as conn:
+            conn.execute("""
+                CREATE TABLE IF NOT EXISTS accounts (
+                    id INTEGER PRIMARY KEY,
+                    balance REAL NOT NULL DEFAULT 0.0,
+                    version INTEGER NOT NULL DEFAULT 1
+                )
+            """)
+            conn.execute("""
+                CREATE TABLE IF NOT EXISTS transactions (
+                    id INTEGER PRIMARY KEY AUTOINCREMENT,
+                    account_id INTEGER NOT NULL,
+                    amount REAL NOT NULL,
+                    type TEXT NOT NULL CHECK(type IN ('credit', 'debit')),
+                    timestamp REAL NOT NULL,
+                    FOREIGN KEY (account_id) REFERENCES accounts(id)
+                )
+            """)
+            conn.commit()
+    
+    @contextmanager
+    def _get_connection(self):
+        """Get a database connection with WAL mode for better concurrency."""
+        conn = sqlite3.connect(self.db_path, check_same_thread=False)
+        conn.execute("PRAGMA journal_mode=WAL")
+        conn.execute("PRAGMA foreign_keys=ON")
+        try:
+            yield conn
+        finally:
+            conn.close()
+    
+    def create_account(self, account_id: int, initial_balance: float = 0.0) -> Account:
+        """Create a new account with initial balance."""
+        with self._get_connection() as conn:
+            conn.execute(
+                "INSERT INTO accounts (id, balance, version) VALUES (?, ?, 1)",
+                (account_id, initial_balance)
+            )
+            conn.commit()
+        return Account(id=account_id, balance=initial_balance, version=1)
+    
+    def get_balance(self, account_id: int) -> Optional[Account]:
+        """Get account balance and version."""
+        with self._get_connection() as conn:
+            cursor = conn.execute(
+                "SELECT id, balance, version FROM accounts WHERE id = ?",
+                (account_id,)
+            )
+            row = cursor.fetchone()
+            if row:
+                return Account(id=row[0], balance=row[1], version=row[2])
+            return None
+    
+    def deduct_pessimistic(self, account_id: int, amount: float) -> Account:
+        """
+        Deduct using pessimistic locking (SELECT ... FOR UPDATE equivalent).
+        
+        In SQLite, we use BEGIN IMMEDIATE transaction which acquires
+        a reserved lock, preventing other writers from proceeding.
+        """
+        with self._get_connection() as conn:
+            # BEGIN IMMEDIATE acquires write lock immediately
+            conn.execute("BEGIN IMMEDIATE")
+            try:
+                # Row-level lock via SELECT within transaction
+                cursor = conn.execute(
+                    "SELECT balance, version FROM accounts WHERE id = ?",
+                    (account_id,)
+                )
+                row = cursor.fetchone()
+                if not row:
+                    raise ValueError(f"Account {account_id} not found")
+                
+                current_balance = row[0]
+                
+                # Check sufficient balance BEFORE deduction
+                if current_balance < amount:
+                    raise InsufficientFundsError(
+                        f"Insufficient balance: {current_balance} < {amount}"
+                    )
+                
+                new_balance = current_balance - amount
+                
+                # Post-deduction balance non-negative check (defense in depth)
+                if new_balance < 0:
+                    raise InsufficientFundsError(
+                        f"Balance would become negative: {new_balance}"
+                    )
+                
+                # Update balance and increment version
+                conn.execute(
+                    "UPDATE accounts SET balance = ?, version = version + 1 WHERE id = ?",
+                    (new_balance, account_id)
+                )
+                
+                # Record transaction
+                conn.execute(
+                    "INSERT INTO transactions (account_id, amount, type, timestamp) VALUES (?, ?, 'debit', ?)",
+                    (account_id, amount, time.time())
+                )
+                
+                conn.commit()
+                return Account(id=account_id, balance=new_balance, version=row[1] + 1)
