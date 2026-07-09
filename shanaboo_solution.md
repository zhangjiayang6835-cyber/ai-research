Based on the issue description, this is a race condition in a distributed transaction system that allows double spending. I need to implement a fix using database transactions with row-level locking, optimistic locking with version numbers, and balance validation.

Looking at the repository structure, I can see there's a `src` directory and various fix files. The issue mentions a payment system with "check balance → deduct → confirm" operations. I'll create a proper fix file that implements the required solution.

Let me check if there's an existing payment-related file in the `src` directory or if I need to create one based on the patterns I see in the repo.

Given the repo structure and the existing fix files like `fix_issue_341.py`, `fix_issue_342.py`, etc., I'll create a comprehensive fix that addresses the race condition with:
1. Database transaction with row-level locking (SELECT FOR UPDATE)
2. Optimistic locking with version numbers
3. Balance non-negative check after deduction

```diff
--- /dev/null
+++ b/fix_race_condition_double_spend.py
@@ -0,0 +1,198 @@
+"""
+Fix: Race Condition in Distributed Transaction → Double Spend Attack
+
+This module implements a secure payment processing system that prevents
+double-spend attacks caused by race conditions in the
+"check balance → deduct → confirm" flow.
+
+Solutions implemented:
+1. Database transaction with row-level locking (SELECT ... FOR UPDATE)
+2. Optimistic locking with version numbers
+3. Post-deduction balance non-negative check
+"""
+
+import threading
+import time
+from contextlib import contextmanager
+from dataclasses import dataclass
+from enum import Enum
+from typing import Optional, Tuple
+import sqlite3
+
+
+class TransactionStatus(Enum):
+    PENDING = "pending"
+    COMPLETED = "completed"
+    FAILED = "failed"
+    INSUFFICIENT_FUNDS = "insufficient_funds"
+
+
+@dataclass
+class Account:
+    """Account model with optimistic locking version field."""
+    id: int
+    balance: float
+    version: int
+
+
+@dataclass
+class PaymentTransaction:
+    """Payment transaction record."""
+    id: int
+    account_id: int
+    amount: float
+    status: TransactionStatus
+    created_at: float
+
+
+class DatabaseConnection:
+    """Thread-safe database connection pool for SQLite."""
+    
+    def __init__(self, db_path: str = ":memory:"):
+        self.db_path = db_path
+        self._local = threading.local()
+        self._lock = threading.Lock()
+        self._init_db()
+    
+    def _get_connection(self) -> sqlite3.Connection:
+        """Get thread-local database connection."""
+        if not hasattr(self._local, 'connection') or self._local.connection is None:
+            conn = sqlite3.connect(self.db_path, check_same_thread=False)
+            conn.execute("PRAGMA journal_mode=WAL")
+            conn.execute("PRAGMA busy_timeout=5000")
+            conn.row_factory = sqlite3.Row
+            self._local.connection = conn
+        return self._local.connection
+    
+    def _init_db(self):
+        """Initialize database schema."""
+        conn = self._get_connection()
+        conn.executescript("""
+            CREATE TABLE IF NOT EXISTS accounts (
+                id INTEGER PRIMARY KEY AUTOINCREMENT,
+                balance REAL NOT NULL DEFAULT 0.0,
+                version INTEGER NOT NULL DEFAULT 1,
+                CHECK (balance >= 0)
+            );
+            
+            CREATE TABLE IF NOT EXISTS transactions (
+                id INTEGER PRIMARY KEY AUTOINCREMENT,
+                account_id INTEGER NOT NULL,
+                amount REAL NOT NULL,
+                status TEXT NOT NULL DEFAULT 'pending',
+                created_at REAL NOT NULL,
+                FOREIGN KEY (account_id) REFERENCES accounts(id)
+            );
+            
+            CREATE INDEX IF NOT EXISTS idx_transactions_account 
+                ON transactions(account_id, status);
+        """)
+        conn.commit()
+    
+    @contextmanager
+    def transaction(self):
+        """Context manager for database transactions with row-level locking."""
+        conn = self._get_connection()
+        try:
+            conn.execute("BEGIN IMMEDIATE")
+            yield conn
+            conn.commit()
+        except Exception:
+            conn.rollback()
+            raise
+
+
+class PaymentService:
+    """
+    Secure payment service that prevents double-spend attacks.
+    
+    Uses a combination of:
+    - Pessimistic locking (SELECT ... FOR UPDATE equivalent via BEGIN IMMEDIATE)
+    - Optimistic locking (version number check)
+    - Post-deduction balance validation
+    """
+    
+    def __init__(self, db: DatabaseConnection):
+        self.db = db
+        self._operation_lock = threading.Lock()
+    
+    def create_account(self, initial_balance: float = 1000.0) -> int:
+        """Create a new account with initial balance."""
+        if initial_balance < 0:
+            raise ValueError("Initial balance cannot be negative")
+        
+        with self.db.transaction() as conn:
+            cursor = conn.execute(
+                "INSERT INTO accounts (balance, version) VALUES (?, 1)",
+                (initial_balance,)
+            )
+            return cursor.lastrowid
+    
+    def get_balance(self, account_id: int) -> Optional[float]:
+        """Get current account balance (non-locking read)."""
+        conn = self.db._get_connection()
+        cursor = conn.execute(
+            "SELECT balance FROM accounts WHERE id = ?",
+            (account_id,)
+        )
+        row = cursor.fetchone()
+        return row["balance"] if row else None
+    
+    def process_payment_pessimistic(
+        self, account_id: int, amount: float
+    ) -> Tuple[bool, str]:
+        """
+        Process payment using pessimistic locking (row-level lock).
+        
+        Uses BEGIN IMMEDIATE to acquire exclusive lock on the database,
+        then SELECTs the account row within the transaction to prevent
+        concurrent modifications.
+        """
+        if amount <= 0:
+            return False, "Amount must be positive"
+        
+        with self.db.transaction() as conn:
+            # Row-level lock: SELECT the account within the transaction
+            cursor = conn.execute(
+                "SELECT id, balance, version FROM accounts WHERE id = ?",
+                (account_id,)
+            )
+            row = cursor.fetchone()
+            
+            if not row:
+                return False, "Account not found"
+            
