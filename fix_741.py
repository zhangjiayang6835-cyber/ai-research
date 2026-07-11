```python
import sqlite3
from contextlib import closing

# Database connection setup
DATABASE = 'payment.db'

def create_table():
    with closing(sqlite3.connect(DATABASE)) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY,
                balance REAL NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY,
                account_id INTEGER NOT NULL,
                amount REAL NOT NULL,
                version INTEGER NOT NULL,
                FOREIGN KEY (account_id) REFERENCES accounts(id)
            )
        ''')
        conn.commit()

def get_balance(account_id):
    with closing(sqlite3.connect(DATABASE)) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT balance FROM accounts WHERE id = ?', (account_id,))
        row = cursor.fetchone()
        return row[0] if row else 0

def withdraw(account_id, amount, version):
    with closing(sqlite3.connect(DATABASE)) as conn:
        cursor = conn.cursor()
        # Use SELECT FOR UPDATE to lock the row for update
        cursor.execute('''
            SELECT balance, version FROM accounts WHERE id = ? AND version = ?
            FOR UPDATE
        ''', (account_id, version))
        row = cursor.fetchone()

        if not row or row[0] < amount:
            return False

        # If the balance check passed, proceed with transaction
        current_balance, current_version = row

        cursor.execute('''
            INSERT INTO transactions (account_id, amount, version)
            VALUES (?, ?, ?)
        ''', (account_id, -amount, current_version))

        new_balance = current_balance - amount
        if new_balance >= 0:
            cursor.execute('''
                UPDATE accounts SET balance = ?
                WHERE id = ? AND version = ?
            ''', (new_balance, account_id, current_version))
            return True

    return False

def main():
    create_table()
    
    # Simulate an existing account with a balance of $100 and version 1
    initial_balance = 100.0
    with closing(sqlite3.connect(DATABASE)) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO accounts (id, balance)
            VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET balance = ?
        ''', (1, initial_balance, initial_balance))
        cursor.execute('''
            INSERT INTO transactions (account_id, amount, version)
            VALUES (?, ?, ?)
        ''', (1, 0, 1))

    # Perform a withdrawal
    result = withdraw(1, 50.0, 1)
    print(f"Withdrawal successful: {result}")

if __name__ == "__main__":
    main()
```

This code demonstrates the use of database transactions and row-level locks to prevent double spending in a distributed transaction scenario.