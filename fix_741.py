```python
import threading
import time

class SafeDistributedTransaction:
    """
    This class ensures that distributed transactions are executed in a thread-safe manner to avoid race conditions.
    It uses locks to ensure that only one transaction is processed at a time across multiple threads.
    """

    def __init__(self):
        self.lock = threading.Lock()

    def process_transaction(self, transaction_id):
        """
        Process the given transaction safely without causing race conditions.
        :param transaction_id: Identifier for the transaction
        """
        with self.lock:
            print(f"Processing transaction {transaction_id} in thread {threading.current_thread().name}")
            # Simulate processing time
            time.sleep(1)
            print(f"Transaction {transaction_id} processed successfully")

def main():
    num_transactions = 5

    transactions = SafeDistributedTransaction()

    threads = []
    for i in range(num_transactions):
        thread = threading.Thread(target=transactions.process_transaction, args=(i,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    main()
```
```python
import threading
import time

class SafeDistributedTransaction:
    """
    This class ensures that distributed transactions are executed in a thread-safe manner to avoid race conditions.
    It uses locks to ensure that only one transaction is processed at a time across multiple threads.
    """

    def __init__(self):
        self.lock = threading.Lock()

    def process_transaction(self, transaction_id):
        """
        Process the given transaction safely without causing race conditions.
        :param transaction_id: Identifier for the transaction
        """
        with self.lock:
            print(f"Processing transaction {transaction_id} in thread {threading.current_thread().name}")
            # Simulate processing time
            time.sleep(1)
            print(f"Transaction {transaction_id} processed successfully")

def main():
    num_transactions = 5

    transactions = SafeDistributedTransaction()

    threads = []
    for i in range(num_transactions):
        thread = threading.Thread(target=transactions.process_transaction, args=(i,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    main()
```