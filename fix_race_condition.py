import redis

class WalletService:
    """
    A wallet service that prevents double spending using atomic Redis Lua scripts.
    """

    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self._load_scripts()

    def _load_scripts(self) -> None:
        """
        Register Lua scripts for atomic transactions.
        """
        # Atomically check balance and deduct if sufficient.
        # Returns new balance on success, -1 if insufficient, nil if account missing.
        self.deduct_script = self.redis.register_script("""
            local balance = redis.call('GET', KEYS[1])
            if not balance then
                return nil
            end
            balance = tonumber(balance)
            if balance >= tonumber(ARGV[1]) then
                redis.call('DECRBY', KEYS[1], ARGV[1])
                return balance - tonumber(ARGV[1])
            else
                return -1
            end
        """)

    def transfer(self, from_account: str, to_account: str, amount: int) -> bool:
        """
        Transfer funds atomically, preventing double spending.

        Args:
            from_account: Source account key.
            to_account: Destination account key.
            amount: Amount to transfer (positive integer).

        Returns:
            True if transfer succeeded.

        Raises:
            ValueError: If account not found or insufficient funds.
        """
        if amount <= 0:
            raise ValueError("Amount must be positive")

        # Atomic deduction from source account
        new_balance = self.deduct_script(keys=[from_account], args=[amount])
        if new_balance is None:
            raise ValueError(f"Account '{from_account}' does not exist")
        if new_balance == -1:
            raise ValueError("Insufficient balance")

        # Credit to destination (no race condition for credit)
        self.redis.incrby(to_account, amount)
        return True


# Example usage (uncomment to test with a local Redis instance):
# if __name__ == '__main__':
#     client = redis.Redis(host='localhost', port=6379, db=0)
#     service = WalletService(client)
#     client.set('alice', 100)
#     client.set('bob', 0)
#     try:
#         service.transfer('alice', 'bob', 50)
#         print("Transfer succeeded")
#     except ValueError as e:
#         print(f"Transfer failed: {e}")
