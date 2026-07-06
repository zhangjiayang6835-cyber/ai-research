class Bank:
    def __init__(self):
        self.balances = {}
        self._locked = False

    def withdraw(self, amount, sender):
        if self._locked:
            raise Exception("ReentrancyGuard: reentrant call")
        self._locked = True
        try:
            if self.balances.get(sender, 0) < amount:
                raise Exception("Insufficient balance")
            # Update state before external call (checks-effects-interactions pattern)
            self.balances[sender] -= amount
            # External call (e.g., sending ETH) - assume it can trigger reentrancy
            # In real scenario, use call() with gas limit
            self._send_eth(sender, amount)
        finally:
            self._locked = False

    def _send_eth(self, sender, amount):
        # Simulate external transfer; in a real contract, this would be a low-level call
        # For demonstration, we just mark it as successful
        pass
