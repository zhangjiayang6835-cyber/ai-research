class DeFiVault:
    def __init__(self):
        self.balances = {}
        self._reentrancy_guard = False

    def deposit(self, user, amount):
        if user not in self.balances:
            self.balances[user] = 0
        self.balances[user] += amount

    def withdraw(self, user, amount):
        if self._reentrancy_guard:
            raise Exception("Reentrancy attack detected")
        self._reentrancy_guard = True
        try:
            if self.balances.get(user, 0) < amount:
                raise Exception("Insufficient balance")
            self.balances[user] -= amount
            # External call (simulated)
            self._transfer(user, amount)
        finally:
            self._reentrancy_guard = False

    def _transfer(self, user, amount):
        # Placeholder for actual token/ether transfer
        pass
