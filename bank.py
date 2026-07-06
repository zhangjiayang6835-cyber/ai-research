import threading

class Bank:
    def __init__(self):
        self.balances = {}
        self.lock = threading.Lock()

    def deposit(self, user, amount):
        self.balances[user] = self.balances.get(user, 0) + amount

    def withdraw(self, user, amount):
        # Vulnerable version: state updated after external call
        if self.balances.get(user, 0) >= amount:
            # Simulate external call that could re-enter
            self.send_eth(user, amount)
            self.balances[user] -= amount
            return True
        return False

    def send_eth(self, user, amount):
        # In real contract this sends Ether; here we allow re-entrancy
        # Malicious receiver would call withdraw again
        pass

    # Fixed version using checks-effects-interactions pattern
    def withdraw_fixed(self, user, amount):
        if self.balances.get(user, 0) < amount:
            return False
        # Effects: update state first
        self.balances[user] -= amount
        # Interactions: external call after state update
        self.send_eth(user, amount)
        return True

    # Alternative fix: reentrancy guard
    _entered = False

    def withdraw_guarded(self, user, amount):
        if self._entered:
            raise Exception("Reentrancy detected")
        self._entered = True
        try:
            if self.balances.get(user, 0) < amount:
                return False
            self.balances[user] -= amount
            self.send_eth(user, amount)
            return True
        finally:
            self._entered = False
