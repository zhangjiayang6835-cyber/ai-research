// Secure DeFi Withdraw - preventing reentrancy attack
class SecureDeFiContract {
  constructor() {
    this.balances = {}; // track user balances
    this.locked = false; // reentrancy guard
  }

  // Deposit function (no vulnerability here)
  deposit(user, amount) {
    if (!this.balances[user]) this.balances[user] = 0;
    this.balances[user] += amount;
  }

  // Vulnerable withdraw (original buggy version for reference)
  withdraw_vulnerable(user, amount) {
    // !!! VULNERABLE: state update after external call
    require(this.balances[user] >= amount, 'Insufficient balance');
    // External call first (simulate sending Ether)
    this._sendEther(user, amount);
    // Then update state (too late!)
    this.balances[user] -= amount;
  }

  // Fixed withdraw using Checks-Effects-Interactions pattern
  withdraw(user, amount) {
    // Reentrancy guard
    require(!this.locked, 'Reentrancy detected');
    this.locked = true;

    // 1. Checks
    require(this.balances[user] >= amount, 'Insufficient balance');

    // 2. Effects (update state first)
    this.balances[user] -= amount;

    // 3. Interactions (external call after state update)
    this._sendEther(user, amount);

    // Unlock
    this.locked = false;
  }

  // Simulated external call (e.g., send Ether)
  _sendEther(user, amount) {
    // In real contract: call.value(amount)() or transfer
    console.log(`Sending ${amount} to ${user}...`);
    // Potential malicious fallback would call back into withdraw
  }

  // Helper to check balance
  getBalance(user) {
    return this.balances[user] || 0;
  }
}

// Export for testing
module.exports = SecureDeFiContract;
