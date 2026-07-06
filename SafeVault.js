// SPDX-License-Identifier: MIT
// Fixed implementation to prevent reentrancy attack on DeFi withdraw function

class SafeVault {
  constructor() {
    this.balances = {};
    this._locked = false;
  }

  // Reentrancy guard: prevent recursive calls
  _noReentrant() {
    if (this._locked) {
      throw new Error('ReentrancyGuard: reentrant call');
    }
    this._locked = true;
  }

  _unlock() {
    this._locked = false;
  }

  deposit(user, amount) {
    if (!this.balances[user]) {
      this.balances[user] = 0;
    }
    this.balances[user] += amount;
  }

  withdraw(user, amount) {
    this._noReentrant();
    // Checks: sufficient balance
    if (!this.balances[user] || this.balances[user] < amount) {
      this._unlock();
      throw new Error('Insufficient balance');
    }
    // Effects: update balance before external call
    this.balances[user] -= amount;
    // Interactions: transfer funds (simulated external call)
    // In a real contract, this would call an external token transfer
    console.log(`Transferring ${amount} to ${user}`);
    this._unlock();
  }
}

module.exports = SafeVault;
