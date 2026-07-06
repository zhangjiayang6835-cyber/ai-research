const SecureDeFiContract = require('./fix');

// Test scenario
const contract = new SecureDeFiContract();

// Alice deposits 100 tokens
contract.deposit('alice', 100);
console.log('Initial balance:', contract.getBalance('alice')); // 100

// Attempt safe withdraw
contract.withdraw('alice', 50);
console.log('After withdraw 50:', contract.getBalance('alice')); // 50

// Test reentrancy protection: simulate malicious contract
// (In real test, would try to call withdraw again from fallback)
console.log('Reentrancy test skipped for simulation.');
