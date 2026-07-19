// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title FixedWithdraw
 * @notice Demonstrates the fix against ERC-777 callback reentrancy in withdraw functions.
 * 
 * Vulnerability: When a contract calls `send` on an ERC-777 token, the token contract
 * invokes the recipient's `tokensReceived` hook. If the recipient is a malicious contract,
 * it can reenter the withdraw function before the sender's balance is updated, draining
 * funds.
 * 
 * Fix: Use a reentrancy guard (e.g., OpenZeppelin's nonReentrant modifier) and apply
 * the checks-effects-interactions pattern: update state before making the external call.
 */
contract FixedWithdraw {
    mapping(address => uint256) public balances;
    address public token; // Address of the ERC-777 token contract

    // Reentrancy guard (custom implementation for simplicity)
    uint256 private _status = 0;
    modifier nonReentrant() {
        // Only one reentrancy allowed
        require(_status == 0, "ReentrancyGuard: reentrant call");
        _status = 1;
        _;
        _status = 0;
    }

    constructor(address _token) {
        token = _token;
    }

    /**
     * @notice Withdraws all tokens of the caller.
     * Fixed using nonReentrant and state update before external call.
     */
    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance to withdraw");

        // Effects: update state first
        balances[msg.sender] = 0;

        // Interactions: transfer tokens via ERC-777 send
