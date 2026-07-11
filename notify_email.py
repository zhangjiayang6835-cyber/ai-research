// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC777/IERC777Receiver.sol";

contract SafeWithdrawal {
    using ECDSA for bytes32;

    modifier notReentrant() {
        require(!reentrancyGuard._reentrancyBitSet, "Reentrancy detected");
        _;
        reentrancyGuard._reentrancyBitSet = false;
    }

    ReentrancyGuard private reentrancyGuard;

    constructor() {
        reentrancyGuard = new ReentrancyGuard();
    }

    function withdraw(uint256 amount) external notReentrant {
        // Update balance
        uint256 oldBalance = address(this).balance;
        require(oldBalance >= amount, "Insufficient funds");

        // Transfer to user
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Failed to send Ether");

        // Emit event or log the withdrawal
    }

    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata data,
        bytes calldata operatorData
    ) external virtual override {
        // Handle ERC-777 token transfer, but do not call withdraw() here
    }
}