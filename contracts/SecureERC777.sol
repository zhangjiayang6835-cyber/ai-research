// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC777/ERC777.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureERC777 is ERC777, Ownable {
    bool private _notEntered;

    constructor(
        string memory name,
        string memory symbol,
        address[] memory defaultOperators
    ) ERC777(name, symbol, defaultOperators) {
        _notEntered = true;
    }

    // Function to receive ETH (if needed)
    receive() external payable {}

    // Example function that needs protection from reentrancy
    function safeTransferFrom(
        address from,
        address to,
        uint256 amount,
        bytes calldata data
    ) public override {
        require(_notEntered, "ReentrancyGuard: reentrant call");
        _notEntered = false;

        // Perform the transfer
        super.safeTransferFrom(from, to, amount, data);

        // Reset the flag
        _notEntered = true;
    }

    // Another example function that needs protection from reentrancy
    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] memory amounts,
        bytes calldata data
    ) public override {
        require(_notEntered, "ReentrancyGuard: reentrant call");
        _notEntered = false;

        // Perform the batch transfer
        super.safeBatchTransferFrom(from, to, amounts, data);

        // Reset the flag
        _notEntered = true;
    }

    // Additional functions and logic can be added here
}