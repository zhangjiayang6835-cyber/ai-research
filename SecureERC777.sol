// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC777/ERC777.sol";
import "@openzeppelin/contracts/utils/Context.sol";

contract SecureERC777 is Context, ERC777 {
    // State variable to prevent reentrancy
    bool private _notEntered = true;

    constructor(
        string memory name,
        string memory symbol,
        address[] memory defaultOperators
    ) ERC777(name, symbol, defaultOperators) {}

    // Modifier to prevent reentrancy
    modifier nonReentrant() {
        require(_notEntered, "ReentrancyGuard: reentrant call");
        _notEntered = false;
        _;
        _notEntered = true;
    }

    // Override the tokensReceived function to prevent reentrancy
    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external override {
        require(_notEntered, "ReentrancyGuard: reentrant call");
        _notEntered = false;
        super.tokensReceived(operator, from, to, amount, userData, operatorData);
        _notEntered = true;
    }

    // Example function that transfers tokens and prevents reentrancy
    function safeTransferFrom(
        address from,
        address to,
        uint256 amount,
        bytes calldata data
    ) external nonReentrant {
        _transfer(from, to, amount, data);
    }

    // Example function that handles state changes before external calls
    function transferAndCall(
        address to,
        uint256 amount,
        bytes calldata data
    ) external nonReentrant {
        // Perform state changes first
        _transfer(_msgSender(), to, amount, data);

        // Make the external call after state changes
        (bool success, ) = to.call(data);
        require(success, "External call failed");
    }
}