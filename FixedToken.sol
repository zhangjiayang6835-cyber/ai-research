// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract FixedToken is ERC20, Ownable {
    constructor() ERC20("FixedToken", "FIX") {
        _mint(msg.sender, 1000 * 10 ** decimals());
    }

    // No vulnerable functions because Solidity 0.8+ has built-in overflow checks.
    // This contract is secure against integer overflow.
}
