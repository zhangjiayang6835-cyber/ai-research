// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title SecureToken - Fixed Integer Overflow Vulnerability
 * @notice This contract fixes the integer overflow vulnerability that could lead to token theft.
 *         Solidity 0.8+ has built-in overflow/underflow checks, replacing the need for SafeMath.
 */
contract SecureToken {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
    
    uint256 public totalSupply;
    string public name;
    string public symbol;
    uint8 public decimals;
    
    address public owner;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }
    
    constructor(string memory _name, string memory _symbol, uint8 _decimals, uint256 _initialSupply) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
        owner = msg.sender;
        
        // Safe minting - Solidity 0.8+ auto-reverts on overflow
        totalSupply = _initialSupply * (10 ** uint256(_decimals));
        balances[msg.sender] = totalSupply;
        emit Transfer(address(0), msg.sender, totalSupply);
    }
    
    /**
     * @notice Transfer tokens with built-in overflow protection (Solidity 0.8+)
     * @dev Previously vulnerable to integer overflow in balance checks.
     *      Now uses Solidity 0.8+ automatic overflow checks.
     */
    function transfer(address _to, uint256 _value) public returns (bool success) {
        // Solidity 0.8+ automatically reverts on underflow here
        require(balances[msg.sender] >= _value, "Insufficient balance");
        
        // These operations are now overflow/underflow safe in Solidity 0.8+
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
    
    /**
     * @notice Transfer from with built-in overflow protection
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(balances[_from] >= _value, "Insufficient balance");
        require(allowances[_from][msg.sender] >= _value, "Insufficient allowance");
        
        // Safe arithmetic with Solidity 0.8+ built-in checks
        balances[_from] -= _value;
        balances[_to] += _value;
        allowances[_from][msg.sender] -= _value;
        
        emit Transfer(_from, _to, _value);
        return true;
    }
    
    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowances[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }
}
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title FixedToken - 修复整数溢出漏洞的ERC20代币合约
 *
 * 修复前的问题:
 * - 使用 Solidity < 0.8.0 时，uint256 的加法和乘法会溢出
 * - 攻击者可利用溢出盗取代币
 *
 * 修复方案:
 * - 使用 Solidity 0.8.0+，默认启用安全数学检查
 * - 或者使用 OpenZeppelin 的 SafeMath 库（对于 0.8.0+ 不再需要）
 * - 所有算术操作自动回滚于溢出
 *
 * 本合约展示最佳实践: 继承 ERC20 标准实现
 */
contract FixedToken {
    // 简化的ERC20实现 (仅展示核心逻辑)
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    uint256 public totalSupply;
    string public name;
    string public symbol;
    uint8 public decimals;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(
        uint256 initialSupply,
        string memory tokenName,
        string memory tokenSymbol,
        uint8 tokenDecimals
    ) {
        name = tokenName;
        symbol = tokenSymbol;
        decimals = tokenDecimals;
        totalSupply = initialSupply * 10 ** tokenDecimals;
        _balances[msg.sender] = totalSupply;
        emit Transfer(address(0), msg.sender, totalSupply);
    }

    function balanceOf(address account) public view returns (uint256) {
        return _balances[account];
    }

    function transfer(address recipient, uint256 amount) public returns (bool) {
        _transfer(msg.sender, recipient, amount);
        return true;
    }

    function allowance(address owner_, address spender) public view returns (uint256) {
        return _allowances[owner_][spender];
    }

    function approve(address spender, uint256 amount) public returns (bool) {
        _approve(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) public returns (bool) {
        _transfer(sender, recipient, amount);

        uint256 currentAllowance = _allowances[sender][msg.sender];
        require(currentAllowance >= amount, "ERC20: transfer amount exceeds allowance");
        unchecked {
            _approve(sender, msg.sender, currentAllowance - amount);
        }
        return true;
    }

    function _transfer(
        address sender,
        address recipient,
        uint256 amount
    ) internal {
        require(sender != address(0), "ERC20: transfer from the zero address");
        require(recipient != address(0), "ERC20: transfer to the zero address");

        uint256 senderBalance = _balances[sender];
        require(senderBalance >= amount, "ERC20: transfer amount exceeds balance");
        unchecked {
            _balances[sender] = senderBalance - amount;
        }
        _balances[recipient] += amount; // SafeMath 自动检测溢出

        emit Transfer(sender, recipient, amount);
    }

    function _approve(
        address owner,
        address spender,
        uint256 amount
    ) internal {
        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }
}

/**
 * 安全要点总结:
 * 1. 安全使用 Solidity >=0.8.0，算术异常自动回滚
 * 2. transferFrom 中 allowance 减法使用 unchecked 避免额外检查（因为已前置检查）
 * 3. 所有余额操作确保先检查后加减
 * 4. 不使用低层数学库，除非兼容安全标准
 *
 * 如果必须支持 <0.8.0 版本，需引入 OpenZeppelin SafeMath 库并包装所有算术操作。
 */
