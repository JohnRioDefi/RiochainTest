pragma solidity >=0.8.0;

contract MyToken {
/* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    address owner;
    string name;
    uint256 token_uid;

    event Transfer(address, uint256);
    
    /* Initializes contract with initial supply tokens to the creator of the contract */
    constructor() public {
        owner = 0x32Df1C41804a53ffE08B162fA02A3c2bae829258;
        balanceOf[owner] = 1000000000000000000;              
        // Give the creator all initial tokens

        name = "name";
        token_uid = 1;
    }

    event GetBalance(address, uint);
    function getBalance(address account) public returns (uint) {
        uint balance = balanceOf[account];
        emit GetBalance(account, balance);
        return balance;
    }
    
    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        require(balanceOf[msg.sender] >= _value);           
        // Check if the sender has enough
        require(balanceOf[_to] + _value >= balanceOf[_to]); 
        // Check for overflows
        balanceOf[msg.sender] -= _value;                    
        // Subtract from the sender
        balanceOf[_to] += _value;                  
        // Add the same to the recipient

        emit Transfer(_to, _value);
    }

    // for test
    event Print(uint);
    function multiply(uint a, uint b) public returns (uint) {
        emit Print(a * b);
        return a * b;
    }
}
