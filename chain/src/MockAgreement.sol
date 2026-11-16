// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

/// @notice Mock of Bull's Agreement contract implementing ONLY the DOCUMENTED
/// semantics from https://www.bull.family/llms.txt: the payer locks funds; the
/// payee is paid when ALL conditions are true; after expiry anyone can refund
/// the payer. The real BullAgreement source is NOT verified anywhere
/// (Sourcify/Blockscout return no match), so this mock mirrors the documented
/// interface and behavior. The PoC's claim is about the SDK — which sends the
/// server's inflated steps without verification — not about this mock's
/// internals. The mock pulls funds with a plain transferFrom and releases
/// them when the documented condition (attest by the named wallet) is met.
contract MockAgreement {
    struct Condition {
        uint8 kind; // 1 = attest
        address by;
    }
    struct Agreement {
        address payer;
        address payee;
        address asset;
        uint256 amount;
        uint64 expiry;
        bytes32 termsHash;
        bool released;
        bool refunded;
        Condition[] conditions;
        mapping(uint256 => mapping(address => bool)) attested;
    }

    uint256 public nextId = 1;
    mapping(uint256 => Agreement) internal _agreements;
    address public immutable treasury;
    address public immutable feeSigner;

    event AgreementCreated(uint256 indexed id, address indexed payer, address indexed payee, address asset, uint256 amount, uint64 expiry, bytes32 termsHash);

    constructor(address _treasury, address _feeSigner) {
        treasury = _treasury;
        feeSigner = _feeSigner;
    }

    struct Params {
        address payee;
        address asset;
        uint256 amount;
        uint64 expiry;
        bytes32 termsHash;
    }

    function createAgreement(Params calldata p, Condition[] calldata conds) external payable returns (uint256 id) {
        require(p.payee != address(0) && p.amount > 0 && p.expiry > block.timestamp, "bad input");
        id = nextId++;
        Agreement storage a = _agreements[id];
        a.payer = msg.sender;
        a.payee = p.payee;
        a.asset = p.asset;
        a.amount = p.amount;
        a.expiry = p.expiry;
        a.termsHash = p.termsHash;
        for (uint256 i = 0; i < conds.length; i++) {
            a.conditions.push(conds[i]);
        }
        if (p.asset == address(0)) {
            require(msg.value >= p.amount, "need eth");
        } else {
            require(IERC20(p.asset).transferFrom(msg.sender, address(this), p.amount), "pull failed");
        }
        emit AgreementCreated(id, msg.sender, p.payee, p.asset, p.amount, p.expiry, p.termsHash);
    }

    function attest(uint256 id, uint256 index) external {
        Agreement storage a = _agreements[id];
        require(index < a.conditions.length, "no condition");
        require(!a.released && !a.refunded, "closed");
        a.attested[index][msg.sender] = true;
    }

    function conditionsMet(uint256 id) public view returns (bool) {
        Agreement storage a = _agreements[id];
        for (uint256 i = 0; i < a.conditions.length; i++) {
            if (a.conditions[i].kind == 1) {
                if (!a.attested[i][a.conditions[i].by]) return false;
            } else {
                return false;
            }
        }
        return true;
    }

    function release(uint256 id) external {
        Agreement storage a = _agreements[id];
        require(!a.released && !a.refunded, "closed");
        require(conditionsMet(id), "conditions not met");
        a.released = true;
        _send(a.asset, a.payee, a.amount);
    }

    function refund(uint256 id) external {
        Agreement storage a = _agreements[id];
        require(!a.released && !a.refunded, "closed");
        require(block.timestamp > a.expiry, "not expired");
        a.refunded = true;
        _send(a.asset, a.payer, a.amount);
    }

    function _send(address token, address to, uint256 amount) private {
        if (token == address(0)) {
            (bool ok, ) = to.call{value: amount}("");
            require(ok, "eth send failed");
        } else {
            require(IERC20(token).transfer(to, amount), "token send failed");
        }
    }

    function agreement(uint256 id) external view returns (address payer, address payee, address asset, uint256 amount, uint64 expiry, bytes32 termsHash) {
        Agreement storage a = _agreements[id];
        return (a.payer, a.payee, a.asset, a.amount, a.expiry, a.termsHash);
    }
}
