// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract AgentRegistry {
    uint256 public constant MAX_DID_LENGTH = 255;
    uint256 public constant MAX_CONTROLLER_LENGTH = 255;
    uint256 public constant MAX_DOCUMENTREF_LENGTH = 1024;

    struct AgentRecord {
        string did;
        string controller;
        string createdAt;
        string revokedAt;
        string documentRef;
        bool exists;
        address owner;
    }

    mapping(string => AgentRecord) private records;

    address public immutable admin;
    bool public paused;

    event AgentRegistered(string did, string controller, string createdAt, address indexed owner);
    event AgentRevoked(string did, string revokedAt);
    event DocumentReferenceUpdated(string did, string documentRef, address indexed updatedBy);
    mapping(string => mapping(address => bool)) private revocationDelegates;
    event RevocationDelegateUpdated(string did, address indexed delegate, bool authorized);
    event AgentOwnershipTransferred(string did, address indexed previousOwner, address indexed newOwner);
    event Paused(address indexed account);
    event Unpaused(address indexed account);

    modifier whenNotPaused() {
        require(!paused, "contract paused");
        _;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function pause() external onlyAdmin {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyAdmin {
        paused = false;
        emit Unpaused(msg.sender);
    }

    function registerAgent(string calldata did, string calldata controller) external whenNotPaused {
        require(bytes(did).length > 0, "did required");
        require(bytes(did).length <= MAX_DID_LENGTH, "did too long");
        require(bytes(did).length >= 7, "did too short");
        require(bytes(did)[0] == 'd' && bytes(did)[1] == 'i' && bytes(did)[2] == 'd' && bytes(did)[3] == ':', "did must start with did:");
        require(bytes(controller).length > 0, "controller required");
        require(bytes(controller).length <= MAX_CONTROLLER_LENGTH, "controller too long");
        require(!records[did].exists, "already registered");

        string memory nowIso = _timestampToString(block.timestamp);

        records[did] = AgentRecord({
            did: did,
            controller: controller,
            createdAt: nowIso,
            revokedAt: "",
            documentRef: "",
            exists: true,
            owner: msg.sender
        });

        emit AgentRegistered(did, controller, nowIso, msg.sender);
    }

    function registerAgentWithDocument(
        string calldata did,
        string calldata controller,
        string calldata documentRef
    ) external whenNotPaused {
        require(bytes(did).length > 0, "did required");
        require(bytes(did).length <= MAX_DID_LENGTH, "did too long");
        require(bytes(did).length >= 7, "did too short");
        require(bytes(did)[0] == 'd' && bytes(did)[1] == 'i' && bytes(did)[2] == 'd' && bytes(did)[3] == ':', "did must start with did:");
        require(bytes(controller).length > 0, "controller required");
        require(bytes(controller).length <= MAX_CONTROLLER_LENGTH, "controller too long");
        require(!records[did].exists, "already registered");
        require(bytes(documentRef).length > 0, "documentRef required");
        require(bytes(documentRef).length <= MAX_DOCUMENTREF_LENGTH, "documentRef too long");

        string memory nowIso = _timestampToString(block.timestamp);

        records[did] = AgentRecord({
            did: did,
            controller: controller,
            createdAt: nowIso,
            revokedAt: "",
            documentRef: documentRef,
            exists: true,
            owner: msg.sender
        });

        emit AgentRegistered(did, controller, nowIso, msg.sender);
        emit DocumentReferenceUpdated(did, documentRef, msg.sender);
    }

    function revokeAgent(string calldata did) external whenNotPaused {
        AgentRecord storage record = records[did];

        require(record.exists, "not found");
        require(bytes(record.revokedAt).length == 0, "already revoked");
        require(_isAuthorizedRevoker(did, msg.sender), "not authorized");

        string memory nowIso = _timestampToString(block.timestamp);
        record.revokedAt = nowIso;

        emit AgentRevoked(did, nowIso);
    }

    function setRevocationDelegate(string calldata did, address delegate, bool authorized) external whenNotPaused {
        AgentRecord storage record = records[did];

        require(record.exists, "not found");
        require(record.owner == msg.sender, "only owner");
        require(delegate != address(0), "delegate required");

        revocationDelegates[did][delegate] = authorized;
        emit RevocationDelegateUpdated(did, delegate, authorized);
    }

    function transferAgentOwnership(string calldata did, address newOwner) external whenNotPaused {
        AgentRecord storage record = records[did];

        require(record.exists, "not found");
        require(record.owner == msg.sender, "only owner");
        require(newOwner != address(0), "newOwner required");

        address previousOwner = record.owner;
        record.owner = newOwner;

        emit AgentOwnershipTransferred(did, previousOwner, newOwner);
    }

    function isRevocationDelegate(string calldata did, address delegate) external view returns (bool) {
        return revocationDelegates[did][delegate];
    }

    function setDocumentRef(string calldata did, string calldata documentRef) external whenNotPaused {
        AgentRecord storage record = records[did];

        require(record.exists, "not found");
        require(record.owner == msg.sender, "only owner");
        require(bytes(documentRef).length > 0, "documentRef required");
        require(bytes(documentRef).length <= MAX_DOCUMENTREF_LENGTH, "documentRef too long");

        record.documentRef = documentRef;
        emit DocumentReferenceUpdated(did, documentRef, msg.sender);
    }

    function getAgentRecord(string calldata did)
        external
        view
        returns (
            string memory recordDid,
            string memory controller,
            string memory createdAt,
            string memory revokedAt,
            string memory documentRef
        )
    {
        AgentRecord memory record = records[did];
        require(record.exists, "not found");

        return (
            record.did,
            record.controller,
            record.createdAt,
            record.revokedAt,
            record.documentRef
        );
    }

    function isRevoked(string calldata did) external view returns (bool) {
        AgentRecord memory record = records[did];
        if (!record.exists) {
            return false;
        }

        return bytes(record.revokedAt).length > 0;
    }

    function _timestampToString(uint256 timestamp) private pure returns (string memory) {
        return _toString(timestamp);
    }

    function _isAuthorizedRevoker(string calldata did, address actor) private view returns (bool) {
        AgentRecord memory record = records[did];
        return record.owner == actor || revocationDelegates[did][actor];
    }

    function _toString(uint256 value) private pure returns (string memory) {
        if (value == 0) {
            return "0";
        }

        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }

        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }

        return string(buffer);
    }
}
