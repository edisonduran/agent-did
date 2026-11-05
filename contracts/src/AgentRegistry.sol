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

    /// @notice Registration attestation signed by the registrar (EIP-712).
    struct Attestation {
        address owner;
        uint256 deadline;
        bytes signature;
    }

    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant REGISTRATION_TYPEHASH = keccak256(
        "Registration(string did,string controller,string documentRef,address owner,uint256 deadline)"
    );
    bytes32 private constant NAME_HASH = keccak256("AgentRegistry");
    bytes32 private constant VERSION_HASH = keccak256("1");
    uint256 private constant HALF_CURVE_ORDER =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    address public immutable admin;
    /// @notice Address whose signature authorizes a registration. The registrar is trusted to have
    /// verified, off-chain, that `owner` controls the DID before signing.
    address public registrar;
    bool public paused;

    event AgentRegistered(string did, string controller, string createdAt, address indexed owner);
    event AgentRevoked(string did, string revokedAt);
    event DocumentReferenceUpdated(string did, string documentRef, address indexed updatedBy);
    mapping(string => mapping(address => bool)) private revocationDelegates;
    event RevocationDelegateUpdated(string did, address indexed delegate, bool authorized);
    event AgentOwnershipTransferred(string did, address indexed previousOwner, address indexed newOwner);
    event Paused(address indexed account);
    event Unpaused(address indexed account);
    event RegistrarUpdated(address indexed previousRegistrar, address indexed newRegistrar);

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
        registrar = msg.sender;
        emit RegistrarUpdated(address(0), msg.sender);
    }

    function setRegistrar(address newRegistrar) external onlyAdmin {
        require(newRegistrar != address(0), "registrar required");
        emit RegistrarUpdated(registrar, newRegistrar);
        registrar = newRegistrar;
    }

    function pause() external onlyAdmin {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyAdmin {
        paused = false;
        emit Unpaused(msg.sender);
    }

    /// @notice Registers `did` for the attested owner. Anyone may submit the transaction, but the
    /// registrar must have signed (did, controller, documentRef, owner, deadline) for this contract
    /// and chain. A DID can be registered once, so an attestation cannot be replayed.
    /// `documentRef` may be empty; set it later with `setDocumentRef`.
    function registerAgentAttested(
        string calldata did,
        string calldata controller,
        string calldata documentRef,
        Attestation calldata attestation
    ) external whenNotPaused {
        require(bytes(did).length > 0, "did required");
        require(bytes(did).length <= MAX_DID_LENGTH, "did too long");
        require(bytes(did).length >= 7, "did too short");
        require(bytes(did)[0] == 'd' && bytes(did)[1] == 'i' && bytes(did)[2] == 'd' && bytes(did)[3] == ':', "did must start with did:");
        require(bytes(controller).length > 0, "controller required");
        require(bytes(controller).length <= MAX_CONTROLLER_LENGTH, "controller too long");
        require(bytes(documentRef).length <= MAX_DOCUMENTREF_LENGTH, "documentRef too long");
        require(attestation.owner != address(0), "owner required");
        require(block.timestamp <= attestation.deadline, "attestation expired");
        require(!records[did].exists, "already registered");
        require(
            _recoverSigner(registrationDigest(did, controller, documentRef, attestation.owner, attestation.deadline), attestation.signature)
                == registrar,
            "invalid attestation"
        );

        string memory nowIso = _timestampToString(block.timestamp);

        records[did] = AgentRecord({
            did: did,
            controller: controller,
            createdAt: nowIso,
            revokedAt: "",
            documentRef: documentRef,
            exists: true,
            owner: attestation.owner
        });

        emit AgentRegistered(did, controller, nowIso, attestation.owner);
        if (bytes(documentRef).length > 0) {
            emit DocumentReferenceUpdated(did, documentRef, attestation.owner);
        }
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    /// @notice EIP-712 digest the registrar signs to authorize a registration.
    function registrationDigest(
        string calldata did,
        string calldata controller,
        string calldata documentRef,
        address owner,
        uint256 deadline
    ) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                REGISTRATION_TYPEHASH,
                keccak256(bytes(did)),
                keccak256(bytes(controller)),
                keccak256(bytes(documentRef)),
                owner,
                deadline
            )
        );
        return keccak256(abi.encodePacked(hex"1901", DOMAIN_SEPARATOR(), structHash));
    }

    function revokeAgent(string calldata did) external {
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

    function _recoverSigner(bytes32 digest, bytes calldata signature) private pure returns (address) {
        if (signature.length != 65) {
            return address(0);
        }
        bytes32 r = bytes32(signature[0:32]);
        bytes32 sig = bytes32(signature[32:64]);
        uint8 v = uint8(signature[64]);
        // Reject malleable signatures (high-s) and invalid recovery ids.
        if (uint256(sig) > HALF_CURVE_ORDER || (v != 27 && v != 28)) {
            return address(0);
        }
        return ecrecover(digest, v, r, sig);
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
