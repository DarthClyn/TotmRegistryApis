// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title Trusted-issuer registry v2 (TOTM Trust API)
/// @notice Says which bank a DID belongs to: name, BIC, signing key, what it may issue and whether it is trusted.
/// Anyone can read; only the owner can write. Signature checks stay off-chain; this contract only answers
/// "is this DID a known, active bank, and which key does it sign with?".
/// v2 adds `bic` (unique, looked up both ways) and `signingKey` (compressed public key hex, 0x…) to v1.
contract IssuerRegistryV2 {
    enum Status {
        None, // not registered
        Active,
        Suspended,
        Revoked
    }

    struct Issuer {
        string did; // e.g. did:web:bank.example or did:key:z… (the lookup key)
        string name; // organisation, e.g. "Bank Alpha ID"
        string role; // free text, e.g. "Issuing bank"
        string bic; // SWIFT BIC, e.g. "ALPHIDJA"; unique; may be empty
        string signingKey; // compressed public key hex, e.g. 0x02ab…; may be empty
        string[] allowedDocs; // e.g. ["eLC"]; empty = any document type
        Status status;
        uint64 validFrom; // unix seconds; 0 = from registration
        uint64 validUntil; // unix seconds; 0 = no end
        uint64 updatedAt;
    }

    /// @dev Write input, as one struct to keep the function signatures short.
    struct IssuerInput {
        string did;
        string name;
        string role;
        string bic;
        string signingKey;
        string[] allowedDocs;
        uint64 validFrom;
        uint64 validUntil;
    }

    address public owner;
    address public pendingOwner;

    mapping(bytes32 => Issuer) private _issuers;
    bytes32[] private _keys;
    mapping(bytes32 => uint256) private _indexPlusOne;
    mapping(bytes32 => bytes32) private _didKeyByBic;

    event IssuerAdded(bytes32 indexed key, string did, string name, string bic);
    event IssuerUpdated(bytes32 indexed key, string did, string name, string bic);
    event IssuerStatusChanged(bytes32 indexed key, string did, Status status);
    event IssuerRemoved(bytes32 indexed key, string did);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotOwner();
    error NotPendingOwner();
    error AlreadyRegistered(string did);
    error NotRegistered(string did);
    error BicTaken(string bic);
    error InvalidInput(string reason);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    // ---------- Reads (open to everyone) ----------

    function keyOf(string calldata did) public pure returns (bytes32) {
        return keccak256(bytes(did));
    }

    /// @notice Full entry; status None means the DID is not registered.
    function getIssuer(string calldata did) external view returns (Issuer memory) {
        return _issuers[keyOf(did)];
    }

    /// @notice Entry for a BIC; status None means no bank has this BIC.
    function getIssuerByBic(string calldata bic) external view returns (Issuer memory) {
        return _issuers[_didKeyByBic[keccak256(bytes(bic))]];
    }

    /// @notice True when the DID is registered, Active, inside its validity window and allowed this document type.
    function isTrusted(string calldata did, string calldata docType) external view returns (bool) {
        Issuer storage i = _issuers[keyOf(did)];
        if (i.status != Status.Active) return false;
        if (i.validFrom != 0 && block.timestamp < i.validFrom) return false;
        if (i.validUntil != 0 && block.timestamp > i.validUntil) return false;
        if (i.allowedDocs.length == 0) return true;
        bytes32 wanted = keccak256(bytes(docType));
        for (uint256 n = 0; n < i.allowedDocs.length; n++) {
            if (keccak256(bytes(i.allowedDocs[n])) == wanted) return true;
        }
        return false;
    }

    function issuerCount() external view returns (uint256) {
        return _keys.length;
    }

    function issuerAt(uint256 index) external view returns (Issuer memory) {
        return _issuers[_keys[index]];
    }

    // ---------- Writes (owner only) ----------

    function addIssuer(IssuerInput calldata x) external onlyOwner {
        bytes32 key = _checkInput(x);
        if (_issuers[key].status != Status.None) revert AlreadyRegistered(x.did);
        Issuer storage i = _issuers[key];
        i.did = x.did;
        _setBic(i, key, x.bic);
        _write(i, x);
        i.status = Status.Active;
        _keys.push(key);
        _indexPlusOne[key] = _keys.length;
        emit IssuerAdded(key, x.did, x.name, x.bic);
    }

    /// @notice Replaces name, role, BIC, signing key, allowed documents and validity. Status is unchanged (use setStatus).
    function updateIssuer(IssuerInput calldata x) external onlyOwner {
        bytes32 key = _checkInput(x);
        Issuer storage i = _issuers[key];
        if (i.status == Status.None) revert NotRegistered(x.did);
        _setBic(i, key, x.bic);
        _write(i, x);
        emit IssuerUpdated(key, x.did, x.name, x.bic);
    }

    function setStatus(string calldata did, Status status) external onlyOwner {
        if (status == Status.None) revert InvalidInput("use removeIssuer to delete");
        bytes32 key = keyOf(did);
        Issuer storage i = _issuers[key];
        if (i.status == Status.None) revert NotRegistered(did);
        i.status = status;
        i.updatedAt = uint64(block.timestamp);
        emit IssuerStatusChanged(key, did, status);
    }

    /// @notice Deletes the entry. Prefer setStatus(Revoked) to keep it readable; the events keep the history either way.
    function removeIssuer(string calldata did) external onlyOwner {
        bytes32 key = keyOf(did);
        uint256 idx = _indexPlusOne[key];
        if (idx == 0) revert NotRegistered(did);
        string memory bic = _issuers[key].bic;
        if (bytes(bic).length != 0) delete _didKeyByBic[keccak256(bytes(bic))];
        bytes32 last = _keys[_keys.length - 1];
        _keys[idx - 1] = last;
        _indexPlusOne[last] = idx;
        _keys.pop();
        delete _indexPlusOne[key];
        delete _issuers[key];
        emit IssuerRemoved(key, did);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        emit OwnershipTransferred(owner, msg.sender);
        owner = msg.sender;
        pendingOwner = address(0);
    }

    // ---------- Internal ----------

    function _checkInput(IssuerInput calldata x) private pure returns (bytes32) {
        if (bytes(x.did).length < 7) revert InvalidInput("did");
        if (bytes(x.name).length == 0) revert InvalidInput("name");
        if (x.validUntil != 0 && x.validUntil < x.validFrom) revert InvalidInput("validUntil before validFrom");
        return keccak256(bytes(x.did));
    }

    /// @dev Keeps the BIC → DID index unique and in step with the entry.
    function _setBic(Issuer storage i, bytes32 key, string calldata bic) private {
        bytes32 newBic = keccak256(bytes(bic));
        if (bytes(i.bic).length != 0) {
            bytes32 oldBic = keccak256(bytes(i.bic));
            if (oldBic == newBic) return;
            delete _didKeyByBic[oldBic];
        }
        if (bytes(bic).length == 0) return;
        bytes32 holder = _didKeyByBic[newBic];
        if (holder != bytes32(0) && holder != key) revert BicTaken(bic);
        _didKeyByBic[newBic] = key;
    }

    function _write(Issuer storage i, IssuerInput calldata x) private {
        i.name = x.name;
        i.role = x.role;
        i.bic = x.bic;
        i.signingKey = x.signingKey;
        delete i.allowedDocs;
        for (uint256 n = 0; n < x.allowedDocs.length; n++) i.allowedDocs.push(x.allowedDocs[n]);
        i.validFrom = x.validFrom;
        i.validUntil = x.validUntil;
        i.updatedAt = uint64(block.timestamp);
    }
}
