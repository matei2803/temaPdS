// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

contract DIDDocumentCommitmentRegistry is AccessControl, Pausable {
    bytes32 public constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");

    enum Status {
        None,
        Active,
        Suspended,
        Revoked
    }

    enum HashAlg {
        None,
        Keccak256CanonicalJson,      // keccak256(canonicalized DID Document bytes)
        Sha256CanonicalJsonBytes32,  // bytes32(sha256(canonicalized bytes))
        Keccak256JwsCompact,         // keccak256(JWS compact bytes) if you store signed envelope
        Sha256JwsCompactBytes32
    }

    struct Commitment {
        bytes32 didHash;

        bytes32 docHash;
        HashAlg docHashAlg;

        Status status;
        uint64 validFrom;    // unix seconds
        uint64 validUntil;   // 0 = unlimited

        string metadataURI;  // optional pointer (IPFS/HTTPS) to DID Doc snapshot or proof

        uint64 createdAt;
        uint64 updatedAt;

        bool exists;
    }

    mapping(bytes32 => Commitment) private commitments;

    event DidDocCommitted(
        address indexed registrar,
        bytes32 indexed didHash,
        bytes32 docHash,
        HashAlg alg,
        uint64 validFrom,
        uint64 validUntil,
        Status status,
        string metadataURI
    );

    event DidDocCommitmentUpdated(
        address indexed registrar,
        bytes32 indexed didHash,
        bytes32 oldHash,
        bytes32 newHash,
        HashAlg alg,
        uint64 validFrom,
        uint64 validUntil,
        Status status,
        string metadataURI
    );

    event DidDocStatusChanged(address indexed registrar, bytes32 indexed didHash, Status newStatus);

    error NotFound(bytes32 didHash);
    error AlreadyExists(bytes32 didHash);
    error InvalidInterval();
    error InvalidAlg();
    error InvalidHash();

    constructor(address admin, address[] memory registrars) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        for (uint256 i = 0; i < registrars.length; i++) {
            _grantRole(REGISTRAR_ROLE, registrars[i]);
        }
    }

    function didKey(string memory did) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(did));
    }

    function _requireExists(bytes32 didHash) internal view {
        if (!commitments[didHash].exists) revert NotFound(didHash);
    }

    function commitDidDocument(
        bytes32 didHash,
        bytes32 docHash,
        HashAlg alg,
        uint64 validFrom,
        uint64 validUntil,
        Status status,
        string calldata metadataURI
    ) external whenNotPaused onlyRole(REGISTRAR_ROLE) {
        if (commitments[didHash].exists) revert AlreadyExists(didHash);
        if (alg == HashAlg.None) revert InvalidAlg();
        if (docHash == bytes32(0)) revert InvalidHash();
        if (status == Status.None) revert InvalidAlg(); // reuse; or make separate error
        if (validUntil != 0 && validUntil <= validFrom) revert InvalidInterval();

        Commitment storage c = commitments[didHash];
        c.didHash = didHash;
        c.docHash = docHash;
        c.docHashAlg = alg;
        c.status = status;
        c.validFrom = validFrom;
        c.validUntil = validUntil;
        c.metadataURI = metadataURI;
        c.createdAt = uint64(block.timestamp);
        c.updatedAt = c.createdAt;
        c.exists = true;

        emit DidDocCommitted(msg.sender, didHash, docHash, alg, validFrom, validUntil, status, metadataURI);
    }

    function updateDidDocumentCommitment(
        bytes32 didHash,
        bytes32 newDocHash,
        HashAlg alg,
        uint64 validFrom,
        uint64 validUntil,
        Status status,
        string calldata metadataURI
    ) external whenNotPaused onlyRole(REGISTRAR_ROLE) {
        _requireExists(didHash);

        if (alg == HashAlg.None) revert InvalidAlg();
        if (newDocHash == bytes32(0)) revert InvalidHash();
        if (status == Status.None) revert InvalidAlg();
        if (validUntil != 0 && validUntil <= validFrom) revert InvalidInterval();

        Commitment storage c = commitments[didHash];
        bytes32 old = c.docHash;

        c.docHash = newDocHash;
        c.docHashAlg = alg;
        c.status = status;
        c.validFrom = validFrom;
        c.validUntil = validUntil;
        c.metadataURI = metadataURI;
        c.updatedAt = uint64(block.timestamp);

        emit DidDocCommitmentUpdated(msg.sender, didHash, old, newDocHash, alg, validFrom, validUntil, status, metadataURI);
    }

    function setDidDocStatus(bytes32 didHash, Status newStatus)
        external
        whenNotPaused
        onlyRole(REGISTRAR_ROLE)
    {
        _requireExists(didHash);
        commitments[didHash].status = newStatus;
        commitments[didHash].updatedAt = uint64(block.timestamp);
        emit DidDocStatusChanged(msg.sender, didHash, newStatus);
    }

    function getCommitment(bytes32 didHash)
        external
        view
        returns (
            bool exists,
            bytes32 docHash,
            HashAlg alg,
            Status status,
            uint64 validFrom,
            uint64 validUntil,
            string memory metadataURI,
            uint64 createdAt,
            uint64 updatedAt
        )
    {
        Commitment storage c = commitments[didHash];
        return (c.exists, c.docHash, c.docHashAlg, c.status, c.validFrom, c.validUntil, c.metadataURI, c.createdAt, c.updatedAt);
    }

    function isDidDocCommittedNow(bytes32 didHash) public view returns (bool) {
        Commitment storage c = commitments[didHash];
        if (!c.exists) return false;
        if (c.status != Status.Active) return false;
        if (c.validFrom > block.timestamp) return false;
        if (c.validUntil != 0 && c.validUntil < block.timestamp) return false;
        return c.docHash != bytes32(0) && c.docHashAlg != HashAlg.None;
    }

    function isDidDocValidNow(bytes32 didHash, bytes32 resolvedDocHash) external view returns (bool) {
        Commitment storage c = commitments[didHash];
        if (!c.exists) return false;
        if (c.status != Status.Active) return false;
        if (c.validFrom > block.timestamp) return false;
        if (c.validUntil != 0 && c.validUntil < block.timestamp) return false;
        return c.docHash == resolvedDocHash;
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) { _pause(); }
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) { _unpause(); }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}
