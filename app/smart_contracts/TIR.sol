// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

contract TrustedIssuerRegistry is AccessControl, Pausable {
    bytes32 public constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");

    enum Status {
        None,
        Active,
        Suspended,
        Revoked
    }

    struct IssuerCore {
        bytes32 didHash;

        Status status;
        uint64 validFrom;
        uint64 validUntil; // 0 = unlimited

        // accreditation reference (keccak256 only)
        bytes32 accreditationHash;
        Status accreditationStatus;
        uint64 accreditationValidFrom;
        uint64 accreditationValidUntil; // 0 = unlimited

        string metadataURI;

        // capabilities as a set (no on-chain enumeration needed)
        mapping(bytes32 => bool) capability;

        bool exists;
    }

    // didHash -> issuer core
    mapping(bytes32 => IssuerCore) private issuers;

    // didHash -> schemaIdHash (keccak256) -> allowed
    mapping(bytes32 => mapping(bytes32 => bool)) private canIssueSchema;

    // didHash -> credDefIdHash (keccak256) -> allowed
    mapping(bytes32 => mapping(bytes32 => bool)) private canIssueCredDef;

    event IssuerAdded(
        address indexed registrar,
        bytes32 indexed didHash,
        uint64 validFrom,
        uint64 validUntil,
        string metadataURI
    );
    event IssuerCoreUpdated(
        address indexed registrar,
        bytes32 indexed didHash,
        uint64 validFrom,
        uint64 validUntil,
        string metadataURI
    );
    event IssuerStatusChanged(address indexed registrar, bytes32 indexed didHash, Status newStatus);

    event AccreditationUpdated(
        address indexed registrar,
        bytes32 indexed didHash,
        bytes32 accreditationHash,
        uint64 validFrom,
        uint64 validUntil,
        Status status,
        string metadataURI
    );

    event CapabilitySet(address indexed registrar, bytes32 indexed didHash, bytes32 capabilityId, bool allowed);

    event SchemaPermissionSet(address indexed registrar, bytes32 indexed didHash, bytes32 schemaIdHash, bool allowed);
    event CredDefPermissionSet(address indexed registrar, bytes32 indexed didHash, bytes32 credDefIdHash, bool allowed);

    event IssuerUpsertedBatch(address indexed registrar, bytes32 indexed didHash);

    constructor(address admin, address[] memory registrars) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        for (uint256 i = 0; i < registrars.length; i++) {
            _grantRole(REGISTRAR_ROLE, registrars[i]);
        }
    }

    function didKey(string memory did) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(did));
    }


    function addIssuer(
        string calldata did,
        uint64 validFrom,
        uint64 validUntil,
        string calldata metadataURI,
        bytes32[] calldata capabilityIds
    ) external whenNotPaused onlyRole(REGISTRAR_ROLE) {
        bytes32 key = didKey(did);
        IssuerCore storage isr = issuers[key];

        require(!isr.exists, "issuer already exists");
        require(validUntil == 0 || validUntil > validFrom, "invalid validity interval");

        isr.exists = true;
        isr.didHash = key;

        isr.status = Status.Active;
        isr.validFrom = validFrom;
        isr.validUntil = validUntil;

        isr.metadataURI = metadataURI;

        isr.accreditationStatus = Status.None;

        emit IssuerAdded(msg.sender, key, validFrom, validUntil, metadataURI);

        for (uint256 i = 0; i < capabilityIds.length; i++) {
            bytes32 cid = capabilityIds[i];
            if (cid == bytes32(0)) continue;
            if (!isr.capability[cid]) {
                isr.capability[cid] = true;
                emit CapabilitySet(msg.sender, key, cid, true);
            }
        }
    }

    function updateIssuerCore(
        string calldata did,
        uint64 newValidFrom,
        uint64 newValidUntil,
        string calldata newMetadataURI
    ) external whenNotPaused onlyRole(REGISTRAR_ROLE) {
        bytes32 key = didKey(did);
        IssuerCore storage isr = issuers[key];

        require(isr.exists, "issuer not found");
        require(newValidUntil == 0 || newValidUntil > newValidFrom, "invalid validity interval");

        isr.validFrom = newValidFrom;
        isr.validUntil = newValidUntil;
        isr.metadataURI = newMetadataURI;

        emit IssuerCoreUpdated(msg.sender, key, newValidFrom, newValidUntil, newMetadataURI);
    }

    function setIssuerStatus(string calldata did, Status newStatus) external whenNotPaused onlyRole(REGISTRAR_ROLE) {
        bytes32 key = didKey(did);
        IssuerCore storage isr = issuers[key];

        require(isr.exists, "issuer not found");
        isr.status = newStatus;

        emit IssuerStatusChanged(msg.sender, key, newStatus);
    }

    function setAccreditation(
        string calldata did,
        bytes32 accreditationHash,
        uint64 validFrom,
        uint64 validUntil,
        Status accStatus,
        string calldata metadataURI
    ) external whenNotPaused onlyRole(REGISTRAR_ROLE) {
        bytes32 key = didKey(did);
        IssuerCore storage isr = issuers[key];

        require(isr.exists, "issuer not found");
        require(accreditationHash != bytes32(0), "accreditationHash required");
        require(accStatus != Status.None, "acc status required");
        require(validUntil == 0 || validUntil > validFrom, "invalid accreditation interval");

        isr.accreditationHash = accreditationHash;
        isr.accreditationValidFrom = validFrom;
        isr.accreditationValidUntil = validUntil;
        isr.accreditationStatus = accStatus;

        if (bytes(metadataURI).length > 0) {
            isr.metadataURI = metadataURI;
        }

        emit AccreditationUpdated(msg.sender, key, accreditationHash, validFrom, validUntil, accStatus, metadataURI);
    }

    function setCapability(string calldata did, bytes32 capabilityId, bool allowed)
        external
        whenNotPaused
        onlyRole(REGISTRAR_ROLE)
    {
        bytes32 key = didKey(did);
        IssuerCore storage isr = issuers[key];

        require(isr.exists, "issuer not found");
        require(capabilityId != bytes32(0), "capabilityId=0");

        isr.capability[capabilityId] = allowed;
        emit CapabilitySet(msg.sender, key, capabilityId, allowed);
    }

    function setCapabilities(string calldata did, bytes32[] calldata capabilityIds, bool allowed)
        external
        whenNotPaused
        onlyRole(REGISTRAR_ROLE)
    {
        bytes32 key = didKey(did);
        IssuerCore storage isr = issuers[key];

        require(isr.exists, "issuer not found");

        for (uint256 i = 0; i < capabilityIds.length; i++) {
            bytes32 cid = capabilityIds[i];
            if (cid == bytes32(0)) continue;
            isr.capability[cid] = allowed;
            emit CapabilitySet(msg.sender, key, cid, allowed);
        }
    }

    function setSchemaPermissions(string calldata did, bytes32[] calldata schemaIdHashes, bool allowed)
        external
        whenNotPaused
        onlyRole(REGISTRAR_ROLE)
    {
        bytes32 key = didKey(did);
        IssuerCore storage isr = issuers[key];
        require(isr.exists, "issuer not found");

        for (uint256 i = 0; i < schemaIdHashes.length; i++) {
            bytes32 sid = schemaIdHashes[i];
            if (sid == bytes32(0)) continue;
            canIssueSchema[key][sid] = allowed;
            emit SchemaPermissionSet(msg.sender, key, sid, allowed);
        }
    }

    function setCredDefPermissions(string calldata did, bytes32[] calldata credDefIdHashes, bool allowed)
        external
        whenNotPaused
        onlyRole(REGISTRAR_ROLE)
    {
        bytes32 key = didKey(did);
        IssuerCore storage isr = issuers[key];
        require(isr.exists, "issuer not found");

        for (uint256 i = 0; i < credDefIdHashes.length; i++) {
            bytes32 cd = credDefIdHashes[i];
            if (cd == bytes32(0)) continue;
            canIssueCredDef[key][cd] = allowed;
            emit CredDefPermissionSet(msg.sender, key, cd, allowed);
        }
    }

    struct IssuerCoreInput {
        uint64 validFrom;
        uint64 validUntil;
        string metadataURI;

        bytes32[] addCapabilities;
        bytes32[] removeCapabilities;
    }

    struct AccreditationInput {
        bytes32 hash; // keccak256
        uint64 validFrom;
        uint64 validUntil;
        Status status;
        string metadataURI; 
    }

    struct ScopeInput {
        bytes32[] schemaIdHashes;
        bool schemaAllowed;

        bytes32[] credDefIdHashes;
        bool credDefAllowed;
    }

    function upsertIssuerWithAccreditationAndScope(
        string calldata did,
        IssuerCoreInput calldata core,
        AccreditationInput calldata acc,
        ScopeInput calldata scope
    ) external whenNotPaused onlyRole(REGISTRAR_ROLE) {
        bytes32 key = didKey(did);

        require(core.validUntil == 0 || core.validUntil > core.validFrom, "invalid validity interval");
        require(acc.hash != bytes32(0), "accreditationHash required");
        require(acc.status != Status.None, "acc status required");
        require(acc.validUntil == 0 || acc.validUntil > acc.validFrom, "invalid accreditation interval");

        IssuerCore storage isr = issuers[key];
        bool isNew = !isr.exists;

        if (isNew) {
            isr.exists = true;
            isr.didHash = key;
            isr.status = Status.Active;

            isr.accreditationStatus = Status.None;

            emit IssuerAdded(msg.sender, key, core.validFrom, core.validUntil, core.metadataURI);
        } else {
            emit IssuerCoreUpdated(msg.sender, key, core.validFrom, core.validUntil, core.metadataURI);
        }

        isr.validFrom = core.validFrom;
        isr.validUntil = core.validUntil;
        isr.metadataURI = core.metadataURI;

        if (core.addCapabilities.length > 0) {
            for (uint256 i = 0; i < core.addCapabilities.length; i++) {
                bytes32 cid = core.addCapabilities[i];
                if (cid == bytes32(0)) continue;
                if (!isr.capability[cid]) {
                    isr.capability[cid] = true;
                    emit CapabilitySet(msg.sender, key, cid, true);
                }
            }
        }

        if (core.removeCapabilities.length > 0) {
            for (uint256 i = 0; i < core.removeCapabilities.length; i++) {
                bytes32 cid = core.removeCapabilities[i];
                if (cid == bytes32(0)) continue;
                if (isr.capability[cid]) {
                    isr.capability[cid] = false;
                    emit CapabilitySet(msg.sender, key, cid, false);
                }
            }
        }

        isr.accreditationHash = acc.hash;
        isr.accreditationValidFrom = acc.validFrom;
        isr.accreditationValidUntil = acc.validUntil;
        isr.accreditationStatus = acc.status;

        if (bytes(acc.metadataURI).length > 0) {
            isr.metadataURI = acc.metadataURI;
        }

        emit AccreditationUpdated(msg.sender, key, acc.hash, acc.validFrom, acc.validUntil, acc.status, acc.metadataURI);

        if (scope.schemaIdHashes.length > 0) {
            for (uint256 i = 0; i < scope.schemaIdHashes.length; i++) {
                bytes32 sid = scope.schemaIdHashes[i];
                if (sid == bytes32(0)) continue;
                canIssueSchema[key][sid] = scope.schemaAllowed;
                emit SchemaPermissionSet(msg.sender, key, sid, scope.schemaAllowed);
            }
        }

        if (scope.credDefIdHashes.length > 0) {
            for (uint256 i = 0; i < scope.credDefIdHashes.length; i++) {
                bytes32 cd = scope.credDefIdHashes[i];
                if (cd == bytes32(0)) continue;
                canIssueCredDef[key][cd] = scope.credDefAllowed;
                emit CredDefPermissionSet(msg.sender, key, cd, scope.credDefAllowed);
            }
        }

        emit IssuerUpsertedBatch(msg.sender, key);
    }

    function getIssuerCore(bytes32 didHash)
        external
        view
        returns (
            bool exists,
            Status issuerStatus,
            uint64 validFrom,
            uint64 validUntil,
            bytes32 accreditationHash,
            Status accreditationStatus,
            uint64 accreditationValidFrom,
            uint64 accreditationValidUntil,
            string memory metadataURI
        )
    {
        IssuerCore storage isr = issuers[didHash];
        return (
            isr.exists,
            isr.status,
            isr.validFrom,
            isr.validUntil,
            isr.accreditationHash,
            isr.accreditationStatus,
            isr.accreditationValidFrom,
            isr.accreditationValidUntil,
            isr.metadataURI
        );
    }

    function hasCapability(bytes32 didHash, bytes32 capabilityId) external view returns (bool) {
        IssuerCore storage isr = issuers[didHash];
        if (!isr.exists) return false;
        return isr.capability[capabilityId];
    }

    function canIssueSchemaForHash(bytes32 didHash, bytes32 schemaIdHash) external view returns (bool) {
        IssuerCore storage isr = issuers[didHash];
        if (!_issuerActiveNow(isr)) return false;
        return canIssueSchema[didHash][schemaIdHash];
    }

    function canIssueCredDefForHash(bytes32 didHash, bytes32 credDefIdHash) external view returns (bool) {
        IssuerCore storage isr = issuers[didHash];
        if (!_issuerActiveNow(isr)) return false;
        return canIssueCredDef[didHash][credDefIdHash];
    }

    function isAccreditedNowHash(bytes32 didHash) external view returns (bool) {
        IssuerCore storage isr = issuers[didHash];
        if (!_issuerActiveNow(isr)) return false;

        if (isr.accreditationStatus != Status.Active) return false;
        if (isr.accreditationValidFrom > block.timestamp) return false;
        if (isr.accreditationValidUntil != 0 && isr.accreditationValidUntil < block.timestamp) return false;

        return true;
    }

    function isTrustedIssuerForHash(bytes32 didHash, bytes32 schemaIdHash, bytes32 credDefIdHash)
        external
        view
        returns (bool)
    {
        IssuerCore storage isr = issuers[didHash];
        if (!_issuerActiveNow(isr)) return false;

        if (isr.accreditationStatus != Status.Active) return false;
        if (isr.accreditationValidFrom > block.timestamp) return false;
        if (isr.accreditationValidUntil != 0 && isr.accreditationValidUntil < block.timestamp) return false;

        bool schemaOk = (schemaIdHash == bytes32(0)) ? true : canIssueSchema[didHash][schemaIdHash];
        bool credDefOk = (credDefIdHash == bytes32(0)) ? true : canIssueCredDef[didHash][credDefIdHash];

        return schemaOk && credDefOk;
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    function _issuerActiveNow(IssuerCore storage isr) internal view returns (bool) {
        if (!isr.exists) return false;
        if (isr.status != Status.Active) return false;
        if (isr.validFrom > block.timestamp) return false;
        if (isr.validUntil != 0 && isr.validUntil < block.timestamp) return false;
        return true;
    }
}
