// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

contract CredentialDefinitionsRegistry is AccessControl, Pausable {
    bytes32 public constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");

    enum Status { None, Active, Deprecated }

    struct CredDefCore {
        bytes32 credDefHash; // keccak256(creddef.json)
        bytes32 schemaHash;  // keccak256(schema.json)
        Status status;       // Active / Deprecated
        uint64 createdAt;
        uint64 updatedAt;
        bool exists;
    }

    mapping(bytes32 => CredDefCore) private credDefs;

    // Optional index (remove if not needed)
    bytes32[] public credDefIndex;
    mapping(bytes32 => uint256) private credDefIndexPlusOne; // 0 = not present

    // Events
    event CredDefRegistered(bytes32 indexed credDefHash, bytes32 indexed schemaHash);
    event CredDefUpdated(bytes32 indexed credDefHash, bytes32 indexed schemaHash);
    event StatusChanged(bytes32 indexed credDefHash, Status newStatus);

    error CredDefAlreadyExists(bytes32 credDefHash);
    error CredDefNotFound(bytes32 credDefHash);
    error InvalidInput();

    constructor(address admin, address[] memory registrars) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        for (uint256 i = 0; i < registrars.length; i++) {
            _grantRole(REGISTRAR_ROLE, registrars[i]);
        }
    }

    // --------- Mutators ---------

    function registerCredDef(bytes32 credDefHash, bytes32 schemaHash)
        external
        whenNotPaused
        onlyRole(REGISTRAR_ROLE)
    {
        if (credDefHash == bytes32(0) || schemaHash == bytes32(0)) revert InvalidInput();
        if (credDefs[credDefHash].exists) revert CredDefAlreadyExists(credDefHash);

        CredDefCore storage cd = credDefs[credDefHash];
        cd.credDefHash = credDefHash;
        cd.schemaHash = schemaHash;
        cd.status = Status.Active;
        cd.createdAt = uint64(block.timestamp);
        cd.updatedAt = cd.createdAt;
        cd.exists = true;

        // optional index
        if (credDefIndexPlusOne[credDefHash] == 0) {
            credDefIndex.push(credDefHash);
            credDefIndexPlusOne[credDefHash] = credDefIndex.length; // 1-based
        }

        emit CredDefRegistered(credDefHash, schemaHash);
    }

    /// @notice Update mapping to a new schemaHash (rare, but kept for flexibility).
    function updateCredDef(bytes32 credDefHash, bytes32 newSchemaHash)
        external
        whenNotPaused
        onlyRole(REGISTRAR_ROLE)
    {
        if (newSchemaHash == bytes32(0)) revert InvalidInput();

        CredDefCore storage cd = credDefs[credDefHash];
        if (!cd.exists) revert CredDefNotFound(credDefHash);

        cd.schemaHash = newSchemaHash;
        cd.updatedAt = uint64(block.timestamp);

        emit CredDefUpdated(credDefHash, newSchemaHash);
    }

    function setStatus(bytes32 credDefHash, Status newStatus)
        external
        whenNotPaused
        onlyRole(REGISTRAR_ROLE)
    {
        CredDefCore storage cd = credDefs[credDefHash];
        if (!cd.exists) revert CredDefNotFound(credDefHash);
        if (newStatus == Status.None) revert InvalidInput(); // optional strictness

        cd.status = newStatus;
        cd.updatedAt = uint64(block.timestamp);

        emit StatusChanged(credDefHash, newStatus);
    }

    /// @notice Strict upsert: create if missing, else update schemaHash + status (single tx).
    function upsertCredDef(bytes32 credDefHash, bytes32 schemaHash, Status status)
        external
        whenNotPaused
        onlyRole(REGISTRAR_ROLE)
    {
        if (credDefHash == bytes32(0) || schemaHash == bytes32(0)) revert InvalidInput();
        if (status == Status.None) revert InvalidInput();

        CredDefCore storage cd = credDefs[credDefHash];
        if (!cd.exists) {
            cd.exists = true;
            cd.credDefHash = credDefHash;
            cd.createdAt = uint64(block.timestamp);

            // optional index
            if (credDefIndexPlusOne[credDefHash] == 0) {
                credDefIndex.push(credDefHash);
                credDefIndexPlusOne[credDefHash] = credDefIndex.length; // 1-based
            }

            emit CredDefRegistered(credDefHash, schemaHash);
        } else {
            emit CredDefUpdated(credDefHash, schemaHash);
        }

        cd.schemaHash = schemaHash;
        cd.status = status;
        cd.updatedAt = uint64(block.timestamp);

        emit StatusChanged(credDefHash, status);
    }

    // --------- Views ---------

    function getCredDef(bytes32 credDefHash)
        external
        view
        returns (
            bool exists,
            bytes32 outCredDefHash,
            bytes32 schemaHash,
            Status status,
            uint64 createdAt,
            uint64 updatedAt
        )
    {
        CredDefCore storage cd = credDefs[credDefHash];
        return (cd.exists, cd.credDefHash, cd.schemaHash, cd.status, cd.createdAt, cd.updatedAt);
    }

    function isActive(bytes32 credDefHash) external view returns (bool) {
        CredDefCore storage cd = credDefs[credDefHash];
        return cd.exists && cd.status == Status.Active;
    }

    // --------- Admin ---------

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
