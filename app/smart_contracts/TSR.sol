// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

contract TrustedSchemaRegistry is AccessControl, Pausable {
    bytes32 public constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");

    enum Status { None, Active, Deprecated }

    struct SchemaCore {
        bytes32 schemaHash;   // keccak256(schema.json canonicalizat)
        string metadataURI;   // pointer off-chain (HTTPS)
        string version;       // ex. "1.0.0"
        Status status;        // Active / Deprecated
        uint64 createdAt;
        uint64 updatedAt;
        bool exists;
    }

    mapping(bytes32 => SchemaCore) private schemas;
    bytes32[] public schemaIndex;

    event SchemaRegistered(bytes32 indexed schemaHash, string version, string metadataURI);
    event SchemaUpdated(bytes32 indexed schemaHash, string oldVersion, string newVersion, string newURI);
    event StatusChanged(bytes32 indexed schemaHash, Status newStatus);

    error SchemaAlreadyExists(bytes32 schemaHash);
    error SchemaNotFound(bytes32 schemaHash);

    constructor(address admin, address[] memory registrars) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        for (uint i = 0; i < registrars.length; i++) {
            _grantRole(REGISTRAR_ROLE, registrars[i]);
        }
    }

    // --- Register a new schema ---
    function registerSchema(
        bytes32 schemaHash,
        string calldata version,
        string calldata metadataURI
    ) external whenNotPaused onlyRole(REGISTRAR_ROLE) {
        if (schemas[schemaHash].exists) revert SchemaAlreadyExists(schemaHash);

        SchemaCore storage sc = schemas[schemaHash];
        sc.schemaHash = schemaHash;
        sc.version = version;
        sc.metadataURI = metadataURI;
        sc.status = Status.Active;
        sc.createdAt = uint64(block.timestamp);
        sc.updatedAt = sc.createdAt;
        sc.exists = true;

        schemaIndex.push(schemaHash);
        emit SchemaRegistered(schemaHash, version, metadataURI);
    }

    // --- Update schema (new version or new URI) ---
    function updateSchema(
        bytes32 schemaHash,
        string calldata newVersion,
        string calldata newMetadataURI
    ) external whenNotPaused onlyRole(REGISTRAR_ROLE) {
        SchemaCore storage sc = schemas[schemaHash];
        if (!sc.exists) revert SchemaNotFound(schemaHash);

        string memory oldVersion = sc.version;
        sc.version = newVersion;
        sc.metadataURI = newMetadataURI;
        sc.updatedAt = uint64(block.timestamp);

        emit SchemaUpdated(schemaHash, oldVersion, newVersion, newMetadataURI);
    }

    // --- Change status (Active -> Deprecated) ---
    function setStatus(bytes32 schemaHash, Status newStatus)
        external whenNotPaused onlyRole(REGISTRAR_ROLE)
    {
        SchemaCore storage sc = schemas[schemaHash];
        if (!sc.exists) revert SchemaNotFound(schemaHash);

        sc.status = newStatus;
        sc.updatedAt = uint64(block.timestamp);
        emit StatusChanged(schemaHash, newStatus);
    }

    // --- Views ---
    struct SchemaView {
        bytes32 schemaHash;
        string version;
        string metadataURI;
        Status status;
        uint64 createdAt;
        uint64 updatedAt;
    }

    function getSchema(bytes32 schemaHash) external view returns (SchemaView memory) {
        SchemaCore storage sc = schemas[schemaHash];
        if (!sc.exists) revert SchemaNotFound(schemaHash);

        return SchemaView({
            schemaHash: sc.schemaHash,
            version: sc.version,
            metadataURI: sc.metadataURI,
            status: sc.status,
            createdAt: sc.createdAt,
            updatedAt: sc.updatedAt
        });
    }

    // --- Admin ---
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) { _pause(); }
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) { _unpause(); }
}
