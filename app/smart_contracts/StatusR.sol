// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

contract StatusListRegistry is AccessControl, Pausable {
    bytes32 public constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");

    enum Status { None, Active, Deprecated }
    enum Purpose { Revocation, Suspension }

    /// @notice Minimal on-chain anchor for a status list:
    ///         listId -> (issuerDidHash, credDefHash, purpose, listHash, listURI, status, timestamps)
    struct ListCore {
        bytes32 issuerDidHash;
        bytes32 credDefHash;
        Purpose purpose;

        bytes32 listHash;   // keccak256(canonical JSON of StatusList VC)
        string  listURI;    // can stay the same URI if you disable caching

        Status status;
        uint64 createdAt;
        uint64 updatedAt;
        bool exists;
    }

    mapping(bytes32 => ListCore) private lists;

    // ---- Events ----
    event StatusListRegistered(
        bytes32 indexed listId,
        bytes32 indexed issuerDidHash,
        bytes32 indexed credDefHash,
        Purpose purpose,
        bytes32 listHash,
        string listURI
    );

    event StatusListUpdated(
        bytes32 indexed listId,
        bytes32 oldHash,
        bytes32 newHash,
        string newURI
    );

    event StatusListStatusChanged(bytes32 indexed listId, Status newStatus);

    // ---- Errors ----
    error ListAlreadyExists(bytes32 listId);
    error ListNotFound(bytes32 listId);
    error InvalidInput();

    constructor(address admin, address[] memory registrars) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        for (uint256 i = 0; i < registrars.length; i++) {
            _grantRole(REGISTRAR_ROLE, registrars[i]);
        }
    }

    /// @notice Stable listId (no version): keccak256(issuerDidHash, credDefHash, purpose)
    function deriveListId(bytes32 issuerDidHash, bytes32 credDefHash, Purpose purpose)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(issuerDidHash, credDefHash, purpose));
    }

    // -------------------------
    // Mutators
    // -------------------------

    function registerStatusList(
        bytes32 issuerDidHash,
        bytes32 credDefHash,
        Purpose purpose,
        bytes32 listHash,
        string calldata listURI
    ) external whenNotPaused onlyRole(REGISTRAR_ROLE) returns (bytes32 listId) {
        if (
            issuerDidHash == bytes32(0) ||
            credDefHash == bytes32(0) ||
            listHash == bytes32(0) ||
            bytes(listURI).length == 0
        ) revert InvalidInput();

        listId = deriveListId(issuerDidHash, credDefHash, purpose);
        if (lists[listId].exists) revert ListAlreadyExists(listId);

        ListCore storage lc = lists[listId];
        lc.exists = true;
        lc.issuerDidHash = issuerDidHash;
        lc.credDefHash = credDefHash;
        lc.purpose = purpose;
        lc.listHash = listHash;
        lc.listURI = listURI;
        lc.status = Status.Active;
        lc.createdAt = uint64(block.timestamp);
        lc.updatedAt = lc.createdAt;

        emit StatusListRegistered(listId, issuerDidHash, credDefHash, purpose, listHash, listURI);
    }

    /// @notice Update the anchored status list hash/URI (call on every revocation if you want).
    /// @dev Registrar-only (simplest and safest). If you want issuer-controlled updates, add `publisher` back.
    function updateStatusList(
        bytes32 listId,
        bytes32 newListHash,
        string calldata newListURI
    ) external whenNotPaused onlyRole(REGISTRAR_ROLE) {
        ListCore storage lc = lists[listId];
        if (!lc.exists) revert ListNotFound(listId);
        if (lc.status != Status.Active) revert InvalidInput();
        if (newListHash == bytes32(0) || bytes(newListURI).length == 0) revert InvalidInput();

        bytes32 oldHash = lc.listHash;

        lc.listHash = newListHash;
        lc.listURI = newListURI;
        lc.updatedAt = uint64(block.timestamp);

        emit StatusListUpdated(listId, oldHash, newListHash, newListURI);
    }

    function setListStatus(bytes32 listId, Status newStatus)
        external
        whenNotPaused
        onlyRole(REGISTRAR_ROLE)
    {
        ListCore storage lc = lists[listId];
        if (!lc.exists) revert ListNotFound(listId);
        if (newStatus == Status.None) revert InvalidInput();

        lc.status = newStatus;
        lc.updatedAt = uint64(block.timestamp);

        emit StatusListStatusChanged(listId, newStatus);
    }

    /// @notice Strict upsert: create if missing, else update (single tx).
    function upsertStatusList(
        bytes32 issuerDidHash,
        bytes32 credDefHash,
        Purpose purpose,
        bytes32 listHash,
        string calldata listURI,
        Status status
    ) external whenNotPaused onlyRole(REGISTRAR_ROLE) returns (bytes32 listId) {
        if (
            issuerDidHash == bytes32(0) ||
            credDefHash == bytes32(0) ||
            listHash == bytes32(0) ||
            bytes(listURI).length == 0 ||
            status == Status.None
        ) revert InvalidInput();

        listId = deriveListId(issuerDidHash, credDefHash, purpose);
        ListCore storage lc = lists[listId];

        if (!lc.exists) {
            lc.exists = true;
            lc.issuerDidHash = issuerDidHash;
            lc.credDefHash = credDefHash;
            lc.purpose = purpose;
            lc.createdAt = uint64(block.timestamp);
            emit StatusListRegistered(listId, issuerDidHash, credDefHash, purpose, listHash, listURI);
        } else {
            emit StatusListUpdated(listId, lc.listHash, listHash, listURI);
        }

        lc.listHash = listHash;
        lc.listURI = listURI;
        lc.status = status;
        lc.updatedAt = uint64(block.timestamp);

        emit StatusListStatusChanged(listId, status);
    }

    // -------------------------
    // Views
    // -------------------------

    function getStatusList(bytes32 listId)
        external
        view
        returns (
            bool exists,
            bytes32 issuerDidHash,
            bytes32 credDefHash,
            Purpose purpose,
            bytes32 listHash,
            string memory listURI,
            Status status,
            uint64 createdAt,
            uint64 updatedAt
        )
    {
        ListCore storage lc = lists[listId];
        return (
            lc.exists,
            lc.issuerDidHash,
            lc.credDefHash,
            lc.purpose,
            lc.listHash,
            lc.listURI,
            lc.status,
            lc.createdAt,
            lc.updatedAt
        );
    }

    function isActive(bytes32 listId) external view returns (bool) {
        ListCore storage lc = lists[listId];
        return lc.exists && lc.status == Status.Active;
    }

    // -------------------------
    // Admin
    // -------------------------

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
