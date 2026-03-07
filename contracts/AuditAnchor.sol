// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title  AuditAnchor
 * @notice Anchors Sovereignly audit chain Merkle roots to any EVM chain.
 *         Primarily deployed to Base mainnet; also usable on Arbitrum/Optimism.
 *
 * @dev    Deployed once per SovereignCloud deployment.
 *         Only authorised node keys can submit anchors.
 *         All anchors are permanent and publicly verifiable.
 *
 * Integration:
 *   SovereignChain (off-chain) → calls auditAnchor() every ANCHOR_INTERVAL blocks
 *   Anyone can call verifyAnchor() to prove a given Merkle root was
 *   committed at a specific time.
 *
 * Maps to SOC 2 CC4.1 (Monitoring) and CC7.1 (System Operations):
 *   External, permissionless proof that the audit log exists and
 *   has not been retroactively modified.
 */
contract AuditAnchor {

    // ─── Structs ──────────────────────────────────────────────────────────────

    struct Anchor {
        bytes32 merkleRoot;     // Merkle root of audit events batch
        uint256 chainBlockIdx;  // SovereignChain block index
        uint256 anchoredAt;     // Block timestamp (seconds)
        address submitter;      // Which validator submitted
        uint32  eventCount;     // Number of events in this batch
    }

    // ─── State ────────────────────────────────────────────────────────────────

    /// @notice Owner can add/remove authorised validators
    address public owner;

    /// @notice Sequence counter for anchors
    uint256 public anchorCount;

    /// @notice anchorId → Anchor data
    mapping(uint256 => Anchor) public anchors;

    /// @notice merkleRoot → anchorId (for quick lookup)
    mapping(bytes32 => uint256) public rootToAnchorId;

    /// @notice Authorised validator addresses (node pubkeys as Ethereum addresses)
    mapping(address => bool) public validators;

    /// @notice Node registration (nodeId string → address)
    mapping(string => address) public nodeRegistry;

    // ─── Events ───────────────────────────────────────────────────────────────

    event AnchorSubmitted(
        uint256 indexed anchorId,
        bytes32 indexed merkleRoot,
        uint256         chainBlockIdx,
        address         submitter,
        uint256         ts
    );

    event ValidatorAdded(address indexed validator, string nodeId);
    event ValidatorRemoved(address indexed validator);
    event OwnershipTransferred(address indexed prev, address indexed next);

    // ─── Errors ───────────────────────────────────────────────────────────────

    error NotOwner();
    error NotValidator();
    error AlreadyAnchored();
    error ZeroRoot();

    // ─── Constructor ──────────────────────────────────────────────────────────

    constructor() {
        owner = msg.sender;
        validators[msg.sender] = true;
    }

    // ─── Modifiers ────────────────────────────────────────────────────────────

    modifier onlyOwner()     { if (msg.sender != owner)                revert NotOwner();     _; }
    modifier onlyValidator() { if (!validators[msg.sender])            revert NotValidator(); _; }

    // ─── Core: submit anchor ──────────────────────────────────────────────────

    /**
     * @notice Submit a new Merkle root anchor from SovereignChain.
     * @param  merkleRoot     SHA-256 Merkle root of the event batch (as bytes32).
     * @param  chainBlockIdx  Index of the SovereignChain block being anchored.
     * @param  eventCount     Number of audit events in this batch.
     * @return anchorId       Sequential anchor identifier.
     */
    function auditAnchor(
        bytes32 merkleRoot,
        uint256 chainBlockIdx,
        uint32  eventCount
    ) external onlyValidator returns (uint256 anchorId) {
        if (merkleRoot == bytes32(0))              revert ZeroRoot();
        if (rootToAnchorId[merkleRoot] != 0)       revert AlreadyAnchored();

        anchorId = ++anchorCount;

        anchors[anchorId] = Anchor({
            merkleRoot:    merkleRoot,
            chainBlockIdx: chainBlockIdx,
            anchoredAt:    block.timestamp,
            submitter:     msg.sender,
            eventCount:    eventCount
        });

        rootToAnchorId[merkleRoot] = anchorId;

        emit AnchorSubmitted(anchorId, merkleRoot, chainBlockIdx, msg.sender, block.timestamp);
    }

    // ─── Verification ─────────────────────────────────────────────────────────

    /**
     * @notice Verify that a Merkle root was anchored on-chain.
     * @param  merkleRoot  The root to verify.
     * @return exists      True if this root was anchored.
     * @return anchor      Full anchor data.
     */
    function verifyAnchor(bytes32 merkleRoot)
        external view
        returns (bool exists, Anchor memory anchor)
    {
        uint256 id = rootToAnchorId[merkleRoot];
        if (id == 0) return (false, anchor);
        return (true, anchors[id]);
    }

    /**
     * @notice Get a page of anchors (newest first).
     * @param  from   Start index (1-based, inclusive).
     * @param  count  Max records to return.
     */
    function getAnchors(uint256 from, uint256 count)
        external view
        returns (Anchor[] memory result)
    {
        uint256 total = anchorCount;
        if (from == 0 || from > total) from = total;
        uint256 end   = from > count ? from - count : 0;

        result = new Anchor[](from - end);
        for (uint256 i = from; i > end; i--) {
            result[from - i] = anchors[i];
        }
    }

    // ─── Admin ────────────────────────────────────────────────────────────────

    function addValidator(address validator, string calldata nodeId) external onlyOwner {
        validators[validator]  = true;
        nodeRegistry[nodeId]   = validator;
        emit ValidatorAdded(validator, nodeId);
    }

    function removeValidator(address validator) external onlyOwner {
        validators[validator] = false;
        emit ValidatorRemoved(validator);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}
