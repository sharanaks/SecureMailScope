// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title AuditRegistry
/// @notice Stores a tamper-evident anchor (SHA-256 hash) for each
///         SecureMailScope security assessment report. Only the
///         assessment ID, the report's SHA-256 hash, and a timestamp
///         are ever written on-chain. The full report content and any
///         private data (e.g. email content) are NEVER stored here.
contract AuditRegistry {
    struct Assessment {
        string reportHash;   // SHA-256 hex digest of the canonical report
        uint256 timestamp;   // block timestamp at registration
        address registeredBy;
        bool exists;
    }

    // assessmentId (UUID string) => Assessment record
    mapping(string => Assessment) private assessments;

    event AssessmentRegistered(
        string indexed assessmentId,
        string reportHash,
        uint256 timestamp,
        address registeredBy
    );

    /// @notice Register a new assessment's report hash on-chain.
    /// @dev Reverts if an assessment with this ID was already registered,
    ///      since reports should be immutable once anchored.
    function registerAssessment(string calldata assessmentId, string calldata reportHash) external {
        require(bytes(assessmentId).length > 0, "assessmentId required");
        require(bytes(reportHash).length > 0, "reportHash required");
        require(!assessments[assessmentId].exists, "assessment already registered");

        assessments[assessmentId] = Assessment({
            reportHash: reportHash,
            timestamp: block.timestamp,
            registeredBy: msg.sender,
            exists: true
        });

        emit AssessmentRegistered(assessmentId, reportHash, block.timestamp, msg.sender);
    }

    /// @notice Retrieve the stored record for an assessment ID.
    function getAssessment(string calldata assessmentId)
        external
        view
        returns (string memory reportHash, uint256 timestamp, address registeredBy)
    {
        Assessment memory a = assessments[assessmentId];
        return (a.reportHash, a.timestamp, a.registeredBy);
    }

    /// @notice Check whether a given hash matches what was anchored for this assessment.
    function verifyHash(string calldata assessmentId, string calldata reportHash)
        external
        view
        returns (bool)
    {
        Assessment memory a = assessments[assessmentId];
        if (!a.exists) {
            return false;
        }
        return keccak256(bytes(a.reportHash)) == keccak256(bytes(reportHash));
    }
}
