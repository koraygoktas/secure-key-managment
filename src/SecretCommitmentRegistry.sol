// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract SecretCommitmentRegistry {
    event CommitmentSet(bytes32 indexed key, bytes32 commitmentHash, uint256 timestamp);
    event CommitmentRevoked(bytes32 indexed key, uint256 timestamp);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotOwner();
    error ZeroAddress();
    error CommitmentAlreadySet();
    error CommitmentNotFound();

    address public owner;

    mapping(bytes32 => bytes32) private commitments;

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address initialOwner) {
        if (initialOwner == address(0)) revert ZeroAddress();
        owner = initialOwner;
        emit OwnershipTransferred(address(0), initialOwner);
    }

    function setCommitment(bytes32 key, bytes32 commitmentHash) external onlyOwner {
        if (commitments[key] != bytes32(0)) revert CommitmentAlreadySet();
        commitments[key] = commitmentHash;
        emit CommitmentSet(key, commitmentHash, block.timestamp);
    }

    function revoke(bytes32 key) external onlyOwner {
        if (commitments[key] == bytes32(0)) revert CommitmentNotFound();
        delete commitments[key];
        emit CommitmentRevoked(key, block.timestamp);
    }

    function verify(bytes32 key, bytes calldata revealedSecret) external view returns (bool) {
        bytes32 stored = commitments[key];
        if (stored == bytes32(0)) return false;
        return stored == keccak256(revealedSecret);
    }

    function commitmentOf(bytes32 key) external view returns (bytes32) {
        return commitments[key];
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}