// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SecretCommitmentRegistry} from "../src/SecretCommitmentRegistry.sol";

contract SecretCommitmentRegistryTest is Test {
    SecretCommitmentRegistry registry;

    address owner = makeAddr("owner");
    address stranger = makeAddr("stranger");

    bytes32 constant KEY = keccak256("api-key-prod");

    function setUp() public {
        registry = new SecretCommitmentRegistry(owner);
    }

    function test_ConstructorSetsOwner() public view {
        assertEq(registry.owner(), owner);
    }

    function test_RevertOnZeroAddressOwner() public {
        vm.expectRevert(SecretCommitmentRegistry.ZeroAddress.selector);
        new SecretCommitmentRegistry(address(0));
    }

    function test_OwnerCanSetCommitment() public {
        bytes memory secret = "sk_live_super_secret_value";
        bytes32 hash = keccak256(secret);
        vm.prank(owner);
        registry.setCommitment(KEY, hash);

        assertEq(registry.commitmentOf(KEY), hash);
    }

    function test_NonOwnerCannotSetCommitment() public {
        vm.prank(stranger);
        vm.expectRevert(SecretCommitmentRegistry.NotOwner.selector);
        registry.setCommitment(KEY, keccak256("whatever"));
    }

    function test_CannotOverwriteExistingCommitmentWithoutRevoke() public {
        vm.startPrank(owner);
        registry.setCommitment(KEY, keccak256("first"));
        vm.expectRevert(SecretCommitmentRegistry.CommitmentAlreadySet.selector);
        registry.setCommitment(KEY, keccak256("second"));
        vm.stopPrank();
    }

    function test_VerifyReturnsTrueForCorrectReveal() public {
        bytes memory secret = "correct horse battery staple";
        vm.prank(owner);
        registry.setCommitment(KEY, keccak256(secret));

        assertTrue(registry.verify(KEY, secret));
    }

    function test_VerifyReturnsFalseForWrongReveal() public {
        bytes memory secret = "correct horse battery staple";
        vm.prank(owner);
        registry.setCommitment(KEY, keccak256(secret));

        assertFalse(registry.verify(KEY, "wrong guess"));
    }

    function test_VerifyReturnsFalseForUnknownKey() public view {
        assertFalse(registry.verify(keccak256("nonexistent"), "anything"));
    }

    function test_RevokeThenResetCommitment() public {
        vm.startPrank(owner);
        registry.setCommitment(KEY, keccak256("v1"));
        registry.revoke(KEY);
        assertEq(registry.commitmentOf(KEY), bytes32(0));

        registry.setCommitment(KEY, keccak256("v2"));
        assertEq(registry.commitmentOf(KEY), keccak256("v2"));
        vm.stopPrank();
    }

    function test_RevokeNonexistentReverts() public {
        vm.prank(owner);
        vm.expectRevert(SecretCommitmentRegistry.CommitmentNotFound.selector);
        registry.revoke(KEY);
    }

    function test_TransferOwnership() public {
        address newOwner = makeAddr("newOwner");

        vm.prank(owner);
        registry.transferOwnership(newOwner);

        assertEq(registry.owner(), newOwner);
    }

    function test_NonOwnerCannotTransferOwnership() public {
        vm.prank(stranger);
        vm.expectRevert(SecretCommitmentRegistry.NotOwner.selector);
        registry.transferOwnership(stranger);
    }

    function test_TransferOwnershipRejectsZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(SecretCommitmentRegistry.ZeroAddress.selector);
        registry.transferOwnership(address(0));
    }

    function testFuzz_VerifyMatchesOnlyExactSecret(bytes memory secret, bytes memory wrongSecret) public {
        vm.assume(keccak256(secret) != keccak256(wrongSecret));

        vm.prank(owner);
        registry.setCommitment(KEY, keccak256(secret));

        assertTrue(registry.verify(KEY, secret));
        assertFalse(registry.verify(KEY, wrongSecret));
    }
}