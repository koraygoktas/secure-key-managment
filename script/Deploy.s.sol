// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {SecretCommitmentRegistry} from "../src/SecretCommitmentRegistry.sol";

contract Deploy is Script {
    function run() external returns (SecretCommitmentRegistry registry) {
        // vm.startBroadcast() argümansız çağrıldığında, komut satırında
        // verilen imzalayıcıyı kullanır (--private-key / --account / --ledger).
        vm.startBroadcast();

        address deployer = msg.sender;
        registry = new SecretCommitmentRegistry(deployer);

        vm.stopBroadcast();

        console.log("Deployer / owner :", deployer);
        console.log("Registry deployed:", address(registry));
    }
}