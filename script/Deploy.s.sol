// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console2} from "forge-std/Script.sol";
import {Forwarder} from "../src/Forwarder.sol";
import {SampleRecipient} from "../src/SampleRecipient.sol";

/// @notice Deploys the forwarder and a sample ERC-2771 recipient wired to trust it.
contract Deploy is Script {
    function run() external returns (Forwarder forwarder, SampleRecipient recipient) {
        vm.startBroadcast();
        forwarder = new Forwarder("Forwarder");
        recipient = new SampleRecipient(address(forwarder));
        vm.stopBroadcast();

        console2.log("Forwarder      :", address(forwarder));
        console2.log("SampleRecipient:", address(recipient));
    }
}
