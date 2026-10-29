// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {SealedInbox} from "../src/SealedInbox.sol";
import {Token} from "../src/demo/Token.sol";
import {Pool} from "../src/demo/Pool.sol";

/// Deploys the inbox and a demo market on a local chain. Keys come from the
/// environment: DEPLOYER, ALICE (the trader) and SEARCHER.
contract Deploy is Script {
    function run() external {
        uint256 deployer = vm.envUint("DEPLOYER");
        uint256 alice = vm.envUint("ALICE");
        uint256 searcher = vm.envUint("SEARCHER");

        vm.startBroadcast(deployer);
        // The inbox deploys its own SealedAccount; senders delegate to inbox.account().
        // Puzzles are fixed near the demo's 8 chains of 2^26 steps with 24-byte links.
        SealedInbox inbox = new SealedInbox(
            SealedInbox.Config({
                deposit: 0.01 ether,
                bounty: 0.002 ether,
                bond: 0.005 ether,
                revealWindow: 2,
                maxTicketGas: 1_000_000,
                slotGasBudget: 10_000_000,
                maxEnvelope: 4096,
                minWork: 1 << 28,
                maxWork: 1 << 30,
                maxChains: 16,
                minLinkBytes: 24,
                maxOpen: 4
            })
        );
        Token a = new Token("A");
        Token b = new Token("B");
        Pool pool = new Pool(a, b, address(inbox));
        address[] memory targets = new address[](1);
        targets[0] = address(pool);
        inbox.restrictTo(targets);
        a.mint(vm.addr(deployer), 1000 ether);
        b.mint(vm.addr(deployer), 1000 ether);
        a.approve(address(pool), type(uint256).max);
        b.approve(address(pool), type(uint256).max);
        pool.addLiquidity(1000 ether, 1000 ether);
        a.mint(vm.addr(alice), 100 ether);
        a.mint(vm.addr(searcher), 1000 ether);
        b.mint(vm.addr(searcher), 1000 ether);
        vm.stopBroadcast();

        for (uint256 i = 0; i < 2; i++) {
            vm.startBroadcast(i == 0 ? alice : searcher);
            a.approve(address(pool), type(uint256).max);
            b.approve(address(pool), type(uint256).max);
            vm.stopBroadcast();
        }

        console2.log("INBOX", address(inbox));
        console2.log("ACCOUNT", inbox.account());
        console2.log("POOL", address(pool));
        console2.log("TOKEN_B", address(b));
    }
}
