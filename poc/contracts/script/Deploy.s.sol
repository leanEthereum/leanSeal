// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {SealedInbox} from "../src/SealedInbox.sol";
import {SealedAccount} from "../src/SealedAccount.sol";
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
        SealedInbox inbox = new SealedInbox(0.01 ether, 2);
        SealedAccount account = new SealedAccount(address(inbox));
        Token a = new Token("A");
        Token b = new Token("B");
        Pool pool = new Pool(a, b);
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
        console2.log("ACCOUNT", address(account));
        console2.log("POOL", address(pool));
        console2.log("TOKEN_B", address(b));
    }
}
