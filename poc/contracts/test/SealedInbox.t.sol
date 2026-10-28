// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {SealedInbox} from "../src/SealedInbox.sol";
import {SealedAccount} from "../src/SealedAccount.sol";
import {Token} from "../src/demo/Token.sol";
import {Pool} from "../src/demo/Pool.sol";
import {Seal} from "./Seal.sol";

contract SealedInboxTest is Test {
    uint256 constant DEPOSIT = 0.01 ether;
    uint64 constant WINDOW = 2;

    SealedInbox inbox;
    SealedAccount account;
    Token a;
    Token b;
    Pool pool;
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address solver = makeAddr("solver");
    address keeper = makeAddr("keeper");

    bytes puzzle;
    bytes32 key;
    uint128 nonces;

    function setUp() public {
        string memory json = vm.readFile("test/vectors.json");
        puzzle = vm.parseJsonBytes(json, ".cases[4].puzzle");
        key = vm.parseJsonBytes32(json, ".cases[4].key");

        inbox = new SealedInbox(DEPOSIT, WINDOW);
        account = new SealedAccount(address(inbox));
        a = new Token("A");
        b = new Token("B");
        pool = new Pool(a, b);
        a.mint(address(this), 1000 ether);
        b.mint(address(this), 1000 ether);
        a.approve(address(pool), type(uint256).max);
        b.approve(address(pool), type(uint256).max);
        pool.addLiquidity(1000 ether, 1000 ether);

        for (uint256 i = 0; i < 2; i++) {
            address u = i == 0 ? alice : bob;
            vm.etch(u, abi.encodePacked(hex"ef0100", address(account)));
            vm.deal(u, 1 ether);
            a.mint(u, 100 ether);
            vm.prank(u);
            a.approve(address(pool), type(uint256).max);
        }
    }

    function sealSwap(uint256 amountIn, uint64 expiry) internal returns (bytes memory) {
        bytes memory call = abi.encodeCall(Pool.swap, (true, amountIn, 0));
        return Seal.seal(puzzle, key, bytes16(++nonces), abi.encode(address(pool), call, expiry));
    }

    function submit(address from, bytes memory env) internal returns (uint256 id) {
        vm.prank(from);
        id = inbox.submit{value: DEPOSIT}(env, 200_000);
    }

    function testRevealAndExecuteInOrder() public {
        bytes memory e0 = sealSwap(10 ether, 100);
        bytes memory e1 = sealSwap(10 ether, 100);
        uint64 slot = uint64(block.number);
        uint256 id0 = submit(alice, e0);
        uint256 id1 = submit(bob, e1);

        vm.roll(slot + 1);
        inbox.reveal(id1, key);
        inbox.reveal(id0, key);
        assertEq(alice.balance, 1 ether, "deposit refunded");

        vm.expectRevert(SealedInbox.OutsideWindow.selector);
        inbox.execute(slot, new bytes[](2));

        vm.roll(slot + WINDOW + 1);
        bytes[] memory envs = new bytes[](2);
        (envs[0], envs[1]) = (e0, e1);
        vm.prank(keeper);
        inbox.execute(slot, envs);

        // Alice was first in the committed order, so she got the better price.
        uint256 outAlice = b.balanceOf(alice);
        uint256 outBob = b.balanceOf(bob);
        assertGt(outAlice, outBob);
        assertEq(outAlice, uint256(10 ether) * 1000 ether / 1010 ether);
    }

    function testWithheldKeyIsForcedOpen() public {
        bytes memory e = sealSwap(10 ether, 1000);
        uint64 slot = uint64(block.number);
        uint256 id = submit(alice, e);

        vm.roll(slot + WINDOW + 1);
        bytes[] memory envs = new bytes[](1);
        inbox.execute(slot, envs);
        (,,, SealedInbox.State st,,,,) = inbox.tickets(id);
        assertEq(uint8(st), uint8(SealedInbox.State.Missed));
        assertEq(alice.balance, 1 ether - DEPOSIT, "deposit forfeited");

        // Minutes later a solver has the key from the puzzle.
        vm.roll(slot + 50);
        vm.prank(solver);
        vm.expectEmit(true, false, false, true);
        emit SealedInbox.Executed(id, true, true);
        inbox.forceOpen(id, key, e);
        assertEq(solver.balance, DEPOSIT, "solver paid");
        assertGt(b.balanceOf(alice), 0, "executed late");
    }

    function testExpiredForcedOpeningDoesNotExecute() public {
        bytes memory e = sealSwap(10 ether, 5);
        uint64 slot = uint64(block.number);
        uint256 id = submit(alice, e);
        vm.roll(slot + WINDOW + 1);
        inbox.execute(slot, new bytes[](1));
        vm.roll(slot + 50);
        vm.prank(solver);
        vm.expectEmit(true, false, false, true);
        emit SealedInbox.Executed(id, false, true);
        inbox.forceOpen(id, key, e);
        assertEq(b.balanceOf(alice), 0);
        assertEq(solver.balance, DEPOSIT, "solver paid even when expired");
    }

    function testRejectsWrongKeyAndLateReveal() public {
        uint64 slot = uint64(block.number);
        uint256 id = submit(alice, sealSwap(1 ether, 100));
        vm.expectRevert(SealedInbox.OutsideWindow.selector);
        inbox.reveal(id, key); // same block as the ordering
        vm.roll(slot + 1);
        vm.expectRevert(SealedInbox.WrongKey.selector);
        inbox.reveal(id, key ^ bytes32(uint256(1)));
        vm.roll(slot + WINDOW + 1);
        vm.expectRevert(SealedInbox.OutsideWindow.selector);
        inbox.reveal(id, key);
    }

    function testGarbageDoesNotBlockTheSlot() public {
        bytes memory junk = Seal.seal(puzzle, key, bytes16(uint128(77)), hex"deadbeef");
        bytes memory good = sealSwap(10 ether, 100);
        uint64 slot = uint64(block.number);
        uint256 id0 = submit(bob, junk);
        uint256 id1 = submit(alice, good);
        vm.roll(slot + 1);
        inbox.reveal(id0, key);
        inbox.reveal(id1, key);
        vm.roll(slot + WINDOW + 1);
        bytes[] memory envs = new bytes[](2);
        (envs[0], envs[1]) = (junk, good);
        inbox.execute(slot, envs);
        assertGt(b.balanceOf(alice), 0);
    }

    function testEnvelopeMustMatchCommittedHash() public {
        bytes memory e = sealSwap(10 ether, 100);
        uint64 slot = uint64(block.number);
        uint256 id = submit(alice, e);
        vm.roll(slot + 1);
        inbox.reveal(id, key);
        vm.roll(slot + WINDOW + 1);
        bytes[] memory envs = new bytes[](1);
        envs[0] = sealSwap(90 ether, 100); // same key, different transaction
        vm.expectRevert(SealedInbox.WrongEnvelope.selector);
        inbox.execute(slot, envs);
    }
}
