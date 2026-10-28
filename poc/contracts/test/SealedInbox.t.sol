// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {SealedInbox} from "../src/SealedInbox.sol";
import {SealedAccount} from "../src/SealedAccount.sol";
import {Token} from "../src/demo/Token.sol";
import {Pool} from "../src/demo/Pool.sol";
import {LeanSeal} from "../src/LeanSeal.sol";
import {Seal} from "./Seal.sol";

contract Burner {
    function burn() external pure {
        assembly {
            for {} 1 {} {}
        }
    }
}

contract ReentryProbe {
    SealedInbox public immutable inbox;
    bool public accepted;
    bool public wasExecuting;
    uint256 public hits;

    constructor(SealedInbox i) {
        inbox = i;
    }

    function ping() external {
        hits++;
        wasExecuting = inbox.executing();
        (accepted,) = address(inbox).call(abi.encodeCall(SealedInbox.execute, (new bytes[](1))));
    }
}

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

        inbox = new SealedInbox(DEPOSIT, 0.002 ether, WINDOW, 1_000_000, 10_000_000, 4096);
        account = new SealedAccount(address(inbox));
        a = new Token("A");
        b = new Token("B");
        pool = new Pool(a, b, address(inbox));
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
        inbox.execute(new bytes[](2));

        vm.roll(slot + WINDOW + 1);
        bytes[] memory envs = new bytes[](2);
        (envs[0], envs[1]) = (e0, e1);
        vm.prank(keeper);
        inbox.execute(envs);

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
        inbox.execute(envs);
        (,,, SealedInbox.State st,,,,) = inbox.tickets(id);
        assertEq(uint8(st), uint8(SealedInbox.State.Missed));
        assertEq(alice.balance, 1 ether - DEPOSIT, "deposit forfeited");

        // Minutes later a solver has the key from the puzzle.
        vm.roll(slot + 50);
        vm.prank(solver);
        vm.expectEmit(true, false, false, true);
        emit SealedInbox.Executed(id, true, true);
        inbox.forceOpen(id, key, e);
        assertEq(solver.balance, 0.002 ether, "solver paid");
        assertGt(b.balanceOf(alice), 0, "executed late");
    }

    function testExpiredForcedOpeningDoesNotExecute() public {
        bytes memory e = sealSwap(10 ether, 5);
        uint64 slot = uint64(block.number);
        uint256 id = submit(alice, e);
        vm.roll(slot + WINDOW + 1);
        inbox.execute(new bytes[](1));
        vm.roll(slot + 50);
        vm.prank(solver);
        vm.expectEmit(true, false, false, true);
        emit SealedInbox.Executed(id, false, true);
        inbox.forceOpen(id, key, e);
        assertEq(b.balanceOf(alice), 0);
        assertEq(solver.balance, 0.002 ether, "solver paid even when expired");
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
        inbox.execute(envs);
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
        inbox.execute(envs);
    }

    function ticketState(uint256 id) internal view returns (SealedInbox.State st) {
        (,,, st,,,,) = inbox.tickets(id);
    }

    function ready(bytes memory e) internal returns (uint256 id, bytes[] memory envs) {
        uint64 slot = uint64(block.number);
        id = submit(alice, e);
        vm.roll(slot + 1);
        inbox.reveal(id, key);
        vm.roll(slot + 3);
        envs = new bytes[](1);
        envs[0] = e;
    }

    function testUndelegatedSenderDoesNotBlockSlot() public {
        bytes memory e = sealSwap(10 ether, 100);
        uint256 bad = submit(bob, e);
        uint256 good = submit(alice, e);
        vm.etch(bob, hex"");
        vm.roll(block.number + 1);
        inbox.reveal(bad, key);
        inbox.reveal(good, key);
        vm.roll(block.number + 2);
        bytes[] memory envs = new bytes[](2);
        envs[0] = e;
        envs[1] = e;
        assertEq(inbox.execute(envs), 2);
        assertGt(b.balanceOf(alice), 0);
        assertEq(inbox.pendingReveals(), 0);
    }

    function testUnderfundedExecuteKeepsTicket() public {
        (uint256 id, bytes[] memory envs) = ready(sealSwap(10 ether, 100));
        (bool ok, bytes memory err) = address(inbox).call{gas: 300_000}(abi.encodeCall(SealedInbox.execute, (envs)));
        assertFalse(ok);
        assertEq(bytes4(err), SealedInbox.InsufficientGas.selector);
        assertEq(uint8(ticketState(id)), uint8(SealedInbox.State.Revealed));
        assertEq(inbox.cursor(), 0);
        assertEq(inbox.execute(envs), 1);
        assertGt(b.balanceOf(alice), 0);
    }

    function testOversizedGasRejected() public {
        bytes memory e = sealSwap(1 ether, 100);
        vm.expectRevert(SealedInbox.GasTooHigh.selector);
        inbox.submit{value: DEPOSIT}(e, 1_000_001);
    }

    function testSlotGasBudget() public {
        bytes memory e = sealSwap(1 ether, 100);
        for (uint256 i; i < 10; i++) {
            inbox.submit{value: DEPOSIT}(e, 1_000_000);
        }
        vm.expectRevert(SealedInbox.SlotFull.selector);
        inbox.submit{value: DEPOSIT}(e, 1);
    }

    function testBatchProgressAcrossCalls() public {
        bytes memory e = sealSwap(10 ether, 100);
        uint256 i0 = submit(alice, e);
        uint256 i1 = submit(bob, e);
        vm.roll(block.number + 1);
        inbox.reveal(i0, key);
        inbox.reveal(i1, key);
        vm.roll(block.number + 2);
        bytes[] memory envs = new bytes[](2);
        envs[0] = e;
        envs[1] = e;
        // Enough to deliver the first allowance, but not both reserves.
        uint256 processed = inbox.execute{gas: 700_000}(envs);
        assertEq(processed, 1);
        assertEq(inbox.cursor(), 1);
        assertEq(uint8(ticketState(i1)), uint8(SealedInbox.State.Revealed));
        envs = new bytes[](1);
        envs[0] = e;
        assertEq(inbox.execute(envs), 1);
        assertEq(inbox.head(), 1);
        assertEq(inbox.cursor(), 0);
        assertGt(b.balanceOf(alice), b.balanceOf(bob));
    }

    function testMalformedEnvelopeRejectedAtSubmit() public {
        bytes memory e = abi.encodePacked(bytes8(0), puzzle);
        vm.expectRevert(LeanSeal.Format.selector);
        inbox.submit{value: DEPOSIT}(e, 200_000);
        e = sealSwap(1 ether, 100);
        e[0] = 0;
        vm.expectRevert(LeanSeal.Format.selector);
        inbox.submit{value: DEPOSIT}(e, 200_000);
        vm.expectRevert(SealedInbox.EnvelopeTooLarge.selector);
        inbox.submit{value: DEPOSIT}(new bytes(4097), 200_000);
    }

    function testOutOfSpecParametersRejected() public {
        bytes32 ctx =
            bytes32(abi.encodePacked(uint8(1), uint8(1), uint16(0), uint32(1), uint64((1 << 48) + 1), bytes16(0)));
        bytes memory p = abi.encodePacked(bytes4("LSPZ"), ctx, LeanSeal.commitment(ctx, key), bytes1(0));
        bytes memory e = Seal.seal(p, key, bytes16(0), hex"abcdef");
        vm.expectRevert(LeanSeal.Format.selector);
        inbox.submit{value: DEPOSIT}(e, 200_000);
    }

    function testSlotsExecuteInOrder() public {
        bytes memory e0 = sealSwap(10 ether, 100);
        bytes memory e1 = sealSwap(10 ether, 100);
        uint256 id0 = submit(alice, e0);
        vm.roll(block.number + 1);
        uint256 id1 = submit(bob, e1);
        inbox.reveal(id0, key);
        vm.roll(block.number + 1);
        inbox.reveal(id1, key);
        vm.roll(block.number + 3);
        bytes[] memory envs = new bytes[](1);
        envs[0] = e1;
        vm.expectRevert(SealedInbox.WrongEnvelope.selector);
        inbox.execute(envs);
        envs[0] = e0;
        inbox.execute(envs);
        envs[0] = e1;
        inbox.execute(envs);
        assertGt(b.balanceOf(alice), b.balanceOf(bob));
        assertEq(inbox.head(), inbox.queueLength());
    }

    function testRevealedSwapCannotBeFrontRun() public {
        (, bytes[] memory envs) = ready(sealSwap(10 ether, 100));
        vm.prank(bob);
        vm.expectRevert("locked");
        pool.swap(true, 50 ether, 0);
        vm.expectRevert("locked");
        pool.addLiquidity(1, 1);
        inbox.execute(envs);
        vm.prank(bob);
        pool.swap(true, 50 ether, 0);
        assertFalse(inbox.locked());
    }

    function testForceOpenWaitsWhileLocked() public {
        bytes memory e = sealSwap(10 ether, 1000);
        uint256 id = submit(alice, e);
        vm.roll(block.number + 3);
        inbox.execute(new bytes[](1));
        // A later ticket is revealed; the missed one must not jump ahead of it.
        (, bytes[] memory envs) = ready(sealSwap(10 ether, 1000));
        vm.prank(alice);
        vm.expectRevert(SealedInbox.Locked.selector);
        inbox.forceOpen(id, key, e);
        inbox.execute(envs);
        vm.prank(alice);
        inbox.forceOpen(id, key, e);
        (,,, SealedInbox.State st,,,,) = inbox.tickets(id);
        assertEq(uint8(st), uint8(SealedInbox.State.Forced));
    }

    function testRestrictedTargets() public {
        address[] memory targets = new address[](1);
        targets[0] = address(pool);
        inbox.restrictTo(targets);
        vm.expectRevert("admin, once");
        inbox.restrictTo(targets);
        bytes memory toPool = sealSwap(10 ether, 100);
        bytes memory toToken = Seal.seal(
            puzzle,
            key,
            bytes16(++nonces),
            abi.encode(address(a), abi.encodeCall(Token.mint, (alice, 1 ether)), uint64(100))
        );
        uint256 id0 = submit(alice, toPool);
        uint256 id1 = submit(bob, toToken);
        vm.roll(block.number + 1);
        inbox.reveal(id0, key);
        inbox.reveal(id1, key);
        vm.roll(block.number + WINDOW);
        bytes[] memory envs = new bytes[](2);
        (envs[0], envs[1]) = (toPool, toToken);
        vm.expectEmit(true, false, false, true);
        emit SealedInbox.Executed(id0, true, false);
        vm.expectEmit(true, false, false, true);
        emit SealedInbox.Executed(id1, false, false);
        inbox.execute(envs);
    }

    function testForceOpenPaysOnlyBounty() public {
        bytes memory e = sealSwap(10 ether, 100);
        uint256 id = submit(alice, e);
        vm.roll(block.number + 3);
        inbox.execute(new bytes[](1));
        vm.prank(alice);
        inbox.forceOpen(id, key, e);
        assertEq(alice.balance, 1 ether - DEPOSIT + inbox.bounty());
        assertEq(inbox.burned(), DEPOSIT - inbox.bounty());
        assertEq(address(inbox).balance, inbox.burned());
    }

    function testUnderfundedForceOpenKeepsTicket() public {
        bytes memory e = sealSwap(10 ether, 100);
        uint256 id = submit(alice, e);
        vm.roll(block.number + 3);
        inbox.execute(new bytes[](1));
        (bool ok,) = address(inbox).call{gas: 300_000}(abi.encodeCall(SealedInbox.forceOpen, (id, key, e)));
        assertFalse(ok);
        assertEq(uint8(ticketState(id)), uint8(SealedInbox.State.Missed));
        vm.prank(solver);
        inbox.forceOpen(id, key, e);
    }

    function testGasBurnerDoesNotBlockFollowingTicket() public {
        Burner burner = new Burner();
        bytes memory bad = Seal.seal(
            puzzle,
            key,
            bytes16(uint128(123)),
            abi.encode(address(burner), abi.encodeCall(Burner.burn, ()), uint64(100))
        );
        bytes memory good = sealSwap(10 ether, 100);
        vm.prank(bob);
        uint256 id0 = inbox.submit{value: DEPOSIT}(bad, 1_000_000);
        uint256 id1 = submit(alice, good);
        vm.roll(block.number + 1);
        inbox.reveal(id0, key);
        inbox.reveal(id1, key);
        vm.roll(block.number + 2);
        bytes[] memory envs = new bytes[](2);
        envs[0] = bad;
        envs[1] = good;
        assertEq(inbox.execute{gas: 3_000_000}(envs), 2);
        assertGt(b.balanceOf(alice), 0);
        assertFalse(inbox.executing());
    }

    function testReentrantExecutionCannotAdvanceQueue() public {
        ReentryProbe probe = new ReentryProbe(inbox);
        bytes memory e = Seal.seal(
            puzzle,
            key,
            bytes16(uint128(123)),
            abi.encode(address(probe), abi.encodeCall(ReentryProbe.ping, ()), uint64(100))
        );
        (, bytes[] memory envs) = ready(e);
        inbox.execute(envs);
        assertEq(probe.hits(), 1);
        assertTrue(probe.wasExecuting());
        assertFalse(probe.accepted());
        assertFalse(inbox.executing());
        assertEq(inbox.head(), 1);
    }
}
