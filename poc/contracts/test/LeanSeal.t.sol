// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Seal} from "./Seal.sol";
import {LeanSeal} from "../src/LeanSeal.sol";

contract Harness {
    function puzzleLength(bytes memory p) external pure returns (uint256) {
        return LeanSeal.puzzleLen(p, 0);
    }

    function validate(bytes memory env) external pure {
        LeanSeal.validate(env);
    }

    function open(bytes memory env, bytes32 key) external view returns (bytes memory) {
        return LeanSeal.open(env, key);
    }

    function checkKey(bytes memory env, bytes32 key) external pure returns (bool) {
        return LeanSeal.checkKey(env, key);
    }
}

contract LeanSealTest is Test {
    Harness h = new Harness();
    string json;

    function setUp() public {
        json = vm.readFile("test/vectors.json");
    }

    function testVectors() public view {
        for (uint256 i = 0; i < 7; i++) {
            string memory p = string.concat(".cases[", vm.toString(i), "]");
            bytes memory env = vm.parseJsonBytes(json, string.concat(p, ".envelope"));
            bytes32 key = vm.parseJsonBytes32(json, string.concat(p, ".key"));
            bytes memory message = vm.parseJsonBytes(json, string.concat(p, ".message"));
            assertTrue(h.checkKey(env, key));
            assertEq(h.open(env, key), message);
            assertFalse(h.checkKey(env, key ^ bytes32(uint256(1))));
        }
    }

    function testWrongKeyReverts() public {
        bytes memory env = vm.parseJsonBytes(json, ".cases[3].envelope");
        bytes32 key = vm.parseJsonBytes32(json, ".cases[3].key");
        vm.expectRevert(LeanSeal.Commit.selector);
        h.open(env, key ^ bytes32(uint256(1)));
    }

    function testTamperedCiphertextReverts() public {
        bytes memory env = vm.parseJsonBytes(json, ".cases[3].envelope");
        bytes32 key = vm.parseJsonBytes32(json, ".cases[3].key");
        env[env.length - 40] ^= 0x01;
        vm.expectRevert(LeanSeal.Tag.selector);
        h.open(env, key);
    }

    function testInvalidEnvelopesRevert() public {
        bytes32 key = vm.parseJsonBytes32(json, ".cases[0].key");
        bytes[] memory bad = vm.parseJsonBytesArray(json, ".invalid");
        for (uint256 i = 0; i < bad.length; i++) {
            (bool ok,) = address(h).call(abi.encodeCall(Harness.open, (bad[i], key)));
            assertFalse(ok);
        }
    }

    function invalidParameters(uint8 width, uint32 n, uint64 m) internal {
        bytes32 key = bytes32(uint256(42));
        bytes32 ctx = bytes32(abi.encodePacked(uint8(1), width, uint16(0), n, m, bytes16(0)));
        // Recompute both commitment and authentication tag for each invalid
        // header. Check puzzleLen separately so missing links cannot explain
        // rejection of a header's numerical bounds.
        bytes memory puzzle = abi.encodePacked(bytes4("LSPZ"), ctx, LeanSeal.commitment(ctx, key), bytes1(0));
        bytes memory env = Seal.seal(puzzle, key, bytes16(0), hex"abcdef");
        vm.expectRevert(LeanSeal.Format.selector);
        h.puzzleLength(puzzle);
        vm.expectRevert(LeanSeal.Format.selector);
        h.validate(env);
        vm.expectRevert(LeanSeal.Format.selector);
        h.open(env, key);
    }

    function testAuthenticatedOutOfBoundsHeaders() public {
        invalidParameters(0, 1, 1);
        invalidParameters(33, 1, 1);
        invalidParameters(1, 0, 1);
        invalidParameters(1, (1 << 20) + 1, 1);
        invalidParameters(1, 1, 0);
        invalidParameters(1, 1, (1 << 48) + 1);
        invalidParameters(1, 1 << 20, (1 << 40) + 1);
    }

    function testAuthenticatedOversizedCiphertextLength() public {
        bytes32 key = bytes32(uint256(42));
        bytes32 ctx = bytes32(abi.encodePacked(uint8(1), uint8(1), uint16(0), uint32(1), uint64(1), bytes16(0)));
        bytes memory puzzle = abi.encodePacked(bytes4("LSPZ"), ctx, LeanSeal.commitment(ctx, key), bytes1(0));
        bytes memory body = abi.encodePacked(bytes8("LSEN\x01\x00\x00\x00"), puzzle, bytes16(0), uint32((1 << 24) + 1));
        bytes32 kmac = sha256(abi.encodePacked(uint8(15), "leanseal/v1/mac", key, bytes16(0)));
        bytes memory env = abi.encodePacked(body, LeanSeal.hmac(kmac, body));
        vm.expectRevert(LeanSeal.Format.selector);
        h.validate(env);
        vm.expectRevert(LeanSeal.Format.selector);
        h.open(env, key);
    }

    function testPartialBlocksAndFollowingAllocation() public view {
        bytes memory puzzle = vm.parseJsonBytes(json, ".cases[4].puzzle");
        bytes32 key = vm.parseJsonBytes32(json, ".cases[4].key");
        for (uint256 len; len <= 97; len++) {
            bytes memory plain = new bytes(len);
            for (uint256 i; i < len; i++) {
                plain[i] = bytes1(uint8(i));
            }
            bytes memory out = h.open(Seal.seal(puzzle, key, bytes16(uint128(len)), plain), key);
            bytes memory afterOut = abi.encode(uint256(123), new bytes(65));
            assertEq(out, plain);
            assertEq(abi.decode(afterOut, (uint256)), 123);
        }
    }
}
