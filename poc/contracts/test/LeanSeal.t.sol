// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LeanSeal} from "../src/LeanSeal.sol";

contract Harness {
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
}
