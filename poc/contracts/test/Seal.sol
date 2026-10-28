// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {LeanSeal} from "../src/LeanSeal.sol";

/// leanSeal's `seal` in Solidity, for tests only: envelopes under a known puzzle and key.
library Seal {
    function seal(bytes memory puzzle, bytes32 key, bytes16 nonce, bytes memory message)
        internal
        pure
        returns (bytes memory env)
    {
        bytes32 kenc = sha256(abi.encodePacked(uint8(15), "leanseal/v1/enc", key, nonce));
        bytes32 kmac = sha256(abi.encodePacked(uint8(15), "leanseal/v1/mac", key, nonce));
        bytes memory ct = new bytes(message.length);
        for (uint256 i = 0; i < message.length; i++) {
            bytes32 ks = LeanSeal.hmac(kenc, abi.encodePacked(uint64(i / 32)));
            ct[i] = message[i] ^ ks[i % 32];
        }
        env = abi.encodePacked(bytes8("LSEN\x01\x00\x00\x00"), puzzle, nonce, uint32(message.length), ct);
        env = abi.encodePacked(env, LeanSeal.hmac(kmac, env));
    }
}
