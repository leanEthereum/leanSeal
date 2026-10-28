// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

/// On-chain checks for leanSeal v1 (SPEC.md): key commitments and envelope
/// opening. Every hash is SHA-256, so the work is a few precompile calls.
library LeanSeal {
    error Format();
    error Commit();
    error Tag();

    bytes4 constant PUZZLE_MAGIC = "LSPZ";
    bytes8 constant ENVELOPE_MAGIC = "LSEN\x01\x00\x00\x00";

    /// Commitment to `key` under the puzzle context `ctx`.
    function commitment(bytes32 ctx, bytes32 key) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(uint8(18), "leanseal/v1/commit", ctx, key));
    }

    /// Length of the canonical puzzle starting at `at`, after checking its header.
    function puzzleLen(bytes memory data, uint256 at) internal pure returns (uint256) {
        if (data.length < at + 68) revert Format();
        bytes32 w0;
        assembly {
            w0 := mload(add(add(data, 32), at))
        }
        // "LSPZ" | version 1 | b | 0 0 | n (4) | m (8) | ...
        if (bytes4(w0) != PUZZLE_MAGIC || uint8(w0[4]) != 1 || w0[6] != 0 || w0[7] != 0) revert Format();
        uint256 b = uint8(w0[5]);
        uint256 n = uint32(bytes4(w0 << 64));
        uint256 m = uint64(bytes8(w0 << 96));
        if (b == 0 || b > 32 || n == 0 || n > 2 ** 20 || m == 0 || m > 2 ** 48 || n * m > 2 ** 60) revert Format();
        return 68 + n * b;
    }

    /// Context and commitment of the puzzle starting at `at`.
    function header(bytes memory data, uint256 at) internal pure returns (bytes32 ctx, bytes32 commit) {
        assembly {
            ctx := mload(add(add(data, 36), at))
            commit := mload(add(add(data, 68), at))
        }
    }

    /// Check `key` against the commitment of the puzzle inside envelope `env`.
    function checkKey(bytes memory env, bytes32 key) internal pure returns (bool) {
        puzzleLen(env, 8);
        (bytes32 ctx, bytes32 commit) = header(env, 8);
        return commitment(ctx, key) == commit;
    }

    /// The puzzle commitment of envelope `env`.
    function envelopeCommitment(bytes memory env) internal pure returns (bytes32 commit) {
        puzzleLen(env, 8);
        (, commit) = header(env, 8);
    }

    /// Validate canonical structure and bounds, not puzzle solvability.
    function validate(bytes memory env) internal pure {
        if (env.length < 8 || bytes8(_word(env, 0)) != ENVELOPE_MAGIC) revert Format();
        uint256 at = 8 + puzzleLen(env, 8);
        if (env.length < at + 52) revert Format();
        uint256 len = uint32(bytes4(_word(env, at + 16)));
        if (len > 2 ** 24 || env.length != at + 52 + len) revert Format();
    }

    /// Check the key and tag of envelope `env`, then decrypt it.
    function open(bytes memory env, bytes32 key) internal view returns (bytes memory out) {
        validate(env);
        uint256 at = 8 + puzzleLen(env, 8);
        (bytes32 ctx, bytes32 commit) = header(env, 8);
        if (commitment(ctx, key) != commit) revert Commit();
        bytes16 nonce = bytes16(_word(env, at));
        uint256 len = uint32(bytes4(_word(env, at + 16)));
        if (env.length != at + 52 + len) revert Format();
        uint256 end = at + 20 + len;
        bytes32 kmac = sha256(abi.encodePacked(uint8(15), "leanseal/v1/mac", key, nonce));
        if (hmac(kmac, _slice(env, 0, end)) != _word(env, end)) revert Tag();
        bytes32 kenc = sha256(abi.encodePacked(uint8(15), "leanseal/v1/enc", key, nonce));
        out = _slice(env, at + 20, len);
        for (uint256 i = 0; i * 32 < len; i++) {
            bytes32 ks = hmac(kenc, abi.encodePacked(uint64(i)));
            assembly {
                let p := add(add(out, 32), mul(i, 32))
                mstore(p, xor(mload(p), ks))
            }
        }
        // The last block's XOR may spill past `len`; that memory is not part of `out`.
    }

    function hmac(bytes32 key, bytes memory message) internal pure returns (bytes32) {
        bytes32 i0 = key ^ bytes32(0x3636363636363636363636363636363636363636363636363636363636363636);
        bytes32 o0 = key ^ bytes32(0x5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c);
        bytes32 i1 = bytes32(0x3636363636363636363636363636363636363636363636363636363636363636);
        bytes32 o1 = bytes32(0x5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c);
        return sha256(abi.encodePacked(o0, o1, sha256(abi.encodePacked(i0, i1, message))));
    }

    function _word(bytes memory data, uint256 at) private pure returns (bytes32 w) {
        assembly {
            w := mload(add(add(data, 32), at))
        }
    }

    function _slice(bytes memory data, uint256 at, uint256 len) private view returns (bytes memory out) {
        out = new bytes(len);
        bool ok;
        assembly {
            ok := staticcall(gas(), 4, add(add(data, 32), at), len, add(out, 32), len)
        }
        if (!ok) revert Format();
    }
}
