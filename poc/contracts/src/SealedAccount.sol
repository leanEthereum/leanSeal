// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

/// EIP-7702 delegate for a sender's account: the inbox may make calls as the
/// account, so an opened transaction runs with the sender's own address,
/// balances and approvals.
contract SealedAccount {
    address public immutable inbox;

    constructor(address inbox_) {
        inbox = inbox_;
    }

    receive() external payable {}

    function run(address target, bytes calldata data) external {
        require(msg.sender == inbox, "only inbox");
        (bool ok, bytes memory ret) = target.call(data);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
    }
}
