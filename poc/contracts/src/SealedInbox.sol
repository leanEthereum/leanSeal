// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {LeanSeal} from "./LeanSeal.sol";
import {SealedAccount} from "./SealedAccount.sol";

/// An encrypted mempool as a contract. Senders submit leanSeal envelopes; the
/// block that includes them fixes their order before anyone can read them.
/// Each sender then reveals its key within `revealWindow` blocks, and after
/// the window anyone executes the slot's transactions in order. A sender that
/// stays silent forfeits its deposit; anyone who solves the puzzle can open
/// the transaction later, collect the deposit and, before the transaction's
/// own expiry, execute it.
///
/// The plaintext of an envelope is abi.encode(address target, bytes data,
/// uint64 expiry). It runs as a call from the sender's account, which must
/// delegate to SealedAccount (EIP-7702).
contract SealedInbox {
    enum State {
        None,
        Sealed,
        Revealed,
        Executed,
        Missed,
        Forced
    }

    struct Ticket {
        address sender;
        uint64 slot;
        uint32 gasLimit;
        State state;
        bytes32 envelopeHash;
        bytes32 context;
        bytes32 commitment;
        bytes32 key;
    }

    uint256 public immutable deposit;
    uint64 public immutable revealWindow;

    Ticket[] public tickets;
    mapping(uint64 => uint256[]) internal slotTickets;
    mapping(uint64 => bool) public slotDone;

    event Sealed(uint256 indexed id, uint64 indexed slot, address indexed sender, uint32 gasLimit, bytes envelope);
    event Revealed(uint256 indexed id, bytes32 key);
    event Executed(uint256 indexed id, bool ok, bool late);
    event Missed(uint256 indexed id);
    event Forced(uint256 indexed id, address solver, bytes32 key);

    error BadDeposit();
    error WrongState();
    error OutsideWindow();
    error WrongKey();
    error WrongEnvelope();

    constructor(uint256 deposit_, uint64 revealWindow_) {
        deposit = deposit_;
        revealWindow = revealWindow_;
    }

    function submit(bytes calldata envelope, uint32 gasLimit) external payable returns (uint256 id) {
        if (msg.value != deposit) revert BadDeposit();
        bytes memory env = envelope;
        LeanSeal.puzzleLen(env, 8);
        (bytes32 ctx, bytes32 commit) = LeanSeal.header(env, 8);
        id = tickets.length;
        uint64 slot = uint64(block.number);
        tickets.push(Ticket(msg.sender, slot, gasLimit, State.Sealed, keccak256(envelope), ctx, commit, 0));
        slotTickets[slot].push(id);
        emit Sealed(id, slot, msg.sender, gasLimit, envelope);
    }

    /// Publish the key of a sealed ticket within its window. Anyone holding the
    /// key may do this; the deposit goes back to the sender.
    function reveal(uint256 id, bytes32 key) external {
        Ticket storage t = tickets[id];
        if (t.state != State.Sealed) revert WrongState();
        if (block.number <= t.slot || block.number > t.slot + revealWindow) revert OutsideWindow();
        if (LeanSeal.commitment(t.context, key) != t.commitment) revert WrongKey();
        t.key = key;
        t.state = State.Revealed;
        emit Revealed(id, key);
        _pay(t.sender);
    }

    /// After the window, run the slot's revealed transactions in their
    /// committed order. `envelopes[i]` is the envelope of the slot's i-th
    /// ticket, from its Sealed event; it may be empty for unrevealed tickets.
    function execute(uint64 slot, bytes[] calldata envelopes) external {
        if (slotDone[slot] || block.number <= slot + revealWindow) revert OutsideWindow();
        slotDone[slot] = true;
        uint256[] storage ids = slotTickets[slot];
        for (uint256 i = 0; i < ids.length; i++) {
            Ticket storage t = tickets[ids[i]];
            if (t.state == State.Revealed) {
                t.state = State.Executed;
                emit Executed(ids[i], _run(t, envelopes[i]), false);
            } else {
                t.state = State.Missed;
                emit Missed(ids[i]);
            }
        }
    }

    /// Open a missed ticket with a key found by solving its puzzle. The solver
    /// collects the forfeited deposit; the transaction runs late if it has not
    /// expired.
    function forceOpen(uint256 id, bytes32 key, bytes calldata envelope) external {
        Ticket storage t = tickets[id];
        if (t.state != State.Missed) revert WrongState();
        if (LeanSeal.commitment(t.context, key) != t.commitment) revert WrongKey();
        t.key = key;
        t.state = State.Forced;
        emit Forced(id, msg.sender, key);
        emit Executed(id, _run(t, envelope), true);
        _pay(msg.sender);
    }

    function slotLength(uint64 slot) external view returns (uint256) {
        return slotTickets[slot].length;
    }

    function slotTicket(uint64 slot, uint256 i) external view returns (uint256) {
        return slotTickets[slot][i];
    }

    function ticketCount() external view returns (uint256) {
        return tickets.length;
    }

    /// Decrypt and run one ticket; false if it fails to open, has expired or reverts.
    function _run(Ticket storage t, bytes calldata envelope) internal returns (bool) {
        if (keccak256(envelope) != t.envelopeHash) revert WrongEnvelope();
        address target;
        bytes memory data;
        uint64 expiry;
        try this.openEnvelope(envelope, t.key) returns (address a, bytes memory d, uint64 e) {
            (target, data, expiry) = (a, d, e);
        } catch {
            return false;
        }
        if (block.number > expiry) return false;
        try SealedAccount(payable(t.sender)).run{gas: t.gasLimit}(target, data) {
            return true;
        } catch {
            return false;
        }
    }

    /// Decrypt and decode an envelope; external so that `_run` can catch failures.
    function openEnvelope(bytes calldata envelope, bytes32 key) external view returns (address, bytes memory, uint64) {
        return abi.decode(LeanSeal.open(envelope, key), (address, bytes, uint64));
    }

    function _pay(address to) internal {
        (bool ok,) = to.call{value: deposit}("");
        require(ok, "payment failed");
    }
}
