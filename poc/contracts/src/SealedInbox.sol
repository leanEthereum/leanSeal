// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {LeanSeal} from "./LeanSeal.sol";
import {SealedAccount} from "./SealedAccount.sol";

/// Orders structurally valid envelopes; solvability is not verified.
/// A missed reveal permanently locks deposit - bounty as the net penalty,
/// even when the withholding sender claims its own bounty.
/// Plaintext is abi.encode(address target, bytes data, uint64 expiry).
/// gasLimit is the gas given to the delegated account call, including its wrapper.
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
    uint256 public immutable bounty;
    uint32 public immutable maxTicketGas;
    uint64 public immutable slotGasBudget;
    uint32 public immutable maxEnvelope;
    uint256 public burned;
    uint256 public pendingReveals;
    uint64[] internal slots;
    uint256 public head;
    uint256 public cursor;
    mapping(uint64 => uint256) public slotGas;
    bool private busy;

    modifier serial() {
        require(!busy, "busy");
        busy = true;
        _;
        busy = false;
    }

    function executing() public view returns (bool active) {
        assembly {
            active := tload(0)
        }
    }

    function locked() external view returns (bool) {
        return pendingReveals > 0 && !executing();
    }

    function queueLength() external view returns (uint256) {
        return slots.length;
    }

    function slotAt(uint256 i) external view returns (uint64) {
        return slots[i];
    }

    Ticket[] public tickets;
    mapping(uint64 => uint256[]) internal slotTickets;
    mapping(uint64 => bool) public slotDone;

    event Sealed(uint256 indexed id, uint64 indexed slot, address indexed sender, uint32 gasLimit, bytes envelope);
    event Revealed(uint256 indexed id, bytes32 key);
    event Executed(uint256 indexed id, bool ok, bool late);
    event Missed(uint256 indexed id);
    event Forced(uint256 indexed id, address solver, bytes32 key);

    event Progress(uint256 head, uint256 cursor);

    error InsufficientGas();
    error GasTooHigh();
    error SlotFull();
    error EnvelopeTooLarge();
    error BadDeposit();
    error WrongState();
    error OutsideWindow();
    error WrongKey();
    error WrongEnvelope();

    constructor(
        uint256 deposit_,
        uint256 bounty_,
        uint64 revealWindow_,
        uint32 maxTicketGas_,
        uint64 slotGasBudget_,
        uint32 maxEnvelope_
    ) {
        require(bounty_ <= deposit_, "bounty exceeds deposit");
        bounty = bounty_;
        maxTicketGas = maxTicketGas_;
        slotGasBudget = slotGasBudget_;
        maxEnvelope = maxEnvelope_;
        deposit = deposit_;
        revealWindow = revealWindow_;
    }

    function submit(bytes calldata envelope, uint32 gasLimit) external payable returns (uint256 id) {
        if (msg.value != deposit) revert BadDeposit();
        if (envelope.length > maxEnvelope) revert EnvelopeTooLarge();
        if (gasLimit > maxTicketGas) revert GasTooHigh();
        bytes memory env = envelope;
        LeanSeal.validate(env);
        (bytes32 ctx, bytes32 commit) = LeanSeal.header(env, 8);
        id = tickets.length;
        uint64 slot = uint64(block.number);
        if (slotGas[slot] + gasLimit > slotGasBudget) revert SlotFull();
        slotGas[slot] += gasLimit;
        if (slotTickets[slot].length == 0) slots.push(slot);
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
        pendingReveals++;
        emit Revealed(id, key);
        _pay(t.sender, deposit);
    }

    /// Process a prefix of the head slot. Envelopes start at cursor; missed
    /// tickets may use empty bytes. Stop before a ticket whose gas cannot be
    /// delivered in full, retaining any progress already made.
    function execute(bytes[] calldata envelopes) external serial returns (uint256 processed) {
        if (head == slots.length) revert OutsideWindow();
        uint64 slot = slots[head];
        if (block.number <= uint256(slot) + revealWindow) revert OutsideWindow();
        uint256[] storage ids = slotTickets[slot];
        while (processed < envelopes.length && cursor < ids.length) {
            uint256 id = ids[cursor];
            Ticket storage t = tickets[id];
            if (!_enoughGas(t.gasLimit, envelopes[processed].length)) break;
            if (t.state == State.Revealed) {
                t.state = State.Executed;
                pendingReveals--;
                emit Executed(id, _run(t, envelopes[processed]), false);
            } else {
                t.state = State.Missed;
                burned += deposit - bounty;
                emit Missed(id);
            }
            cursor++;
            processed++;
        }
        if (processed == 0) revert InsufficientGas();
        if (cursor == ids.length) {
            slotDone[slot] = true;
            head++;
            cursor = 0;
        }
        emit Progress(head, cursor);
    }

    /// A late opening receives only bounty. deposit - bounty remains locked
    /// forever, including when the sender claims. Late calls have no reserved
    /// pool position: use slippage limits and expiry.
    function forceOpen(uint256 id, bytes32 key, bytes calldata envelope) external serial {
        Ticket storage t = tickets[id];
        if (t.state != State.Missed) revert WrongState();
        if (LeanSeal.commitment(t.context, key) != t.commitment) revert WrongKey();
        if (!_enoughGas(t.gasLimit, envelope.length)) revert InsufficientGas();
        t.key = key;
        t.state = State.Forced;
        emit Forced(id, msg.sender, key);
        emit Executed(id, _run(t, envelope), true);
        _pay(msg.sender, bounty);
    }

    // Covers EIP-150, cold account access, SHA/precompile work per byte,
    // memory/ABI copying and state/event cleanup for the bounded envelope.
    function _enoughGas(uint32 gasLimit, uint256 len) internal view returns (bool) {
        return gasleft() >= uint256(gasLimit) + (uint256(gasLimit) + 62) / 63 + 150_000 + len * 500 + len * len / 256;
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
        bytes memory input = abi.encodeCall(SealedAccount.run, (target, data));
        address sender = t.sender;
        uint256 allowance = t.gasLimit;
        bool ok;
        assembly {
            tstore(0, 1)
            ok := call(allowance, sender, 0, add(input, 32), mload(input), 0, 0)
            tstore(0, 0)
        }
        return ok;
    }

    /// Decrypt and decode an envelope; external so that `_run` can catch failures.
    function openEnvelope(bytes calldata envelope, bytes32 key) external view returns (address, bytes memory, uint64) {
        return abi.decode(LeanSeal.open(envelope, key), (address, bytes, uint64));
    }

    function _pay(address to, uint256 amount) internal {
        (bool ok,) = to.call{value: amount}("");
        require(ok, "payment failed");
    }
}
