// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {LeanSeal} from "./LeanSeal.sol";
import {SealedAccount} from "./SealedAccount.sol";

/// Orders structurally valid envelopes; solvability is not verified.
/// A missed reveal permanently locks deposit - bounty as the net penalty,
/// even when the withholding sender claims its own bounty. The deposit prices
/// only missed reveals: a sender that reveals on time and then revokes its
/// approvals or moves its funds makes its own call fail without penalty.
/// Plaintext is abi.encode(address target, bytes data, uint64 expiry).
/// gasLimit is the gas given to the delegated account call, including its wrapper.
///
/// Senders are accounts delegated (EIP-7702) to this inbox's own SealedAccount,
/// checked at submission and again before each call; a call from an account
/// whose delegation changed fails without blocking the queue.
///
/// Guarded pools refuse direct calls while the queue holds an unprocessed
/// ticket, from its submission until its slot executes, so a key read from a
/// pending reveal cannot buy a position ahead of its ticket. A late opening
/// joins the queue at the block of `forceOpen`, behind every earlier ticket.
/// A sealed call ordered ahead of a victim could still adapt to the victim's
/// revealed plaintext if it read state that someone wrote after the reveal;
/// `restrictTo` limits sealed calls to non-adaptive targets such as the pool,
/// which closes this for the demo market. General programs, and removing the
/// cancellation option above, need execution right after key release, as
/// LUCID provides at the protocol level.
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
    address public immutable account;
    bytes32 internal immutable delegation;
    uint256 public burned;
    uint64[] internal slots;
    uint256 public head;
    uint256 public cursor;
    mapping(uint64 => uint256) public slotGas;
    bool private busy;
    address public immutable admin;
    bool public restricted;
    mapping(address => bool) public allowedTarget;

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

    /// True while a queued ticket waits, except inside a sealed call.
    function locked() external view returns (bool) {
        return head < slots.length && !executing();
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
    error NotDelegated();

    constructor(
        uint256 deposit_,
        uint256 bounty_,
        uint64 revealWindow_,
        uint32 maxTicketGas_,
        uint64 slotGasBudget_,
        uint32 maxEnvelope_
    ) {
        require(bounty_ <= deposit_, "bounty exceeds deposit");
        admin = msg.sender;
        bounty = bounty_;
        maxTicketGas = maxTicketGas_;
        slotGasBudget = slotGasBudget_;
        maxEnvelope = maxEnvelope_;
        deposit = deposit_;
        revealWindow = revealWindow_;
        account = address(new SealedAccount(address(this)));
        delegation = keccak256(abi.encodePacked(hex"ef0100", account));
    }

    /// Limit sealed calls to `targets`, once. A call to any other target fails.
    function restrictTo(address[] calldata targets) external {
        require(msg.sender == admin && !restricted, "admin, once");
        restricted = true;
        for (uint256 i = 0; i < targets.length; i++) {
            allowedTarget[targets[i]] = true;
        }
    }

    function submit(bytes calldata envelope, uint32 gasLimit) external payable returns (uint256 id) {
        if (msg.value != deposit) revert BadDeposit();
        if (envelope.length > maxEnvelope) revert EnvelopeTooLarge();
        if (gasLimit > maxTicketGas) revert GasTooHigh();
        if (msg.sender.codehash != delegation) revert NotDelegated();
        bytes memory env = envelope;
        LeanSeal.validate(env);
        (bytes32 ctx, bytes32 commit) = LeanSeal.header(env, 8);
        id = tickets.length;
        uint64 slot = uint64(block.number);
        if (slotGas[slot] + gasLimit > slotGasBudget) revert SlotFull();
        slotGas[slot] += gasLimit;
        tickets.push(Ticket(msg.sender, slot, gasLimit, State.Sealed, keccak256(envelope), ctx, commit, 0));
        _enqueue(slot, id);
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
        _pay(t.sender, deposit);
    }

    /// Process a prefix of the head slot. Envelopes start at cursor; missed
    /// tickets may use empty bytes. Revealed and forced tickets run in queue
    /// order. Stop before a ticket whose gas cannot be delivered in full,
    /// retaining any progress already made.
    function execute(bytes[] calldata envelopes) external serial returns (uint256 processed) {
        if (head == slots.length) revert OutsideWindow();
        uint64 slot = slots[head];
        if (block.number <= uint256(slot) + revealWindow) revert OutsideWindow();
        uint256[] storage ids = slotTickets[slot];
        while (processed < envelopes.length && cursor < ids.length) {
            uint256 id = ids[cursor];
            Ticket storage t = tickets[id];
            if (!_enoughGas(t.gasLimit, envelopes[processed].length)) break;
            if (t.state == State.Sealed) {
                t.state = State.Missed;
                burned += deposit - bounty;
                emit Missed(id);
            } else {
                // Revealed in its window, or forced open and queued late.
                bool late = t.state == State.Forced;
                t.state = State.Executed;
                emit Executed(id, _run(t, envelopes[processed]), late);
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

    /// Publish a missed ticket's key late. The ticket joins the current block's
    /// slot and `execute` runs it in that order, behind every earlier ticket,
    /// so it never trades ahead of a revealed one. Its gas counts toward the
    /// slot's budget, which never refuses it. The caller receives only bounty;
    /// deposit - bounty remains locked forever, including when the sender
    /// claims. A late call's position is fixed only once its key is public:
    /// use slippage limits and expiry.
    function forceOpen(uint256 id, bytes32 key) external {
        Ticket storage t = tickets[id];
        if (t.state != State.Missed) revert WrongState();
        if (LeanSeal.commitment(t.context, key) != t.commitment) revert WrongKey();
        t.key = key;
        t.state = State.Forced;
        uint64 slot = uint64(block.number);
        slotGas[slot] += t.gasLimit;
        _enqueue(slot, id);
        emit Forced(id, msg.sender, key);
        _pay(msg.sender, bounty);
    }

    function _enqueue(uint64 slot, uint256 id) internal {
        if (slotTickets[slot].length == 0) slots.push(slot);
        slotTickets[slot].push(id);
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

    /// Decrypt and run one ticket; false if its sender no longer delegates to
    /// the canonical account, or the ticket fails to open, has expired or reverts.
    function _run(Ticket storage t, bytes calldata envelope) internal returns (bool) {
        if (keccak256(envelope) != t.envelopeHash) revert WrongEnvelope();
        address sender = t.sender;
        if (sender.codehash != delegation) return false;
        address target;
        bytes memory data;
        uint64 expiry;
        try this.openEnvelope(envelope, t.key) returns (address a, bytes memory d, uint64 e) {
            (target, data, expiry) = (a, d, e);
        } catch {
            return false;
        }
        if (block.number > expiry) return false;
        if (restricted && !allowedTarget[target]) return false;
        bytes memory input = abi.encodeCall(SealedAccount.run, (target, data));
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
