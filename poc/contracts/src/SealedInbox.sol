// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {LeanSeal} from "./LeanSeal.sol";
import {SealedAccount} from "./SealedAccount.sol";

/// Orders structurally valid envelopes whose puzzles are within fixed work
/// limits; solvability is not verified. Each sender may have at most `maxOpen`
/// puzzles whose keys are not yet public.
/// A missed reveal permanently locks deposit - bounty as the net penalty,
/// even when the withholding sender claims its own bounty. The deposit prices
/// only missed reveals: a sender that reveals on time and then revokes its
/// approvals or moves its funds makes its own call fail without penalty.
/// The bond prices malformation. Once a key matching the commitment is
/// known, from a reveal or a forced opening, the envelope's tag is checked:
/// if it verifies, the bond is credited back to the sender, and if it fails,
/// the bond is burned. Chains that do not lead to the committed key cannot be
/// proved here, since that needs a verification game; the bond of such a
/// ticket stays locked with its deposit.
/// Plaintext is abi.encode(address target, bytes data, uint64 expiry).
/// gasLimit is the gas given to the delegated account call, including its wrapper.
///
/// Senders are accounts delegated (EIP-7702) to this inbox's own SealedAccount,
/// checked at submission and again before each call; a call from an account
/// whose delegation changed fails without blocking the queue.
///
/// Guarded pools refuse direct calls while the queue holds an unprocessed
/// ticket, from its submission until its slot executes, so a key read from a
/// pending reveal cannot buy a position ahead of its ticket. A ticket whose
/// reveal misses the window never runs: a builder that kept a pending reveal
/// out of the window already holds its key, and could trade around the ticket
/// if it ran later. `forceOpen` only publishes such a key. An honest sender
/// whose reveal is censored for `revealWindow` blocks loses deposit - bounty.
/// A sealed call ordered ahead of a victim could still adapt to the victim's
/// revealed plaintext if it read state that someone wrote after the reveal, so
/// sealed calls go only to the targets fixed by `restrictTo`, such as the pool,
/// and submissions open once those are set. General programs, and removing the
/// cancellation option above, need execution right after key release, as
/// LUCID provides at the protocol level.
contract SealedInbox {
    enum State {
        None,
        Sealed,
        Revealed,
        Executed,
        Missed,
        Forced,
        Malformed
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

    struct Config {
        uint256 deposit;
        uint256 bounty;
        uint256 bond;
        uint64 revealWindow;
        uint32 maxTicketGas;
        uint64 slotGasBudget;
        uint32 maxEnvelope;
        uint64 minWork;
        uint64 maxWork;
        uint32 maxChains;
        uint8 minLinkBytes;
        uint32 maxOpen;
    }

    uint256 public immutable deposit;
    uint64 public immutable revealWindow;
    uint256 public immutable bounty;
    uint256 public immutable bond;
    uint32 public immutable maxTicketGas;
    uint64 public immutable slotGasBudget;
    uint32 public immutable maxEnvelope;
    /// Bounds on a puzzle's total steps n * m, its chains n and its link bytes b.
    uint64 public immutable minWork;
    uint64 public immutable maxWork;
    uint32 public immutable maxChains;
    uint8 public immutable minLinkBytes;
    uint32 public immutable maxOpen;
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
    /// Puzzles per sender whose keys are not yet public.
    mapping(address => uint256) public openPuzzles;
    /// Bonds owed to senders, paid by `withdraw`.
    mapping(address => uint256) public credit;

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
    event Executed(uint256 indexed id, bool ok);
    event Missed(uint256 indexed id);
    event Forced(uint256 indexed id, address solver, bytes32 key);
    event Malformed(uint256 indexed id);
    event Withdrawn(address indexed to, uint256 amount);

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
    error NotRestricted();
    error OutOfLimits();
    error TooManyOpen();

    constructor(Config memory c) {
        require(c.bounty <= c.deposit, "bounty exceeds deposit");
        require(c.minWork <= c.maxWork, "empty work range");
        admin = msg.sender;
        bounty = c.bounty;
        bond = c.bond;
        maxTicketGas = c.maxTicketGas;
        slotGasBudget = c.slotGasBudget;
        maxEnvelope = c.maxEnvelope;
        deposit = c.deposit;
        revealWindow = c.revealWindow;
        minWork = c.minWork;
        maxWork = c.maxWork;
        maxChains = c.maxChains;
        minLinkBytes = c.minLinkBytes;
        maxOpen = c.maxOpen;
        account = address(new SealedAccount(address(this)));
        delegation = keccak256(abi.encodePacked(hex"ef0100", account));
    }

    /// Limit sealed calls to `targets`, once; submissions are refused until then.
    /// A call to any other target fails.
    function restrictTo(address[] calldata targets) external {
        require(msg.sender == admin && !restricted, "admin, once");
        restricted = true;
        for (uint256 i = 0; i < targets.length; i++) {
            allowedTarget[targets[i]] = true;
        }
    }

    function submit(bytes calldata envelope, uint32 gasLimit) external payable returns (uint256 id) {
        if (!restricted) revert NotRestricted();
        if (msg.value != deposit + bond) revert BadDeposit();
        if (envelope.length > maxEnvelope) revert EnvelopeTooLarge();
        if (gasLimit > maxTicketGas) revert GasTooHigh();
        if (msg.sender.codehash != delegation) revert NotDelegated();
        bytes memory env = envelope;
        LeanSeal.validate(env);
        (uint256 n, uint256 m, uint256 b) = LeanSeal.params(env, 8);
        if (n * m < minWork || n * m > maxWork || n > maxChains || b < minLinkBytes) revert OutOfLimits();
        if (openPuzzles[msg.sender] >= maxOpen) revert TooManyOpen();
        openPuzzles[msg.sender]++;
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
    /// key may do this; the deposit goes back to the sender. The bond is
    /// settled when the ticket executes, since the envelope is checked then.
    function reveal(uint256 id, bytes32 key) external {
        Ticket storage t = tickets[id];
        if (t.state != State.Sealed) revert WrongState();
        if (block.number <= t.slot || block.number > t.slot + revealWindow) revert OutsideWindow();
        if (LeanSeal.commitment(t.context, key) != t.commitment) revert WrongKey();
        t.key = key;
        t.state = State.Revealed;
        openPuzzles[t.sender]--;
        emit Revealed(id, key);
        _pay(t.sender, deposit);
    }

    /// Process a prefix of the head slot. Envelopes start at cursor; unrevealed
    /// tickets may use empty bytes and are marked missed. Revealed tickets run in
    /// queue order. Stop before a ticket whose gas cannot be delivered in full,
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
                t.state = State.Executed;
                (bool ok, bool wellFormed) = _run(t, envelopes[processed]);
                if (wellFormed) {
                    credit[t.sender] += bond;
                    emit Executed(id, ok);
                } else {
                    t.state = State.Malformed;
                    burned += bond;
                    emit Malformed(id);
                }
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

    /// Publish a missed ticket's key, solved from its puzzle, with its
    /// envelope. The ticket does not run. The caller receives only bounty;
    /// deposit - bounty remains locked forever, including when the sender
    /// claims. The bond is credited back if the envelope's tag verifies under
    /// the key and burned if it fails.
    function forceOpen(uint256 id, bytes32 key, bytes calldata envelope) external {
        Ticket storage t = tickets[id];
        if (t.state != State.Missed) revert WrongState();
        if (LeanSeal.commitment(t.context, key) != t.commitment) revert WrongKey();
        if (keccak256(envelope) != t.envelopeHash) revert WrongEnvelope();
        t.key = key;
        openPuzzles[t.sender]--;
        emit Forced(id, msg.sender, key);
        if (LeanSeal.tagValid(envelope, key)) {
            t.state = State.Forced;
            credit[t.sender] += bond;
        } else {
            t.state = State.Malformed;
            burned += bond;
            emit Malformed(id);
        }
        _pay(msg.sender, bounty);
    }

    /// Pay out the caller's credited bonds.
    function withdraw() external {
        uint256 amount = credit[msg.sender];
        credit[msg.sender] = 0;
        emit Withdrawn(msg.sender, amount);
        _pay(msg.sender, amount);
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

    /// Check the tag of one ticket, then decrypt and run it. `wellFormed` is
    /// false if the tag fails under the revealed key, and then the ticket does
    /// not run. `ok` is false if the sender no longer delegates to the
    /// canonical account, or the plaintext does not decode, has expired or
    /// reverts. The tag is checked outside the try, so a caller cannot turn a
    /// failing tag into an ordinary failure by starving the inner call of gas.
    function _run(Ticket storage t, bytes calldata envelope) internal returns (bool ok, bool wellFormed) {
        if (keccak256(envelope) != t.envelopeHash) revert WrongEnvelope();
        if (!LeanSeal.tagValid(envelope, t.key)) return (false, false);
        wellFormed = true;
        address sender = t.sender;
        if (sender.codehash != delegation) return (false, true);
        address target;
        bytes memory data;
        uint64 expiry;
        try this.openEnvelope(envelope, t.key) returns (address a, bytes memory d, uint64 e) {
            (target, data, expiry) = (a, d, e);
        } catch {
            return (false, true);
        }
        if (block.number > expiry) return (false, true);
        if (!allowedTarget[target]) return (false, true);
        bytes memory input = abi.encodeCall(SealedAccount.run, (target, data));
        uint256 allowance = t.gasLimit;
        assembly {
            tstore(0, 1)
            ok := call(allowance, sender, 0, add(input, 32), mload(input), 0, 0)
            tstore(0, 0)
        }
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
