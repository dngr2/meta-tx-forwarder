# meta-tx-forwarder

An ERC-2771 meta-transaction forwarder. A relayer submits EIP-712 signed requests so end users
transact without holding native gas token; recipient contracts recover the real sender through
ERC-2771 context.

- Solidity `0.8.26`, `via_ir`, EVM `cancun`, OpenZeppelin Contracts `v5.0.2` (vendored).
- 46 tests (42 unit + 4 stateful invariants), all green. Invariants proven non-hollow at
  **12,800 calls / 0 reverts** with `fail-on-revert = true` pinned inline.

## The ERC-2771 model

An end user signs an intent off-chain; a **relayer** pays the gas and submits it on-chain to the
`Forwarder`. The forwarder calls the target and **appends the user's address (20 bytes) to the
calldata**. An ERC-2771-aware recipient (`ERC2771Context`) reads those trailing bytes as the real
`_msgSender()` instead of the relayer.

```
user (signs)  ->  relayer (pays gas)  ->  Forwarder.execute(req, sig)
                                              |
                                              v
                          recipient.call(req.data ++ req.from)
                                              |
                                    _msgSender() == req.from
```

## EIP-712 request format

```solidity
struct ForwardRequest {
    address from;     // the user; must equal the signature's signer
    address to;       // target contract
    uint256 value;    // native token to attach (must equal msg.value)
    uint256 gas;      // gas limit forwarded to the inner call
    uint256 nonce;    // must equal nonces(from); consumed on execution
    uint48  deadline; // request expires after this timestamp
    bytes   data;     // calldata for the target
}
```

Type string:
`ForwardRequest(address from,address to,uint256 value,uint256 gas,uint256 nonce,uint48 deadline,bytes data)`

The signature is checked with `SignatureChecker.isValidSignatureNow`, so both **EOA (ECDSA)** and
**smart-contract wallets (ERC-1271)** are supported as `from`.

## Relayer flow

1. User builds a `ForwardRequest` with `nonce = forwarder.nonces(user)` and a future `deadline`.
2. User signs `forwarder.hashRequest(req)` (EIP-712 typed data).
3. Relayer optionally calls `verify(req, sig)` (view) to pre-check validity.
4. Relayer calls `execute(req, sig)` (or `batchExecute`), attaching `msg.value == req.value`.

## Security properties

**Trusted-forwarder trust boundary.** Appending `from` to calldata is only *safe* because the
recipient chooses to trust exactly one forwarder. `ERC2771Context._msgSender()` honors the appended
bytes **only** when `msg.sender` is that trusted forwarder; any other caller's suffix is ignored and
the normal `msg.sender` is used. The forwarder itself trusts nothing about the target — a recipient
that does not trust this forwarder simply sees the forwarder as the sender (tested in
`test_NonTrustingRecipientIgnoresAppendedSender`). Never point a recipient at a forwarder you do not
control: a malicious forwarder can spoof any sender for a recipient that trusts it.

**Nonce / replay protection.** `nonces(from)` increments by exactly one per executed request and is
consumed **before** the external call (checks-effects-interactions). Replaying a request, using an
out-of-order nonce, or reentering to reuse a nonce all fail with `InvalidNonce`. Two different `from`
addresses have independent nonce streams.

**63/64 gas-griefing defense.** Per EIP-150 a `CALL` forwards at most `63/64` of the available gas.
A malicious relayer could supply just too little gas so the inner call runs out while the outer
forwarding still "succeeds". Immediately after the call the forwarder asserts
`gasleft() >= req.gas / 63`; if not, it consumes all remaining gas via `INVALID` so a starved call
cannot be reported as success (tested in `test_GasGriefingDefenseReverts`).

**No native token retained.** `execute` requires `msg.value == req.value` and forwards it in the
call; if the call reverts, the whole transaction reverts, so nothing is stranded. `batchExecute`
requires `msg.value == sum(req.value)` and refunds the value of any skipped or reverted request to
`refundReceiver`, leaving the forwarder balance at zero. The `invariant_forwarderHoldsNoEth` and
`invariant_valueConserved` invariants hold this across 12,800 randomized calls.

## Design decisions

- **`execute` inner-call revert → bubble as revert.** A single request is all-or-nothing: if the
  target reverts, `execute` reverts with `FailedInnerCall` and the nonce increment is rolled back.
- **`batchExecute` refund semantics.** With a non-zero `refundReceiver` the batch is *non-atomic*:
  invalid requests (bad signature / wrong nonce / expired) are skipped and reverting inner calls are
  tolerated; the unused value of both is refunded so one bad request cannot grief the batch. Passing
  `refundReceiver == address(0)` opts into *atomic* execution — any invalid or reverting request
  reverts the whole batch. Either way `msg.value` must equal the sum of request values and no ETH is
  retained.

## Deep dive (v2)

A second adversarial pass hunted specifically for replay, sender-spoofing, and ETH-retention bugs.
**No exploitable bug was found — the forwarder holds.** The audit confirmed:

- **Replay / reentrancy.** The nonce is consumed before the external call (CEI); a reentrant
  recipient replaying the same request hits the nonce guard. A duplicate request inside one
  non-atomic batch executes exactly once (second copy skipped + refunded).
- **Sender-spoofing.** The signature binds `from`/`to`/`data`, so a relayer cannot forge a victim's
  request. A request whose `to` is the forwarder itself cannot spoof a sender — the forwarder is not
  an ERC-2771 recipient, so the appended `from` is inert.
- **Signature malleability.** OZ's `ECDSA` enforces low-`s`; the malleable counterpart
  (`s' = n - s`, `v` flipped) of a valid signature is rejected.
- **ETH retention / drain.** `msg.value == Σ request values` is enforced and every skipped/reverted
  request's value is refunded, so the forwarder retains nothing in normal operation. A reentrant
  `refundReceiver` cannot double-refund nor drain a *forced* (selfdestruct-pushed) balance: its
  nested `execute` is rejected by the value guard because each call can only move `msg.value` it
  itself funds. Forced ETH is stranded but never stealable.

New adversarial tests: `test_MalleableSignatureRejected`, `test_EoaTargetDeliversValue`,
`test_DuplicateRequestInBatchExecutesOnce`, `test_ReentrantRefundReceiverCannotDrain`,
`test_SelfCallCannotSpoofSender`, plus a `batchWithRefund` invariant action that drives the
skip/refund value path under `fail-on-revert = true`.

## Layout

| path | purpose |
| --- | --- |
| `src/Forwarder.sol` | EIP-712 forwarder: `execute`, `batchExecute`, `verify`, `nonces` |
| `src/ERC2771Context.sol` | minimal ERC-2771 context (trusted-forwarder sender recovery) |
| `src/SampleRecipient.sol` | recipient that records `_msgSender()` to prove real-sender delivery |
| `test/Forwarder.t.sol` | 42 unit tests (signatures, nonces, ERC-1271, value, gas, batch, v2 adversarial) |
| `test/ForwarderInvariant.t.sol` | stateful invariants driven by real signatures |
| `script/Deploy.s.sol` | deploys the forwarder + a wired sample recipient |

## Build & test

```bash
forge build --sizes          # Forwarder runtime ~3.9 KB, well under EIP-170
forge test                   # 46 passing
forge fmt --check
forge test --match-path test/ForwarderInvariant.t.sol   # fail-on-revert pinned inline
```
