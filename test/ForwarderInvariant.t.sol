// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {Forwarder} from "../src/Forwarder.sol";
import {SampleRecipient} from "../src/SampleRecipient.sol";

/**
 * @dev Stateful handler that drives the forwarder with REAL EIP-712 signatures. Every action is
 *      constructed to be valid so the suite is meaningful under FOUNDRY_INVARIANT_FAIL_ON_REVERT=true
 *      (any revert would fail the run and expose a hollow invariant). Ghost counters mirror the
 *      expected on-chain nonce so the invariants can prove: nonces only increase, exactly once per
 *      executed request (no double execution), and no ETH is ever retained by the forwarder.
 */
contract Handler is Test {
    Forwarder internal immutable forwarder;
    SampleRecipient internal immutable recipient;

    uint256 internal constant N = 3;
    address[N] internal signers;
    uint256[N] internal keys;

    // ghost state
    mapping(address => uint256) public ghostNonce; // expected nonce per signer
    uint256 public totalExecuted;
    uint256 public totalValueDelivered;

    constructor(Forwarder forwarder_, SampleRecipient recipient_) {
        forwarder = forwarder_;
        recipient = recipient_;
        for (uint256 i; i < N; ++i) {
            (address a, uint256 k) = makeAddrAndKey(string(abi.encodePacked("signer", vm.toString(i))));
            signers[i] = a;
            keys[i] = k;
        }
    }

    function _sign(uint256 key, Forwarder.ForwardRequest memory req) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, forwarder.hashRequest(req));
        return abi.encodePacked(r, s, v);
    }

    function _build(uint256 idx, uint256 value, bytes memory data)
        internal
        view
        returns (Forwarder.ForwardRequest memory)
    {
        return Forwarder.ForwardRequest({
            from: signers[idx],
            to: address(recipient),
            value: value,
            gas: 300_000,
            nonce: forwarder.nonces(signers[idx]),
            deadline: uint48(block.timestamp + 1 days),
            data: data
        });
    }

    /// @dev Execute one always-valid request from a bounded signer with a bounded value.
    function execute(uint256 actorSeed, uint256 valueSeed) external {
        uint256 idx = bound(actorSeed, 0, N - 1); // hi = N-1 >= lo = 0
        uint256 value = bound(valueSeed, 0, 5 ether); // hi >= lo
        bytes memory data = abi.encodeCall(SampleRecipient.ping, ("inv"));

        Forwarder.ForwardRequest memory req = _build(idx, value, data);
        bytes memory sig = _sign(keys[idx], req);

        vm.deal(address(this), value);
        forwarder.execute{value: value}(req, sig);

        ghostNonce[signers[idx]] += 1;
        totalExecuted += 1;
        totalValueDelivered += value;
    }

    /// @dev Execute a bounded batch of always-valid requests (distinct signers to keep nonces valid).
    function batch(uint256 seed, uint256 sizeSeed, uint256 valueSeed) external {
        uint256 size = bound(sizeSeed, 1, N); // 1..N, hi >= lo
        uint256 start = bound(seed, 0, N - 1);

        Forwarder.ForwardRequest[] memory reqs = new Forwarder.ForwardRequest[](size);
        bytes[] memory sigs = new bytes[](size);
        uint256 totalValue;
        bool[N] memory used;

        uint256 count;
        for (uint256 j; j < size; ++j) {
            uint256 idx = (start + j) % N;
            if (used[idx]) continue; // one request per signer per batch (keeps nonces sequential-valid)
            used[idx] = true;
            uint256 value = bound(uint256(keccak256(abi.encode(valueSeed, j))), 0, 2 ether); // hi >= lo
            reqs[count] = _build(idx, value, abi.encodeCall(SampleRecipient.ping, ("batch")));
            sigs[count] = _sign(keys[idx], reqs[count]);
            totalValue += value;
            count += 1;
        }

        // shrink arrays to the actually-populated entries
        assembly {
            mstore(reqs, count)
            mstore(sigs, count)
        }
        if (count == 0) return;

        vm.deal(address(this), totalValue);
        forwarder.batchExecute{value: totalValue}(reqs, sigs, payable(address(0xB0B)));

        for (uint256 j; j < count; ++j) {
            ghostNonce[reqs[j].from] += 1;
            totalExecuted += 1;
            totalValueDelivered += reqs[j].value;
        }
    }

    function signerAt(uint256 i) external view returns (address) {
        return signers[i % N];
    }

    function signerCount() external pure returns (uint256) {
        return N;
    }
}

contract ForwarderInvariantTest is Test {
    Forwarder internal forwarder;
    SampleRecipient internal recipient;
    Handler internal handler;

    function setUp() public {
        forwarder = new Forwarder("Forwarder");
        recipient = new SampleRecipient(address(forwarder));
        handler = new Handler(forwarder, recipient);
        targetContract(address(handler));
    }

    /// @dev The forwarder must never retain native token.
    function invariant_forwarderHoldsNoEth() public view {
        assertEq(address(forwarder).balance, 0);
    }

    /// @dev On-chain nonce for every signer equals the ghost count of its executed requests.
    ///      This simultaneously proves nonces never decrease and that no request executed twice.
    function invariant_noncesMatchGhost() public view {
        for (uint256 i; i < handler.signerCount(); ++i) {
            address s = handler.signerAt(i);
            assertEq(forwarder.nonces(s), handler.ghostNonce(s), "nonce must equal ghost count");
        }
    }

    /// @dev The sum of all on-chain nonces equals the total number of executed requests. A double
    ///      execution or a skipped nonce would break this pinned identity.
    function invariant_totalExecutionsPinned() public view {
        uint256 sum;
        for (uint256 i; i < handler.signerCount(); ++i) {
            sum += forwarder.nonces(handler.signerAt(i));
        }
        assertEq(sum, handler.totalExecuted(), "sum(nonces) == totalExecuted");
    }

    /// @dev All delivered value ended up at the recipient, never stranded in the forwarder.
    function invariant_valueConserved() public view {
        assertEq(address(recipient).balance, handler.totalValueDelivered());
        assertEq(address(forwarder).balance, 0);
    }
}
