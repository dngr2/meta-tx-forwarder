// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/**
 * @title Forwarder
 * @notice ERC-2771 compatible meta-transaction forwarder. A relayer submits EIP-712 signed
 *         {ForwardRequest}s so that end users can transact without holding native gas token.
 *         The real user address is appended to the calldata of the forwarded call; an ERC-2771
 *         aware recipient recovers it via `_msgSender()`.
 *
 * @dev Design notes / decisions (documented in README):
 *  - `execute` reverts the whole transaction if the inner call fails (bubble-as-revert). This keeps
 *    the single-request path all-or-nothing and guarantees no value is stranded.
 *  - `batchExecute` is non-atomic when a non-zero `refundReceiver` is supplied: invalid or reverting
 *    requests are skipped and their `value` is refunded, so a single bad request cannot grief a batch.
 *    Passing `refundReceiver == address(0)` opts into atomic execution (any failure reverts the batch).
 *  - The nonce is consumed BEFORE the external call (checks-effects-interactions), so a reentrant
 *    recipient cannot replay a request.
 *  - A 63/64 gas assertion after the call defends against insufficient-gas griefing by a relayer.
 *  - The forwarder trusts nothing about the target: appending `from` is only *safe* because the
 *    recipient chooses to trust exactly this forwarder (the ERC-2771 trust model). A recipient that
 *    does not trust this forwarder simply ignores the appended bytes.
 */
contract Forwarder is EIP712 {
    struct ForwardRequest {
        address from;
        address to;
        uint256 value;
        uint256 gas;
        uint256 nonce;
        uint48 deadline;
        bytes data;
    }

    bytes32 private constant _FORWARD_REQUEST_TYPEHASH = keccak256(
        "ForwardRequest(address from,address to,uint256 value,uint256 gas,uint256 nonce,uint48 deadline,bytes data)"
    );

    mapping(address => uint256) private _nonces;

    event Executed(address indexed from, address indexed to, uint256 nonce, bool success);

    error InvalidSigner(address from);
    error InvalidNonce(address from, uint256 expected, uint256 provided);
    error ExpiredRequest(uint48 deadline);
    error MismatchedValue(uint256 requested, uint256 provided);
    error MismatchedArrayLengths();
    error FailedInnerCall();
    error RefundFailed();

    constructor(string memory name) EIP712(name, "1") {}

    // --------------------------------------------------------------------- //
    //                                 Views                                 //
    // --------------------------------------------------------------------- //

    /// @notice Current nonce for `owner`; the next valid request from `owner` must carry this value.
    function nonces(address owner) public view returns (uint256) {
        return _nonces[owner];
    }

    /// @notice EIP-712 domain separator for this forwarder.
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @notice EIP-712 struct hash (unhashed with the domain) of a request.
    function structHash(ForwardRequest calldata req) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                _FORWARD_REQUEST_TYPEHASH,
                req.from,
                req.to,
                req.value,
                req.gas,
                req.nonce,
                req.deadline,
                keccak256(req.data)
            )
        );
    }

    /// @notice Full EIP-712 typed-data digest a signer must sign for `req`.
    function hashRequest(ForwardRequest calldata req) public view returns (bytes32) {
        return _hashTypedDataV4(structHash(req));
    }

    /// @notice Returns true if `signature` is a currently-executable authorization of `req`.
    /// @dev Valid means: not expired, nonce matches the current on-chain nonce, and the signature
    ///      recovers to / is validated by `req.from` (EOA via ECDSA or contract wallet via ERC-1271).
    function verify(ForwardRequest calldata req, bytes calldata signature) public view returns (bool) {
        return _validate(req, signature);
    }

    // --------------------------------------------------------------------- //
    //                               Execution                               //
    // --------------------------------------------------------------------- //

    /// @notice Execute a single signed request. Reverts if invalid or if the inner call reverts.
    function execute(ForwardRequest calldata req, bytes calldata signature) public payable {
        if (msg.value != req.value) revert MismatchedValue(req.value, msg.value);
        if (req.deadline < block.timestamp) revert ExpiredRequest(req.deadline);

        uint256 expected = _nonces[req.from];
        if (req.nonce != expected) revert InvalidNonce(req.from, expected, req.nonce);

        if (!SignatureChecker.isValidSignatureNow(req.from, hashRequest(req), signature)) {
            revert InvalidSigner(req.from);
        }

        // Effects before interaction: consume the nonce so reentrancy cannot replay this request.
        _nonces[req.from] = expected + 1;

        (bool success, uint256 gasLeft) = _call(req);
        _checkForwardedGas(gasLeft, req.gas);

        emit Executed(req.from, req.to, expected, success);
        if (!success) revert FailedInnerCall();
    }

    /**
     * @notice Execute many signed requests in one transaction.
     * @param reqs           the requests, aligned 1:1 with `sigs`.
     * @param sigs           signatures for each request.
     * @param refundReceiver where unspent `value` (from skipped / reverted requests) is refunded.
     *                       If `address(0)`, the batch is atomic: any invalid or reverting request
     *                       reverts the whole batch.
     * @dev `msg.value` must equal the sum of `reqs[i].value`. No native token is ever retained by
     *      the forwarder: value is either consumed by a successful call or refunded.
     */
    function batchExecute(ForwardRequest[] calldata reqs, bytes[] calldata sigs, address payable refundReceiver)
        public
        payable
    {
        if (reqs.length != sigs.length) revert MismatchedArrayLengths();
        bool atomic = refundReceiver == address(0);

        uint256 requestsValue;
        uint256 refundValue;

        for (uint256 i; i < reqs.length; ++i) {
            requestsValue += reqs[i].value;
            bool consumed = _tryExecute(reqs[i], sigs[i], atomic);
            if (!consumed) refundValue += reqs[i].value;
        }

        // Reject a mismatched total up front to prevent value tampering and stranded ETH.
        if (requestsValue != msg.value) revert MismatchedValue(requestsValue, msg.value);

        if (refundValue != 0) {
            // atomic == false here (an atomic batch would have reverted), so refundReceiver != 0.
            (bool ok,) = refundReceiver.call{value: refundValue}("");
            if (!ok) revert RefundFailed();
        }
    }

    // --------------------------------------------------------------------- //
    //                               Internals                               //
    // --------------------------------------------------------------------- //

    function _validate(ForwardRequest calldata req, bytes calldata signature) internal view returns (bool) {
        if (req.deadline < block.timestamp) return false;
        if (req.nonce != _nonces[req.from]) return false;
        return SignatureChecker.isValidSignatureNow(req.from, hashRequest(req), signature);
    }

    /// @dev Validates then runs a request inside a batch. Returns whether `req.value` was consumed by
    ///      a successful inner call (false => the caller should refund that value).
    function _tryExecute(ForwardRequest calldata req, bytes calldata sig, bool atomic) private returns (bool) {
        if (!_validate(req, sig)) {
            if (atomic) {
                // Surface a precise reason for the atomic (all-or-nothing) path.
                if (req.deadline < block.timestamp) revert ExpiredRequest(req.deadline);
                uint256 expected = _nonces[req.from];
                if (req.nonce != expected) revert InvalidNonce(req.from, expected, req.nonce);
                revert InvalidSigner(req.from);
            }
            return false; // skip & refund
        }

        // Effects before interaction (CEI): consume the nonce first.
        _nonces[req.from] = req.nonce + 1;

        (bool success, uint256 gasLeft) = _call(req);
        _checkForwardedGas(gasLeft, req.gas);

        emit Executed(req.from, req.to, req.nonce, success);
        if (atomic && !success) revert FailedInnerCall();
        return success; // if the call reverted (non-atomic), value returned to us -> refund
    }

    /// @dev Performs the forwarded call, appending `req.from` (20 bytes) so an ERC-2771 recipient can
    ///      recover the real sender. Captures gasleft() immediately after the call for the 63/64 check.
    function _call(ForwardRequest calldata req) private returns (bool success, uint256 gasLeft) {
        bytes memory payload = abi.encodePacked(req.data, req.from);
        address to = req.to;
        uint256 value = req.value;
        uint256 reqGas = req.gas;
        /// @solidity memory-safe-assembly
        assembly {
            success := call(reqGas, to, value, add(payload, 0x20), mload(payload), 0, 0)
            gasLeft := gas()
        }
    }

    /**
     * @dev Insufficient-gas griefing defense. By EIP-150 a CALL forwards at most 63/64 of the gas
     *      available at the call site and retains at least 1/64. If a relayer supplies just too little
     *      gas, the inner call can run out while the outer forwarding still "succeeds". Measuring
     *      gasleft() right after the call lets us detect that: if the inner call ran out of gas we would
     *      observe `gasLeft < req.gas / 63`. In that case we consume all remaining gas with INVALID so
     *      the relayer cannot profit from the griefing and the meta-tx does not falsely succeed.
     */
    function _checkForwardedGas(uint256 gasLeft, uint256 reqGas) private pure {
        if (gasLeft < reqGas / 63) {
            /// @solidity memory-safe-assembly
            assembly {
                invalid()
            }
        }
    }
}
