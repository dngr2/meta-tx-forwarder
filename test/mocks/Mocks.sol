// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Forwarder} from "../../src/Forwarder.sol";

/// @dev Minimal ERC-1271 contract wallet: a signature is valid if it recovers to `owner`.
contract ERC1271Wallet {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    address public owner;

    constructor(address owner_) {
        owner = owner_;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
        if (err == ECDSA.RecoverError.NoError && recovered == owner) {
            return MAGIC;
        }
        return 0xffffffff;
    }
}

/// @dev Consumes all forwarded gas in an unbounded loop. Used to exercise the 63/64 gas defense.
contract GasBurner {
    uint256 public sink;

    function guzzle() external {
        uint256 i;
        while (true) {
            sink = i;
            unchecked {
                ++i;
            }
        }
    }
}

/// @dev Recipient that re-enters the forwarder trying to replay the same request.
contract ReentrantRecipient {
    Forwarder public immutable forwarder;
    Forwarder.ForwardRequest public stored;
    bytes public storedSig;
    bool public attempted;
    bool public reentryReverted;

    constructor(Forwarder forwarder_) {
        forwarder = forwarder_;
    }

    function arm(Forwarder.ForwardRequest calldata req, bytes calldata sig) external {
        stored = req;
        storedSig = sig;
    }

    /// @notice Called by the forwarder as the inner request; attempts to replay `stored`.
    function reenter() external payable {
        if (!attempted) {
            attempted = true;
            Forwarder.ForwardRequest memory r = stored;
            Forwarder.ForwardRequest memory req = Forwarder.ForwardRequest({
                from: r.from, to: r.to, value: r.value, gas: r.gas, nonce: r.nonce, deadline: r.deadline, data: r.data
            });
            try forwarder.execute(req, storedSig) {
                reentryReverted = false;
            } catch {
                reentryReverted = true;
            }
        }
    }
}
