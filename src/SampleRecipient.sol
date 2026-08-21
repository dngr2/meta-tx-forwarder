// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ERC2771Context} from "./ERC2771Context.sol";

/**
 * @title SampleRecipient
 * @notice An ERC-2771 aware recipient used to prove the forwarder delivers the real user address.
 *         `ping` records `_msgSender()`, which equals the request's `from` when relayed through the
 *         trusted forwarder, and the actual `msg.sender` for direct (non-forwarded) calls.
 */
contract SampleRecipient is ERC2771Context {
    address public lastSender;
    bytes public lastData;
    uint256 public lastValue;
    uint256 public pingCount;

    event Pinged(address indexed sender, uint256 value, uint256 count, bytes data);

    error Boom();

    constructor(address forwarder) ERC2771Context(forwarder) {}

    /// @notice Records and returns the effective sender as seen through ERC-2771 context.
    function ping(bytes calldata payload) external payable returns (address sender) {
        sender = _msgSender();
        lastSender = sender;
        lastValue = msg.value;
        lastData = payload;
        pingCount += 1;
        emit Pinged(sender, msg.value, pingCount, _msgData());
    }

    /// @notice Always reverts; used to exercise inner-call-revert handling in the forwarder.
    function boom() external payable {
        revert Boom();
    }
}
