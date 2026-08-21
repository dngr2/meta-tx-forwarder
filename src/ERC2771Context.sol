// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Context} from "@openzeppelin/contracts/utils/Context.sol";

/**
 * @title ERC2771Context
 * @notice Minimal ERC-2771 context. A contract inheriting this trusts exactly one forwarder; when
 *         that forwarder calls it, the last 20 bytes of calldata are interpreted as the real sender.
 *
 * @dev SECURITY: appending the sender is only safe because the recipient trusts this specific
 *      forwarder. Any call from a non-trusted address ignores the suffix and falls back to the
 *      normal `msg.sender`. Do not use with contracts that depend on a fixed calldata length.
 */
abstract contract ERC2771Context is Context {
    address private immutable _trustedForwarder;

    constructor(address trustedForwarder_) {
        _trustedForwarder = trustedForwarder_;
    }

    /// @notice The single forwarder this contract trusts to relay meta-transactions.
    function trustedForwarder() public view virtual returns (address) {
        return _trustedForwarder;
    }

    /// @notice Whether `forwarder` is the trusted forwarder.
    function isTrustedForwarder(address forwarder) public view virtual returns (bool) {
        return forwarder == _trustedForwarder;
    }

    /// @dev Real sender: the appended 20 bytes when called by the trusted forwarder, else msg.sender.
    function _msgSender() internal view virtual override returns (address) {
        uint256 len = msg.data.length;
        if (isTrustedForwarder(msg.sender) && len >= _contextSuffixLength()) {
            return address(bytes20(msg.data[len - _contextSuffixLength():]));
        }
        return super._msgSender();
    }

    /// @dev Real calldata: strips the appended sender when called by the trusted forwarder.
    function _msgData() internal view virtual override returns (bytes calldata) {
        uint256 len = msg.data.length;
        if (isTrustedForwarder(msg.sender) && len >= _contextSuffixLength()) {
            return msg.data[:len - _contextSuffixLength()];
        }
        return super._msgData();
    }

    /// @dev ERC-2771 context suffix is a single 20-byte address.
    function _contextSuffixLength() internal view virtual override returns (uint256) {
        return 20;
    }
}
