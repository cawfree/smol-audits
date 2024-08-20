// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.0;

/// @custom:hunter Would probably use a single interface to normalize
/// @custom:hunter interface checks. How often are these different?

interface IBeforeTransaction {
    function checkBeforeTransaction(
        address target,
        bytes4 selector,
        uint8 operation,
        uint256 value,
        bytes calldata data
    ) external; /// @custom:hunter May silently fail? Expected to always revert?
}

interface IAfterTransaction {
    function checkAfterTransaction(
        address target,
        bytes4 selector,
        uint8 operation,
        uint256 value,
        bytes calldata data,
        bytes calldata returnData
    ) external;
}
