// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "@src/interfaces/IHookRegistry.sol";
import "@src/libs/Errors.sol";
import {HookLib} from "./Hooks.sol";
import {HookConfig, Hooks} from "./Structs.sol";

contract HookRegistry is IHookRegistry {
    using HookLib for HookConfig;

    /// @custom:hunter `GnosisSafeProxy` implementation: https://arbiscan.io/address/0x3e5c63644e683549055b9be8653de26e0b4cd36e#code
    address public immutable override fund;

    /// keccak256(abi.encode(operator, target, operation, selector)) => hooks
    /// bytes20 + bytes20 + bytes8 + bytes4 = 52 bytes /// @custom:hunter Outdated, bytes20 + bytes20 + bytes1 /// @custom:hunter What used to be here?
    mapping(bytes32 hookPointer => Hooks) private hooks;

    modifier onlyFund() {
        if (msg.sender != fund) {
            revert Errors.OnlyFund();
        }
        _;
    }

    constructor(address _fund) { /// @custom:hunter Doesn't verify this is a `Safe`; `checkConfigIsValid(address)` expects to be able to invoke `isOwner(address)`.
        fund = _fund;
    }

    /// @custom:hunter May return an uninitialized (default) hook (defined => false).
    function getHooks(address operator, address target, uint8 operation, bytes4 selector)
        external
        view
        returns (Hooks memory)
    {
        return hooks[HookLib.hookPointer(operator, target, operation, selector)];
    }

    /// @custom:hunter Only the fund address can call this, but not the Fund owners.
    /// @custom:hunter Therefore a malicious operator could drain gas to prevent
    /// @custom:hunter their hook from being overwritten - consider using a permit.
    function setHooks(HookConfig calldata config) external onlyFund {
        /// @custom:hunter Cannot target address(this).
        config.checkConfigIsValid(fund);

        bytes32 pointer = config.pointer();

        /// @custom:hunter Hooks can be overwritten without explicitly
        /// @custom:hunter unsetting. Might not be able to handle a
        /// @custom:hunter specific hook differently depending upon
        /// @custom:hunter the context. Should throw.
        hooks[pointer] = Hooks({
            beforeTrxHook: config.beforeTrxHook,
            afterTrxHook: config.afterTrxHook,
            defined: true // TODO: change to status code, same cost but more descriptive
        });

        emit HookSet(
            config.operator,
            config.target,
            config.operation,
            config.targetSelector,
            config.beforeTrxHook,
            config.afterTrxHook
        );
    }

    /// @custom:hunter Only the fund address can call this, but not the Fund owners.
    /// @custom:hunter Therefore a malicious operator could drain gas to prevent
    /// @custom:hunter their hook from being overwritten - consider using a permit.
    function removeHooks(HookConfig calldata config) external onlyFund {
        delete hooks[config.pointer()];

        emit HookRemoved(config.operator, config.target, config.operation, config.targetSelector);
    }
}
