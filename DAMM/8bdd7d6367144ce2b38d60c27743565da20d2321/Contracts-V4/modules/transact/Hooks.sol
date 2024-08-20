// SPDX-License-Identifier: UNLICENSED
/// @custom:hunter `mstore8` does not work on Arbitrum: https://github.com/Brechtpd/base64/issues/3 Detected presence of this opcode.
pragma solidity ^0.8.0;

import "@src/libs/Errors.sol";
import "./Structs.sol";

// cast sig "isOwner(address)" /// @custom:hunter Gnosis safe `Ownable` view function.
bytes4 constant IS_OWNER_SAFE_SELECTOR = 0x2f54bf6e;

library HookLib {
    function pointer(HookConfig memory config) internal pure returns (bytes32) {
        return hookPointer(config.operator, config.target, config.operation, config.targetSelector);
    }

    /// @custom:hunter Reverts if the config does not satisfy checks.
    /// @custom:hunter Owners allow the operators to act on their behalf, but operators should not be able to act as owners.
    function checkConfigIsValid(HookConfig memory config, address fund) internal view {

        /// @custom:hunter Should probably do an ERC-165 interface check.

        /// basic operator sanity checks
        if (
            config.operator == address(0) || config.operator == fund
                || config.operator == address(this)
        ) {
            revert Errors.Hook_InvalidOperator();
        }

        (bool success, bytes memory returnData) =
            fund.staticcall(abi.encodeWithSelector(IS_OWNER_SAFE_SELECTOR, config.operator)); /// @custom:hunter `SENTINEL_OWNERS` has some significance.

        /// @notice fund admin cannot be an operator
        if (!success || abi.decode(returnData, (bool))) {
            revert Errors.Hook_InvalidOperator();
        }

        /// basic target sanity checks
        if (config.target == address(0) || config.target == address(this)) { /// @custom:hunter Can target plenty of other trusted contracts within DAMM. Can't add other hooks though.
            revert Errors.Hook_InvalidTargetAddress();
        }

        /// @custom:hunter It is possible to specify other hooks. For example, a
        /// @custom:hunter "trusted" hook can be upgraded, or we can reference
        /// @custom:hunter a contract which does not expose the required life cycle.
        /// @custom:hunter Would honestly consider implementing EIP-165 and
        /// @custom:hunter interrogate the interface.

        /// basic beforeTrxHook sanity checks
        if (config.beforeTrxHook == address(this) || config.beforeTrxHook == config.operator) { /// @custom:hunter Any other trusted DAMM contract.
            revert Errors.Hook_InvalidBeforeHookAddress();
        }

        /// basic afterTrxHook sanity checks
        if (config.afterTrxHook == address(this) || config.afterTrxHook == config.operator) { /// @custom:hunter Any other trusted DAMM contract.
            revert Errors.Hook_InvalidAfterHookAddress();
        }

        // only 0 or 1 allowed (0 = call, 1 = delegatecall)
        if (config.operation != 0 && config.operation != 1) { /// @custom:hunter Gas optimization: if (config.operation > 1)
            revert Errors.Hook_InvalidOperation();
        }
    }

    function hookPointer(address operator, address target, uint8 operation, bytes4 selector)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(operator, target, operation, selector));
    }
}
