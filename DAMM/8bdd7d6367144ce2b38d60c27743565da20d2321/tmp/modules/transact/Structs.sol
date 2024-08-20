// SPDX-License-Identifier: UNLICENSED
/// @custom:hunter Floating pragma, select a locked version. Looks like we're compiling using 0.8.23. `PUSH0` is now supported.
pragma solidity ^0.8.0;

struct Transaction {
    uint256 value;
    address target;
    uint8 operation;
    bytes4 targetSelector;
    bytes data;
}

struct Hooks {
    address beforeTrxHook; /// @custom:hunter `beforeTrxHook` and `afterTrxHook` may be the same address. What's the interface?
    address afterTrxHook;
    bool defined;
}


/// @custom:hunter HookConfig does not enforce maximum value checks.
/// @custom:hunter We are basically saying operators can only do very
/// @custom:hunter specific things, but they are free to use `msg.value`
/// @custom:hunter however they see fit. How much trust do we give to
/// @custom:hunter operators?
struct HookConfig {
    address operator;
    address target;
    address beforeTrxHook;
    address afterTrxHook;
    uint8 operation;
    bytes4 targetSelector;
}
