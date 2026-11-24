// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @notice Stateless protocol boundary; it stores no keys and moves no funds.
contract BoundaryRegistry {
    bytes32 public constant DOMAIN = keccak256("BOOTSTRAP_WALL3T_BOUNDARY_V1");
    uint64 public constant PROTOCOL_VERSION = 1;

    function validateVersion(uint64 expected, uint64 current) external pure returns (bool) {
        return expected == current;
    }
}
