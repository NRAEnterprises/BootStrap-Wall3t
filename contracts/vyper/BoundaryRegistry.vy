# @version ^0.4.0

DOMAIN: constant(bytes32) = keccak256("BOOTSTRAP_WALL3T_BOUNDARY_V1")
PROTOCOL_VERSION: constant(uint64) = 1

@external
@view
def domain() -> bytes32:
    return DOMAIN

@external
@view
def validate_version(expected: uint64, current: uint64) -> bool:
    return expected == current
