// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal mock that mimics "top-down" emissions per subnet
///         and keeps a nonce per subnet to support exhaustiveness proofs.
contract TopdownMessenger {
    struct Subnet {
        uint256 topDownNonce;
    }

    // subnets[bytes32 subnetId] => Subnet info
    mapping(bytes32 => Subnet) public subnets;

    /// @dev Indexed bytes32 so it's topic1 and equals the raw value provided
    event NewTopDownMessage(bytes32 indexed subnetId, uint256 nonce);

    /// @notice Emit `num` messages for a subnet and bump its nonce accordingly.
    /// @param subnetId 32-byte subnet identifier (fits neatly into topic1)
    /// @param num number of events to emit
    function trigger(bytes32 subnetId, uint256 num) external {
        for (uint256 i = 0; i < num; i++) {
            // increment first, then emit the new value
            uint256 n = ++subnets[subnetId].topDownNonce;
            emit NewTopDownMessage(subnetId, n);
        }
    }

    /// @notice Helper view for convenience (same as subnets[subnetId].topDownNonce)
    function topDownNonce(bytes32 subnetId) external view returns (uint256) {
        return subnets[subnetId].topDownNonce;
    }
}
