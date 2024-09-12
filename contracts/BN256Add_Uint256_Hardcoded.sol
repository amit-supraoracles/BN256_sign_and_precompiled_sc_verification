// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract BN256Addition {
    function callBn256Add() public view returns (bytes32[2] memory result) {
        // Hardcoded values for ax, ay, bx, and by
        bytes32 ax = bytes32(uint256(1877680754511875309899085821046020641041516699522550968201931210511122361188));
        bytes32 ay = bytes32(uint256(1879687745237862349771417085220368195630510774060410176566704734657946401647));
        bytes32 bx = bytes32(uint256(10177664824327229270631241062558466194853353905576267792570130720130119743401));
        bytes32 by = bytes32(uint256(2617838070911723228053200997531205923494421078683439118196637157934995837361));

        // Create input bytes array (64 bytes total)
        bytes memory input = new bytes(64);
        assembly {
            mstore(add(input, 0x20), ax)
            mstore(add(input, 0x40), ay)
            mstore(add(input, 0x60), bx)
            mstore(add(input, 0x80), by)
        }

        bytes memory output = new bytes(64); // Allocate 64 bytes for the output

        assembly {
            // Use staticcall to ensure no state modification
            let success := staticcall(
                gas(),            // Gas available for the call
                0x06,             // Address of the BN256 addition precompiled contract
                add(input, 0x20), // Pointer to the input data
                64,               // Length of the input data
                add(output, 0x20),// Pointer to the output buffer
                64                // Length of the output buffer
            )
            switch success
            case 0 {
                revert(0, 0) // Revert the transaction if the call fails
            }
        }

        // Extract results from the output bytes
        assembly {
            result := mload(add(output, 0x20))
            mstore(add(result, 0x20), mload(add(output, 0x40)))
        }
    }
}


// Public key Points source : https://github.com/amit-supraoracles/bn254_sign_verify/blob/master/contracts/BNPairingPrecompileCostEstimator.sol#L13
