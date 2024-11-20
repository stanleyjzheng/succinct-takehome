// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

/// @title Fibonacci.
/// @author Succinct Labs
/// @notice This contract implements a simple example of verifying the proof of a computing a
///         fibonacci number.
contract SP1AggregationVerifier {
    /// @notice The address of the SP1 verifier contract.
    /// @dev This can either be a specific SP1Verifier for a specific version, or the
    ///      SP1VerifierGateway which can be used to verify proofs for any version of SP1.
    ///      For the list of supported verifiers on each chain, see:
    ///      https://github.com/succinctlabs/sp1-contracts/tree/main/contracts/deployments
    address public verifier;

    /// @notice The verification key for the fibonacci program.
    bytes32 public aggregatorProgamVKey;

    /// @notice `true` if a valid merkle root has had their proofs verified.
    mapping(bytes32 => bool) public verifiedMerkleRoots;

    constructor(address _verifier, bytes32 _aggregatorProgamVKey) {
        verifier = _verifier;
        aggregatorProgamVKey = _aggregatorProgamVKey;
    }

    function verifyAndStoreAggregatedProof(
        bytes calldata _publicValues,
        bytes calldata _proofBytes
    ) external {
        ISP1Verifier(verifier).verifyProof(
            aggregatorProgamVKey,
            _publicValues,
            _proofBytes
        );
        bytes32 merkleRoot = abi.decode(_publicValues, (bytes32));
        verifiedMerkleRoots[merkleRoot] = true;
    }

    function verifyFibonacciProof(
        bytes32 _programVKey,
        bytes calldata _publicValues,
        bytes32 merkleRoot,
        bytes32[] memory proof
    ) public view {
        // verify merkle
        require(verifiedMerkleRoots[merkleRoot], "Merkle root not verified");
    }
}
