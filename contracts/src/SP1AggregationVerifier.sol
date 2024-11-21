// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/// @title SP1 Aggregation Verifier with Merkle Proof Verification using OpenZeppelin Library.
/// @notice This contract verifies the aggregated proof using SP1 and validates individual
///         proofs against an aggregated Merkle root using OpenZeppelin's MerkleProof library.
contract SP1AggregationVerifier {
    /// @notice The address of the SP1 verifier contract.
    /// @dev This can either be a specific SP1Verifier for a specific version, or the
    ///      SP1VerifierGateway which can be used to verify proofs for any version of SP1.
    ///      For the list of supported verifiers on each chain, see:
    ///      https://github.com/succinctlabs/sp1-contracts/tree/main/contracts/deployments
    address public verifier;

    /// @notice The verification key for the proof aggregator program.
    bytes32 public aggregatorProgamVKey;

    /// @notice `true` if a valid Merkle root has had its proofs verified.
    mapping(bytes32 => bool) public verifiedMerkleRoots;

    constructor(address _verifier, bytes32 _aggregatorProgamVKey) {
        verifier = _verifier;
        aggregatorProgamVKey = _aggregatorProgamVKey;
    }

    /// @notice Verifies and stores an aggregated proof.
    /// @param _publicValues Thepublic inputs to the SP1 proof, which include the Merkle root.
    /// @param _proofBytes The proof bytes returned by the prover.
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

    function getLeafHash (bytes32 _programVKey, bytes calldata _publicValues) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_programVKey, _publicValues));
    }

    /// @notice Verifies an individual Fibonacci proof against the aggregated Merkle root.
    /// @param _programVKey The verification key for the individual proof.
    /// @param _publicValues The public inputs to the individual SP1 proof.
    /// @param merkleRoot The Merkle root of the aggregated proofs.
    /// @param proof The Merkle proof for this leaf.
    function verifySingleProof(
        bytes32 _programVKey,
        bytes calldata _publicValues,
        bytes32 merkleRoot,
        bytes32[] memory proof
    ) public view returns (bool) {
        require(verifiedMerkleRoots[merkleRoot], "Merkle root not verified");

        bytes32 leafHash = getLeafHash(_programVKey, _publicValues);

        // Verify the Merkle proof using OpenZeppelin's MerkleProof library
        bool isValid = MerkleProof.verify(proof, merkleRoot, leafHash);
        require(isValid, "Invalid Merkle proof");
        return isValid;
    }
}
