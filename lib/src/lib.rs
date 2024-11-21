mod merkletree;

use alloy_dyn_abi::DynSolValue;
use alloy_primitives::{Bytes, B256};
use alloy_sol_types::{sol, SolValue};
use merkletree::{MerkleProof, MerkleTree};
use tiny_keccak::{Hasher, Keccak};

sol! {
    /// The proof pairs to be passed in with solidity.
    struct PublicValuesStruct {
        bytes32 programVKey;
        bytes publicValues;
    }
}

pub fn words_to_bytes_le(words: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..8 {
        let word_bytes = words[i].to_le_bytes();
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word_bytes);
    }
    bytes
}

fn keccak256<T: AsRef<[u8]>>(bytes: T) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes.as_ref());
    hasher.finalize(&mut output);
    output
}

fn hash_leaf(vkey: &[u32; 8], public_values: &[u8]) -> B256 {
    let vkey = B256::from_slice(&words_to_bytes_le(vkey));

    let leaf = DynSolValue::Tuple(vec![
        DynSolValue::FixedBytes(vkey, 32),
        DynSolValue::Bytes(public_values.to_vec()),
    ])
    .abi_encode_packed();

    B256::from(keccak256(leaf))
}

pub fn build_tree(vkeys: &[[u32; 8]], public_values: &[Vec<u8>]) -> MerkleTree {
    let mut tree = MerkleTree::new();

    for i in 0..vkeys.len() {
        let vkey = &vkeys[i];
        // Verify the proofs.
        let public_values = &public_values[i];

        // ABI encode the (vkey, committed_value) pair and add it to the merkle tree

        let hashed_leaf = hash_leaf(vkey, public_values);

        tree.insert(hashed_leaf);
    }

    tree.finish();
    tree
}

pub fn get_merkle_proof_for_value(
    vkey: &[u32; 8],
    public_values: &[u8],
    tree: &MerkleTree,
) -> Option<MerkleProof> {
    let hashed_leaf = hash_leaf(vkey, public_values);

    tree.create_proof(&hashed_leaf)
}
