#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_merkle_tree::tree::MerkleTree;
use alloy_primitives::{Bytes, B256};
use alloy_sol_types::{sol, SolValue};
use sha2::{Digest, Sha256};
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

pub fn main() {
    // Read the verification keys.
    let vkeys = sp1_zkvm::io::read::<Vec<[u32; 8]>>();

    // Read the public values.
    let public_values = sp1_zkvm::io::read::<Vec<Vec<u8>>>();
    let mut tree = MerkleTree::new();

    assert_eq!(vkeys.len(), public_values.len());
    for i in 0..vkeys.len() {
        let vkey = &vkeys[i];
        // Verify the proofs.
        let public_values = &public_values[i];
        let public_values_digest = Sha256::digest(public_values);
        println!("gets here");
        sp1_zkvm::lib::verify::verify_sp1_proof(vkey, &public_values_digest.into());
        println!("doesn't get here");

        // ABI encode the (vkey, committed_value) pair and add it to the merkle tree
        let root = PublicValuesStruct {
            programVKey: B256::from_slice(&words_to_bytes_le(vkey)),
            publicValues: Bytes::from(public_values.clone()),
        }
        .abi_encode();

        tree.insert(B256::from(keccak256(root)));
    }

    tree.finish();

    sp1_zkvm::io::commit_slice(tree.root.as_slice());
}
