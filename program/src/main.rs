#![no_main]
sp1_zkvm::entrypoint!(main);

use aggregation_lib::build_tree;
use sha2::{Digest, Sha256};

pub fn main() {
    // Read the verification keys.
    let vkeys = sp1_zkvm::io::read::<Vec<[u32; 8]>>();

    // Read the public values.
    let public_values = sp1_zkvm::io::read::<Vec<Vec<u8>>>();

    assert_eq!(vkeys.len(), public_values.len());
    for i in 0..vkeys.len() {
        let vkey = &vkeys[i];
        // Verify the proofs.
        let public_values = &public_values[i];
        let public_values_digest = Sha256::digest(public_values);
        sp1_zkvm::lib::verify::verify_sp1_proof(vkey, &public_values_digest.into());
    }

    let tree = build_tree(&vkeys, &public_values);

    sp1_zkvm::io::commit_slice(tree.root.as_slice());
}
