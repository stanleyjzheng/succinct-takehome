//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use alloy_primitives::Bytes;
use anyhow::anyhow;
use clap::Parser;
use dotenv::dotenv;
use futures::future::try_join_all;
use serde::{Deserialize, Serialize};
use sp1_sdk::network::client::NetworkClient;
use sp1_sdk::{include_elf, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1Stdin};
use sp1_sdk::{HashableKey, SP1VerifyingKey};
use std::env;
use std::path::PathBuf;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const AGGREGATOR_ELF: &[u8] = include_elf!("aggregation-program");

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SP1AggregatedProofFixture {
    root: Bytes,
    vkey: String,
    public_values: String,
    proof: String,
}

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,

    #[clap(long, default_value = "20")]
    n: u32,
}

pub async fn get_proofs() -> anyhow::Result<Vec<SP1ProofWithPublicValues>> {
    dotenv().ok();

    let client = NetworkClient::new(&env::var("SP1_PRIVATE_KEY").unwrap());

    // this fails to deserialize and Matt couldn't figure it out
    // so he said to just hardcode the proof ID's for now
    // let proof_requests = client
    //     .get_proof_requests(ProofStatus::ProofFulfilled, Some(SP1_CIRCUIT_VERSION))
    //     .await?;

    // get only compressed proofs
    // let compressed_proof_ids = proof_requests
    //     .proofs
    //     .iter()
    //     .filter(|proof_request| proof_request.mode == 2)
    //     .map(|proof_request| proof_request.clone().proof_id)
    //     .collect::<Vec<_>>();
    let compressed_proof_ids = vec![
        "proofrequest_01jd3kpjybf5ja4pnsyjbcbjpr".to_string(),
        // "proofrequest_01jd3kp583ez2aeehj08vr966a".to_string(),
        // "proofrequest_01jd3kp62cez28fjx7vdhfj4wj".to_string(),
        // "proofrequest_01jd3kp6rmez292mz1r0adbzj8".to_string(),
        // "proofrequest_01jd3kp7qeez2bwh8hj2jr635t".to_string(),
        // "proofrequest_01jd3kp8j5ez2atv2bpfz5kx99".to_string(),
        // "proofrequest_01jd3kp9kfez29vww73shd16vz".to_string(),
        // "proofrequest_01jd3kpac7ez2ak48vx74qxtng".to_string(),
        // "proofrequest_01jd3kpb1jez29kjn12n3av4cc".to_string(),
        // "proofrequest_01jd3kpd4dez2aq8veycnt18z2".to_string(),
        // "proofrequest_01jd3kpdgxez29wdw3vebkact9".to_string(),
    ];

    let proof_futures = compressed_proof_ids
        .iter()
        .map(|proof_id| client.get_proof_status(proof_id));

    try_join_all(proof_futures)
        .await?
        .into_iter()
        .map(|(_, proof)| proof.ok_or(anyhow!("Completed proof request missing proof")))
        .collect::<anyhow::Result<Vec<_>>>()
}

fn get_compressed_proof_vkey(proof: &SP1ProofWithPublicValues) -> SP1VerifyingKey {
    let SP1ProofWithPublicValues {
        proof: SP1Proof::Compressed(proof),
        ..
    } = proof
    else {
        unimplemented!("Only compressed proofs are supported")
    };

    SP1VerifyingKey {
        vk: proof.vk.clone(),
    }
}

#[tokio::main]
async fn main() {
    const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci-program");

    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Setup the prover client.
    let client = ProverClient::new();
    let (aggregation_pk, aggregation_vk) = client.setup(AGGREGATOR_ELF);

    // ----------------------------------------------------------
    // let proofs = get_proofs().await.unwrap();
    // ----------------------------------------------------------
    let (fibonacci_pk, fibonacci_vk) = client.setup(FIBONACCI_ELF);

    let proof_1 = tracing::info_span!("generate fibonacci proof n=10").in_scope(|| {
        let mut stdin = SP1Stdin::new();
        stdin.write(&10);
        client
            .prove(&fibonacci_pk, stdin)
            .compressed()
            .run()
            .expect("proving failed")
    });
    let proof_2 = tracing::info_span!("generate fibonacci proof n=20").in_scope(|| {
        let mut stdin = SP1Stdin::new();
        stdin.write(&20);
        client
            .prove(&fibonacci_pk, stdin)
            .compressed()
            .run()
            .expect("proving failed")
    });
    let proof_3 = tracing::info_span!("generate fibonacci proof n=30").in_scope(|| {
        let mut stdin = SP1Stdin::new();
        stdin.write(&30);
        client
            .prove(&fibonacci_pk, stdin)
            .compressed()
            .run()
            .expect("proving failed")
    });
    let proofs = vec![proof_1, proof_2, proof_3];

    // ----------------------------------------------------------

    if args.execute {
        // Aggregate the proofs.
        tracing::info_span!("aggregate the proofs").in_scope(|| {
            let mut stdin = SP1Stdin::new();

            // Write the verification keys.
            let vkeys = proofs
                .iter()
                // .map(|proof| get_compressed_proof_vkey(proof).hash_u32())
                .map(|_| fibonacci_vk.hash_u32())
                .collect::<Vec<_>>();
            stdin.write::<Vec<[u32; 8]>>(&vkeys);

            // Write the public values.
            let public_values = proofs
                .iter()
                .map(|proof| proof.public_values.to_vec())
                .collect::<Vec<_>>();
            stdin.write::<Vec<Vec<u8>>>(&public_values);

            // Write the proofs.
            //
            // Note: this data will not actually be read by the aggregation program, instead it will be
            // witnessed by the prover during the recursive aggregation process inside SP1 itself.
            for proof in &proofs {
                let SP1Proof::Compressed(reduced_proof) = proof.proof.clone() else {
                    panic!()
                };
                // stdin.write_proof(*reduced_proof, get_compressed_proof_vkey(proof).vk);
                stdin.write_proof(*reduced_proof, fibonacci_vk.vk.clone())
            }

            // Generate the plonk bn254 proof.
            let proof = client
                .prove(&aggregation_pk, stdin)
                .plonk()
                .run()
                .expect("proving failed");

            create_proof_fixture(proof, &aggregation_vk);
        });
    } else {
        // // Setup the program for proving.
        // let (pk, vk) = client.setup(FIBONACCI_ELF);

        // // Generate the proof
        // let proof = client
        //     .prove(&pk, stdin)
        //     .run()
        //     .expect("failed to generate proof");

        // println!("Successfully generated proof!");

        // // Verify the proof.
        // client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
}

fn create_proof_fixture(proof: SP1ProofWithPublicValues, vk: &SP1VerifyingKey) {
    // Deserialize the public values.
    let bytes = Bytes::copy_from_slice(proof.public_values.as_slice());

    // Create the testing fixture so we can test things end-to-end.
    let fixture = SP1AggregatedProofFixture {
        root: bytes.clone(),
        vkey: vk.bytes32().to_string(),
        public_values: format!("0x{:?}", bytes),
        proof: format!("0x{}", hex::encode(proof.bytes())),
    };

    // The verification key is used to verify that the proof corresponds to the execution of the
    // program on the given input.
    //
    // Note that the verification key stays the same regardless of the input.
    println!("Verification Key: {}", fixture.vkey);

    // The public values are the values which are publicly committed to by the zkVM.
    //
    // If you need to expose the inputs or outputs of your program, you should commit them in
    // the public values.
    println!("Public Values: {}", fixture.public_values);

    // The proof proves to the verifier that the program was executed with some inputs that led to
    // the give public values.
    println!("Proof Bytes: {}", fixture.proof);

    // Save the fixture to a file.
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/src/fixtures");
    std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");
    std::fs::write(
        fixture_path.join("plonk-fixture.json".to_lowercase()),
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .expect("failed to write fixture");
}
