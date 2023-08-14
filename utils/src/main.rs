pub use ark_bn254::{Bn254 as Curve, Fr};
use ark_circom::{CircomBuilder, CircomConfig};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::bn::G2Prepared;
use ark_groth16::Proof;
use ark_groth16::{Groth16, PreparedVerifyingKey as ArkPreparedVerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::thread_rng;
use ark_std::UniformRand;
use fastcrypto::error::FastCryptoError;
use fastcrypto_zkp::bn254::api::{prepare_pvk_bytes, verify_groth16_in_bytes};
use fastcrypto_zkp::bn254::api::{Bn254Fr, SCALAR_SIZE};
use fastcrypto_zkp::bn254::verifier::{process_vk_special, PreparedVerifyingKey};
use fastcrypto_zkp::bn254::VerifyingKey;
use fastcrypto_zkp::dummy_circuits::{DummyCircuit, Fibonacci};
use num_bigint::BigInt;
use serde_json::json;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;

pub fn verify_groth16(
    pvk: &PreparedVerifyingKey,
    proof_public_inputs_as_bytes: &[u8],
    proof_points_as_bytes: &[u8],
) -> Result<bool, FastCryptoError> {
    dbg!("#114");
    let proof = Proof::<Curve>::deserialize_compressed(proof_points_as_bytes)
        .map_err(|_| FastCryptoError::InvalidInput)?;
    dbg!("#115");
    let mut public_inputs = Vec::new();
    for chunk in proof_public_inputs_as_bytes.chunks(SCALAR_SIZE) {
        dbg!("chunk", chunk.len(), &chunk);
        public_inputs
            .push(Fr::deserialize_compressed(chunk).map_err(|_| FastCryptoError::InvalidInput)?);
    }
    dbg!("#116");
    let ark_pkv = {
        let mut ark_pvk = ArkPreparedVerifyingKey::default();
        ark_pvk.vk.gamma_abc_g1 = pvk.vk_gamma_abc_g1.clone();
        ark_pvk.alpha_g1_beta_g2 = pvk.alpha_g1_beta_g2;
        ark_pvk.gamma_g2_neg_pc = G2Prepared::from(&pvk.gamma_g2_neg_pc);
        ark_pvk.delta_g2_neg_pc = G2Prepared::from(&pvk.delta_g2_neg_pc);
        ark_pvk
    };

    Groth16::<Curve>::verify_with_processed_vk(&ark_pkv, &public_inputs, &proof)
        .map_err(|e| FastCryptoError::GeneralError(e.to_string()))
}

type CircomInput = HashMap<String, Vec<num_bigint::BigInt>>;

fn verify_proof_with_r1cs(inputs: CircomInput, wasm_path: &str, r1cs_path: &str) {
    // Load the WASM and R1CS for witness and proof generation
    let cfg = CircomConfig::<Curve>::new(wasm_path, r1cs_path).unwrap();

    // Insert our public inputs as key value pairs
    let mut builder = CircomBuilder::new(cfg);
    for (k, v) in inputs {
        for e in v {
            builder.push_input(&k, e);
        }
    }
    // Create an empty instance for setting it up
    let circuit = builder.setup();

    // Run a trusted setup
    let mut rng = thread_rng();
    let params =
        Groth16::<Curve>::generate_random_parameters_with_reduction(circuit, &mut rng).unwrap();

    // Get the populated instance of the circuit with the witness
    let circuit = builder.build().unwrap();

    let inputs = circuit.get_public_inputs().unwrap();
    let proof = Groth16::<Curve>::prove(&params, circuit, &mut rng).unwrap();
    let pvk = Groth16::<Curve>::process_vk(&params.vk).unwrap();

    let verified = Groth16::<Curve>::verify_proof(&pvk, &proof, &inputs).unwrap();
    dbg!("verified", &verified);
    assert!(verified);

    // verify_groth16()

    let vk_bytes = {
        let mut vk_bytes = vec![];
        params.vk.serialize_compressed(&mut vk_bytes).unwrap();
        vk_bytes
    };

    let delta_bytes = {
        let mut bytes = vec![];
        params.delta_g1.serialize_compressed(&mut bytes).unwrap();
        bytes
    };

    let public_inputs_bytes = {
        let mut public_inputs_bytes = Vec::new();
        for input in inputs.iter() {
            input
                .serialize_compressed(&mut public_inputs_bytes)
                .unwrap();
        }
        public_inputs_bytes
    };

    let proof_points_bytes = {
        let mut proof_points_bytes = Vec::new();
        proof
            .a
            .serialize_compressed(&mut proof_points_bytes)
            .unwrap();
        proof
            .b
            .serialize_compressed(&mut proof_points_bytes)
            .unwrap();
        proof
            .c
            .serialize_compressed(&mut proof_points_bytes)
            .unwrap();
        proof_points_bytes
    };

    println!("vk_bytes size: {}", vk_bytes.len());
    println!("public_inputs_bytes size: {}", public_inputs_bytes.len());
    println!("proof_points_bytes size: {}", proof_points_bytes.len());

    println!("vk_bytes: {}", hex::encode(&vk_bytes));
    println!("public_inputs_bytes: {}", hex::encode(&public_inputs_bytes));
    println!("proof_points_bytes: {}", hex::encode(&proof_points_bytes));

    let pvk = process_vk_special(&params.vk.into());
    let result: Result<bool, FastCryptoError> =
        verify_groth16(&pvk, &public_inputs_bytes, &proof_points_bytes);
    dbg!("result", &result);

    println!("{:?}", &vk_bytes);
    println!("{:?}", &public_inputs_bytes);
    println!("{:?}", &proof_points_bytes);

    let output_data = json!({
        "vk_bytes": &vk_bytes,
        "public_inputs_bytes": &public_inputs_bytes,
        "proof_points_bytes": &proof_points_bytes,
    });

    let mut file = File::create("output_data.json").expect("Unable to create file");
    file.write_all(output_data.to_string().as_bytes())
        .expect("Unable to write data");
}

fn main() {
    const PUBLIC_SIZE: usize = 128;

    verify_proof_with_r1cs(
        HashMap::from([
            ("a".to_string(), vec![BigInt::from(3)]),
            ("b".to_string(), vec![BigInt::from(11)]),
        ]),
        "../circuit/main_js/main.wasm",
        "../circuit/main.r1cs",
    );
}
