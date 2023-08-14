pub use ark_bn254::{Bn254 as Curve, Fr};
use ark_circom::{CircomBuilder, CircomConfig};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::thread_rng;
use ark_std::UniformRand;
use fastcrypto_zkp::bn254::api::{prepare_pvk_bytes, verify_groth16_in_bytes};
use fastcrypto_zkp::bn254::verifier::process_vk_special;
use fastcrypto_zkp::bn254::VerifyingKey;
use fastcrypto_zkp::dummy_circuits::{DummyCircuit, Fibonacci};
use std::ops::Mul;

fn main() {
    const PUBLIC_SIZE: usize = 128;

    let rng = &mut thread_rng();
    let circuit = {
        let cfg =
            CircomConfig::<Curve>::new("../circuit/main_js/main.wasm", "../circuit/main.r1cs")
                .unwrap();

        let mut builder = CircomBuilder::new(cfg);
        builder.push_input("a", 3);
        builder.push_input("b", 11);
        builder.setup();
        builder.build().expect("build circuit")
    };

    let (pk, vk) = Groth16::<Curve>::circuit_specific_setup(circuit.clone(), rng).unwrap();
    let inputs = circuit.get_public_inputs().unwrap();
    let proof = Groth16::<Curve>::prove(&pk, circuit, rng).unwrap();

    let vk_bytes = {
        let mut vk_bytes = vec![];
        vk.serialize_compressed(&mut vk_bytes).unwrap();
        vk_bytes
        // prepare_pvk_bytes(vk_bytes.as_slice()).unwrap()
    };

    // // Success case.
    // assert!(prepare_pvk_bytes(vk_bytes.as_slice()).is_ok());

    // // Length of verifying key is incorrect.
    // let mut modified_bytes = vk_bytes.clone();
    // modified_bytes.pop();
    // assert!(prepare_pvk_bytes(&modified_bytes).is_err());

    let public_inputs_bytes = {
        let mut public_inputs_bytes = Vec::new();
        inputs
            .serialize_compressed(&mut public_inputs_bytes)
            .unwrap();
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

    println!("{:?}", vk_bytes);
    println!("{:?}", public_inputs_bytes);
    println!("{:?}", proof_points_bytes);
}
