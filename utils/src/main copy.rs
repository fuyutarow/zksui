use ark_bn254::{Bn254, Fr};
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
    let circuit = DummyCircuit::<Fr> {
        a: Some(<Fr>::rand(rng)),
        b: Some(<Fr>::rand(rng)),
        num_variables: PUBLIC_SIZE,
        num_constraints: 10,
    };

    let (_, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, rng).unwrap();

    let mut vk_bytes = vec![];
    vk.serialize_compressed(&mut vk_bytes).unwrap();

    dbg!(&vk_bytes);

    // Success case.
    assert!(prepare_pvk_bytes(vk_bytes.as_slice()).is_ok());

    // Length of verifying key is incorrect.
    let mut modified_bytes = vk_bytes.clone();
    modified_bytes.pop();
    assert!(prepare_pvk_bytes(&modified_bytes).is_err());
}
