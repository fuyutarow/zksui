use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize, Serialize)]
struct VerificationKey {
    protocol: String,
    curve: String,
    nPublic: u32,
    vk_alpha_1: Vec<Value>,
    vk_beta_2: Vec<Vec<Value>>,
    vk_gamma_2: Vec<Vec<Value>>,
    vk_delta_2: Vec<Vec<Value>>,
    vk_alphabeta_12: Vec<Vec<Vec<Value>>>,
    IC: Vec<Vec<Value>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Proof {
    pi_a: Vec<Value>,
    pi_b: Vec<Vec<Value>>,
    pi_c: Vec<Value>,
    protocol: String,
    curve: String,
}

fn serialize_vk(vk: &VerificationKey) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(serde_json::to_vec(&vk.vk_alpha_1).expect("Failed to serialize vk_alpha_1"));
    bytes.extend(serde_json::to_vec(&vk.vk_beta_2).expect("Failed to serialize vk_beta_2"));
    bytes.extend(serde_json::to_vec(&vk.vk_gamma_2).expect("Failed to serialize vk_gamma_2"));
    bytes.extend(serde_json::to_vec(&vk.vk_delta_2).expect("Failed to serialize vk_delta_2"));
    bytes.extend(
        serde_json::to_vec(&vk.vk_alphabeta_12).expect("Failed to serialize vk_alphabeta_12"),
    );
    bytes
}

fn serialize_public_inputs(ic: &Vec<Vec<Value>>) -> Vec<u8> {
    serde_json::to_vec(ic).expect("Failed to serialize public inputs")
}

fn serialize_proof_points(proof: &Proof) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(serde_json::to_vec(&proof.pi_a).expect("Failed to serialize pi_a"));
    bytes.extend(serde_json::to_vec(&proof.pi_b).expect("Failed to serialize pi_b"));
    bytes.extend(serde_json::to_vec(&proof.pi_c).expect("Failed to serialize pi_c"));
    bytes
}

fn main() {
    let vk_json = std::fs::read_to_string("../trusted_setup/verification_key.json")
        .expect("Failed to read vk file");
    let proof_json =
        std::fs::read_to_string("../prover/proof.json").expect("Failed to read proof file");

    let vk: VerificationKey = serde_json::from_str(&vk_json).expect("Failed to parse vk");
    let proof: Proof = serde_json::from_str(&proof_json).expect("Failed to parse proof");

    let vk_bytes = serialize_vk(&vk);
    let public_inputs_bytes = serialize_public_inputs(&vk.IC);
    let proof_points_bytes = serialize_proof_points(&proof);

    println!("vk_bytes size: {}", vk_bytes.len());
    println!("public_inputs_bytes size: {}", public_inputs_bytes.len());
    println!("proof_points_bytes size: {}", proof_points_bytes.len());

    println!("{:?}", vk_bytes);
    println!("{:?}", public_inputs_bytes);
    println!("{:?}", proof_points_bytes);
}
