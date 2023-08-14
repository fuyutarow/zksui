// use fastcrypto_zkp::PreparedVerifyingKey;
use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_bn254::{Fq, Fq2, G1Affine, G1Projective, G2Affine};
use ark_groth16::VerifyingKey as ArkVerifyingKey;
use fastcrypto_zkp::bn254::verifier::process_vk_special;
use fastcrypto_zkp::bn254::VerifyingKey as FastcryptoVerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;

mod utils;

type StrPair = (&'static str, &'static str);
type StrTriplet = (&'static str, &'static str, &'static str);

#[allow(non_snake_case)]
pub fn G1Affine_from_str_projective(#[allow(clippy::type_complexity)] s: StrTriplet) -> G1Affine {
    G1Projective::new(
        s.0.parse::<Fq>().unwrap(),
        s.1.parse::<Fq>().unwrap(),
        s.2.parse::<Fq>().unwrap(),
    )
    .into()
}

#[allow(non_snake_case)]
pub fn G2Affine_from_str_projective(s: (StrPair, StrPair, StrPair)) -> G2Affine {
    use ark_bn254::G2Projective;
    G2Projective::new(
        Fq2::new(s.0 .0.parse::<Fq>().unwrap(), s.0 .1.parse::<Fq>().unwrap()),
        Fq2::new(s.1 .0.parse::<Fq>().unwrap(), s.1 .1.parse::<Fq>().unwrap()),
        Fq2::new(s.2 .0.parse::<Fq>().unwrap(), s.2 .1.parse::<Fq>().unwrap()),
    )
    .into()
}

#[derive(Debug, Serialize, Deserialize)]
struct VerifyingKeyJson {
    vk_alpha_1: Vec<String>,
    vk_beta_2: Vec<Vec<String>>,
    vk_gamma_2: Vec<Vec<String>>,
    vk_delta_2: Vec<Vec<String>>,
    vk_alphabeta_12: Vec<Vec<Vec<String>>>,
    IC: Vec<Vec<String>>,
}

impl VerifyingKeyJson {
    fn convert(&self) -> ArkVerifyingKey<Bn254> {
        ArkVerifyingKey::<Bn254> {
            alpha_g1: utils::G1Affine_from_str_projective((
                &self.vk_alpha_1[0],
                &self.vk_alpha_1[1],
                &self.vk_alpha_1[2],
            )),
            beta_g2: utils::G2Affine_from_str_projective((
                (&self.vk_beta_2[0][0], &self.vk_beta_2[0][1]),
                (&self.vk_beta_2[1][0], &self.vk_beta_2[1][1]),
                (&self.vk_beta_2[2][0], &self.vk_beta_2[2][1]),
            )),
            gamma_g2: utils::G2Affine_from_str_projective((
                (&self.vk_gamma_2[0][0], &self.vk_gamma_2[0][1]),
                (&self.vk_gamma_2[1][0], &self.vk_gamma_2[1][1]),
                (&self.vk_gamma_2[2][0], &self.vk_gamma_2[2][1]),
            )),
            delta_g2: utils::G2Affine_from_str_projective((
                (&self.vk_delta_2[0][0], &self.vk_delta_2[0][1]),
                (&self.vk_delta_2[1][0], &self.vk_delta_2[1][1]),
                (&self.vk_delta_2[2][0], &self.vk_delta_2[2][1]),
            )),
            gamma_abc_g1: self
                .IC
                .iter()
                .map(|s| utils::G1Affine_from_str_projective((&s[0], &s[1], &s[2])))
                .collect(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct Proof {
    pi_a: Vec<Value>,
    pi_b: Vec<Vec<Value>>,
    pi_c: Vec<Value>,
    protocol: String,
    curve: String,
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

fn concatenate_and_convert_to_hex(data: Vec<Vec<u8>>) -> String {
    // すべての内部のVec<u8>を連結します
    let concatenated: Vec<u8> = data.into_iter().flatten().collect();

    // 連結されたデータをhexに変換します
    hex::encode(concatenated)
}

fn main() {
    let vk_json = std::fs::read_to_string("../trusted_setup/verification_key.json")
        .expect("Failed to read vk file");
    let proof_json =
        std::fs::read_to_string("../prover/proof.json").expect("Failed to read proof file");

    let vk_json: VerifyingKeyJson = serde_json::from_str(&vk_json).expect("Failed to parse vk");
    let vk = vk_json.convert();
    let vk = FastcryptoVerifyingKey::from(vk);
    let pvk = process_vk_special(&vk);
    let vk_bytes = concatenate_and_convert_to_hex(pvk.as_serialized().unwrap());

    let proof: Proof = serde_json::from_str(&proof_json).expect("Failed to parse proof");
    let ic_values: Vec<Vec<Value>> = vk_json
        .IC
        .iter()
        .map(|vec| vec.iter().map(|s| Value::String(s.clone())).collect())
        .collect();
    let public_inputs_bytes = serialize_public_inputs(&ic_values);
    let proof_points_bytes = serialize_proof_points(&proof);

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
