use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_relations::r1cs::ConstraintSystem;
use ark_relations::r1cs::LinearCombination;
use ark_relations::r1cs::SynthesisError;
use ark_relations::r1cs::Variable;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisMode};
use ark_std::rand::Rng;

struct MyCircuit;

// impl ConstraintSynthesizer<Bn254> for MyCircuit {
//     fn generate_constraints<CS: ark_relations::r1cs::ConstraintSystem<Bn254>>(
//         self,
//         cs: &mut CS,
//     ) -> Result<(), SynthesisError> {
//         let _ = cs.alloc(|| "input variable", || Ok(Bn254::one()))?;
//         let _ = cs.alloc_input(|| "input variable", || Ok(Bn254::one()))?;
//         Ok(())
//     }
// }

fn main() {
    let rng = &mut ark_std::rand::thread_rng();
    let circuit = MyCircuit;
    let params = Groth16::<Bn254>::generate_random_parameters(circuit, rng).unwrap();

    let proving_key = params.pk;
    let verification_key = params.vk;

    println!("Proving Key: {:?}", proving_key);
    println!("Verification Key: {:?}", verification_key);
}
