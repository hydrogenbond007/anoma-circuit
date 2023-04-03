use bellman::groth16::{generate_random_parameters, prepare_verifying_key, Proof, VerifyingKey};
use bellman::pairing::bls12_381::{Bls12, Fr, G1Affine, G2Affine};
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use rand::thread_rng;

const ASSET_1_INDEX: usize = 0;
const ASSET_2_INDEX: usize = 1;
const OUTPUT_INDEX: usize = 2;

// Define the circuit
struct AnomaCircuit {
    asset_1: Option<Fr>,
    asset_2: Option<Fr>,
    output: Option<Fr>,
}

impl Circuit<Fr> for AnomaCircuit {
    fn synthesize<CS: ConstraintSystem<Fr>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Define the inputs and allocate them in the circuit
        let asset_1 = cs.alloc(|| "asset_1", || self.asset_1.ok_or_else(|| SynthesisError::AssignmentMissing))?;
        let asset_2 = cs.alloc(|| "asset_2", || self.asset_2.ok_or_else(|| SynthesisError::AssignmentMissing))?;
        let output = cs.alloc(|| "output", || self.output.ok_or_else(|| SynthesisError::AssignmentMissing))?;

        // Define the constraints
        cs.enforce_zero(asset_1.clone() + asset_2.clone() - output.clone());

        // Make sure the output is positive
        cs.enforce(
            || "output is positive",
            |lc| lc + output,
            ConstraintSystem::<Fr>::ONE,
            |lc| lc,
        );

        Ok(())
    }
}

// Define a function to generate the proof
fn generate_proof(
    asset_1: Fr,
    asset_2: Fr,
    output: Fr,
) -> Result<(Proof<Bls12>, Vec<u8>, Vec<u8>), SynthesisError> {
    let circuit = AnomaCircuit {
        asset_1: Some(asset_1),
        asset_2: Some(asset_2),
        output: Some(output),
    };

    // Generate the parameters for the Groth16 proof system
    let params = generate_random_parameters::<Bls12, _, _>(circuit, &mut thread_rng())?;

    // Prepare the verifying key
    let vk_bytes = prepare_verifying_key(&params.vk).write().unwrap();

    // Generate the proof
    let proof = params.prove(&circuit)?;

    // Serialize the proof
    let proof_bytes = proof.write().unwrap();

    Ok((proof, vk_bytes, proof_bytes))
}
