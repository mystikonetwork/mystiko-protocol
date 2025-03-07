use crate::zkp::G16ProverError;
use anyhow::Result;
use rand::{rngs::StdRng, SeedableRng};
use std::io::BufReader;
use zokrates_ast::ir::{self, Witness};
use zokrates_field::Field;
use zokrates_proof_systems::{Backend, Proof, Scheme};

pub fn generate_proof<T: Field, S: Scheme<T>, B: Backend<T, S>>(
    ir_prog: ir::Prog<T>,
    witness: Witness<T>,
    proving_key: &[u8],
) -> Result<Proof<T, S>, G16ProverError> {
    let pk_reader = BufReader::new(proving_key);
    let mut rng = StdRng::from_entropy();
    let proof = B::generate_proof(ir_prog, witness, pk_reader, &mut rng);
    Ok(proof)
}
