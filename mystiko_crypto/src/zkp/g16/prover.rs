use crate::zkp::g16::compute_witness::compute_witness;
use crate::zkp::g16::generate_proof::generate_proof;
use crate::zkp::prover::{ZKProver, ZKVerifyOptions};
use crate::zkp::{G16Proof, G16ProverError, ZKProveOptions};
use anyhow::Result;
use std::io::Cursor;
use zokrates_ast::ir::{self, ProgEnum};
use zokrates_ast::typed::abi::Abi;
use zokrates_bellman::Bellman;
use zokrates_field::Bn128Field;
use zokrates_proof_systems::G16;

pub struct G16Prover;

impl ZKProver<G16Proof> for G16Prover {
    type Error = G16ProverError;

    fn prove(&self, options: ZKProveOptions<'_>) -> Result<G16Proof, Self::Error> {
        let abi: Abi = serde_json::from_slice(options.abi_spec)?;
        let cursor = Cursor::new(options.program);
        let program = match ir::ProgEnum::deserialize(cursor) {
            Ok(p) => p.collect(),
            Err(err) => return Err(G16ProverError::DeserializeProgramError(err)),
        };

        let p = match program {
            ProgEnum::Bn128Program(p) => p,
            _ => return Err(G16ProverError::NotSupport),
        };

        let witness = compute_witness(p.clone(), &abi, options.json_args_str)?;
        let proof = generate_proof::<Bn128Field, G16, Bellman>(p, witness, options.proving_key)?;
        proof.try_into()
    }

    fn verify(&self, options: ZKVerifyOptions<'_, G16Proof>) -> Result<bool, Self::Error> {
        let vk: serde_json::Value = serde_json::from_slice(options.verification_key)?;
        options.proof.verify(vk)
    }
}
