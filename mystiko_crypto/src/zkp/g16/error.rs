use serde_json::Error as SerdeJsonError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum G16ProverError {
    #[error(transparent)]
    SerdeJsonError(#[from] SerdeJsonError),
    #[error("abi parse error {0}")]
    AbiParseError(String),
    #[error("deserialize program error {0}")]
    DeserializeProgramError(String),
    #[error("compute witness error {0}")]
    ComputeWitnessError(String),
    #[error("proof error {0}")]
    ProofError(String),
    #[error("vk error {0}")]
    VKError(String),
    #[error("mismatch error {0}")]
    MismatchError(String),
    #[error("Not support")]
    NotSupport,
}
