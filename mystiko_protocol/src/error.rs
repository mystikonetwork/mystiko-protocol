use mystiko_crypto::error::{CryptoError, MerkleTreeError, SecretShareError};
use mystiko_crypto::zkp::G16ProverError;
use serde_json::Error as SerdeJsonError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("parameter error")]
    ParameterError,
    #[error("invalid shielded address")]
    InvalidShieldedAddressError,
    #[error("invalid note size")]
    InvalidNoteSizeError,
    #[error("invalid note format")]
    InvalidNoteFormatError,
    #[error(transparent)]
    ProtocolKeyError(#[from] ProtocolKeyError),
    #[error(transparent)]
    ECCryptoError(#[from] CryptoError),
    #[error(transparent)]
    SecretShareError(#[from] SecretShareError),
    #[error(transparent)]
    MerkleTreeError(#[from] MerkleTreeError),
    #[error(transparent)]
    SerdeJsonError(#[from] SerdeJsonError),
    #[error(transparent)]
    G16ProverError(#[from] G16ProverError),
    #[error(transparent)]
    AnyhowError(#[from] anyhow::Error),
}

#[derive(Error, Debug)]
pub enum ProtocolKeyError {
    #[error("generate note random secret key error")]
    GenerateNoteRandomSecretKeyError,
    #[error("generate encrypt public key error")]
    GenerateEncryptPublicKeyError,
    #[error("import verify public key error")]
    ImportVerifyPublicKeyError,
    #[error("import verify secret key error")]
    ImportVerifySecretKeyError,
    #[error("import encrypt public key error")]
    ImportEncryptPublicKeyError,
    #[error("import encrypt secret key error")]
    ImportEncryptSecretKeyError,
}
