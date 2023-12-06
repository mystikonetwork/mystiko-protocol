extern crate mystiko_crypto;

use mystiko_crypto::error::{CryptoError, MerkleTreeError, SecretShareError};
use mystiko_crypto::zkp::G16ProverError;

#[tokio::test]
async fn test_error() {
    let merkle_err = MerkleTreeError::MerkleTreeIsFull;
    assert!(!matches!(merkle_err, MerkleTreeError::IndexOutOfBounds));
    assert!(!matches!(merkle_err, MerkleTreeError::Unknown));

    let secret_share_err = SecretShareError::SharesOutOfBounds;
    assert!(!matches!(secret_share_err, SecretShareError::ThresholdOutOfBounds));

    let crypto_err = CryptoError::DataLengthError;
    assert!(!matches!(crypto_err, CryptoError::KeyLengthError));
    assert!(!matches!(crypto_err, CryptoError::MacMismatchError));
    assert!(!matches!(crypto_err, CryptoError::DecryptError(_)));
    assert!(!matches!(crypto_err, CryptoError::InternalError));
}

#[tokio::test]
async fn test_g16_prover_error() {
    let prover_err = G16ProverError::NotSupport;
    assert!(!matches!(prover_err, G16ProverError::SerdeJsonError(_)));
    assert!(!matches!(prover_err, G16ProverError::AbiParseError(_)));
    assert!(!matches!(prover_err, G16ProverError::DeserializeProgramError(_)));
    assert!(!matches!(prover_err, G16ProverError::ComputeWitnessError(_)));
    assert!(!matches!(prover_err, G16ProverError::ProofError(_)));
    assert!(!matches!(prover_err, G16ProverError::VKError(_)));
    assert!(!matches!(prover_err, G16ProverError::MismatchError(_)));
}
