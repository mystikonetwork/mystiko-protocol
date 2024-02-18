use elliptic_curve::Error as EllipticCurveError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MerkleTreeError {
    #[error("merkle tree is full")]
    MerkleTreeIsFull,
    #[error("index out of bounds")]
    IndexOutOfBounds,
    #[error("unknown error")]
    Unknown,
    #[error(transparent)]
    CryptoError(#[from] CryptoError),
}

#[derive(Error, Debug, PartialEq)]
pub enum SecretShareError {
    #[error("num of shares out of range")]
    SharesOutOfBounds,
    #[error("threshold out of range")]
    ThresholdOutOfBounds,
}

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error(transparent)]
    EllipticCurveError(#[from] EllipticCurveError),
    #[error("data length error")]
    DataLengthError,
    #[error("key length error")]
    KeyLengthError,
    #[error("mac mismatch error")]
    MacMismatchError,
    #[error("decrypt error {0}")]
    DecryptError(String),
    #[error("ecc encoded point error")]
    EccEncodedPointError,
    #[error("ecc point conversion none error")]
    EccPointConversionNoneError,
    #[error("poseidon fr from big uint error")]
    PoseidonFrFromBigUintError,
    #[error("poseidon fr to big uint error")]
    PoseidonFrToBigUintError,
    #[error("poseidon fr hash error")]
    PoseidonFrHashError,
    #[error("hmac sha256 error")]
    HmacSha256Error,
    #[error("hmac sha512 error")]
    HmacSha512Error,
    #[error("big uint to 32 bytes error")]
    BigUintTo32BytesError,
    #[error("invalid key size")]
    InvalidKeySize,
    #[error("decompression failed")]
    DecompressionFailed,
    #[error("internal error")]
    InternalError,
}
