use mystiko_crypto::error::CryptoError;
use mystiko_protocol::error::ProtocolError;

#[tokio::test]
async fn test_error() {
    let err = ProtocolError::ECCryptoError(CryptoError::InternalError);
    assert!(!matches!(err, ProtocolError::ParameterError));
    assert!(!matches!(err, ProtocolError::InvalidShieldedAddressError));
    assert!(!matches!(err, ProtocolError::InvalidNoteSizeError));
    assert!(!matches!(err, ProtocolError::SecretShareError(_)));
    assert!(!matches!(err, ProtocolError::G16ProverError(_)));
    assert!(!matches!(err, ProtocolError::MerkleTreeError(_)));
    assert!(!matches!(err, ProtocolError::SerdeJsonError(_)));
}
