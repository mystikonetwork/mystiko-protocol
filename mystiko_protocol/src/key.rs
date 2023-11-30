use crate::error::ProtocolKeyError;
use crate::types::{EncPk, EncSk, FullPk, FullSk, VerifyPk, VerifySk};
use crate::types::{ENC_PK_SIZE, ENC_SK_SIZE, VERIFY_PK_SIZE, VERIFY_SK_SIZE};
use babyjubjub_rs::PrivateKey;
use k256::SecretKey;
use mystiko_crypto::constants::FIELD_SIZE;
use mystiko_crypto::eccrypto::public_key_to_vec;
use mystiko_crypto::utils::{biguint_to_32_bytes, fr_to_bytes};

pub fn verification_secret_key(raw_secret_key: &VerifySk) -> Result<VerifySk, ProtocolKeyError> {
    let pk = PrivateKey::import(raw_secret_key.to_vec()).map_err(|_| ProtocolKeyError::ImportVerifySecretKeyError)?;
    let sk = pk
        .scalar_key()
        .to_biguint()
        .ok_or(ProtocolKeyError::ImportVerifySecretKeyError)?;
    if sk > *FIELD_SIZE {
        return Err(ProtocolKeyError::ImportVerifySecretKeyError);
    }
    Ok(biguint_to_32_bytes(&sk))
}

pub fn verification_public_key(raw_secret_key: &VerifySk) -> Result<VerifyPk, ProtocolKeyError> {
    let pk = PrivateKey::import(raw_secret_key.to_vec()).map_err(|_| ProtocolKeyError::ImportVerifySecretKeyError)?;
    let point = pk.public();
    Ok(fr_to_bytes(&point.x))
}

pub fn encryption_secret_key(raw_secret_key: &EncSk) -> EncSk {
    *raw_secret_key
}

pub fn encryption_public_key(raw_secret_key: &EncSk) -> Result<EncPk, ProtocolKeyError> {
    let secret_key =
        SecretKey::from_slice(raw_secret_key).map_err(|_| ProtocolKeyError::ImportEncryptSecretKeyError)?;
    let public_key = secret_key.public_key();
    let public_key_vec = public_key_to_vec(&public_key, true);
    if public_key_vec.len() != ENC_PK_SIZE {
        return Err(ProtocolKeyError::GenerateEncryptPublicKeyError);
    }
    public_key_vec
        .as_slice()
        .try_into()
        .map_err(|_| ProtocolKeyError::GenerateEncryptPublicKeyError)
}

pub fn combined_secret_key(sk_verify: &VerifySk, sk_enc: &EncSk) -> FullSk {
    let mut combined = [0u8; VERIFY_SK_SIZE + ENC_SK_SIZE];
    combined[..VERIFY_SK_SIZE].copy_from_slice(sk_verify);
    combined[VERIFY_SK_SIZE..].copy_from_slice(sk_enc);
    combined
}

pub fn combined_public_key(pk_verify: &VerifyPk, pk_enc: &EncPk) -> FullPk {
    let mut combined = [0u8; VERIFY_PK_SIZE + ENC_PK_SIZE];
    combined[..VERIFY_PK_SIZE].copy_from_slice(pk_verify);
    combined[VERIFY_PK_SIZE..].copy_from_slice(pk_enc);
    combined
}

pub fn separate_secret_keys(full_sk: &FullSk) -> Result<(VerifySk, EncSk), ProtocolKeyError> {
    let (v_sk, e_sk) = full_sk.split_at(VERIFY_SK_SIZE);
    let v_sk = v_sk
        .try_into()
        .map_err(|_| ProtocolKeyError::ImportVerifySecretKeyError)?;
    let e_sk = e_sk
        .try_into()
        .map_err(|_| ProtocolKeyError::ImportEncryptSecretKeyError)?;
    Ok((v_sk, e_sk))
}

pub fn separate_public_keys(full_pk: &FullPk) -> Result<(VerifyPk, EncPk), ProtocolKeyError> {
    let (v_pk, e_pk) = full_pk.split_at(VERIFY_PK_SIZE);
    let v_pk = v_pk
        .try_into()
        .map_err(|_| ProtocolKeyError::ImportVerifyPublicKeyError)?;
    let e_pk = e_pk
        .try_into()
        .map_err(|_| ProtocolKeyError::ImportEncryptPublicKeyError)?;
    Ok((v_pk, e_pk))
}

pub fn full_public_key(full_sk: &FullSk) -> Result<FullPk, ProtocolKeyError> {
    let (v_sk, e_sk) = separate_secret_keys(full_sk)?;
    let v_pk = verification_public_key(&v_sk)?;
    let e_pk = encryption_public_key(&e_sk)?;
    Ok(combined_public_key(&v_pk, &e_pk))
}
