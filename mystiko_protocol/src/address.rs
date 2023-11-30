use crate::error::{ProtocolError, ProtocolKeyError};
use crate::key::combined_public_key;
use crate::types::{EncPk, FullPk, VerifyPk};
use crate::types::{FULL_PK_SIZE, VERIFY_PK_SIZE};
use bs58;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ShieldedAddress {
    addr: String,
}

impl ShieldedAddress {
    pub fn address(&self) -> String {
        self.addr.clone()
    }

    pub fn is_valid_address(addr: &str) -> bool {
        match bs58::decode(addr).into_vec() {
            Err(_) => false,
            Ok(key) => key.len() == FULL_PK_SIZE,
        }
    }

    pub fn from_string(addr: &str) -> Result<Self, ProtocolError> {
        if !ShieldedAddress::is_valid_address(addr) {
            return Err(ProtocolError::InvalidShieldedAddressError);
        }

        Ok(Self { addr: addr.to_string() })
    }

    pub fn from_full_public_key(full_pk: &FullPk) -> Self {
        let addr = bs58::encode(full_pk).into_string();
        Self { addr }
    }

    pub fn from_public_key(pk_verify: &VerifyPk, pk_enc: &EncPk) -> Self {
        ShieldedAddress::from_full_public_key(&combined_public_key(pk_verify, pk_enc))
    }

    pub fn public_key(&self) -> Result<(VerifyPk, EncPk), ProtocolError> {
        let ck = bs58::decode(self.addr.as_str())
            .into_vec()
            .map_err(|_| ProtocolError::InvalidShieldedAddressError)?;
        if ck.len() != FULL_PK_SIZE {
            return Err(ProtocolError::InvalidShieldedAddressError);
        }
        let vk = &ck[0..VERIFY_PK_SIZE];
        let ek = &ck[VERIFY_PK_SIZE..];
        let vk: VerifyPk = vk
            .try_into()
            .map_err(|_| ProtocolKeyError::ImportVerifyPublicKeyError)?;
        let ek: EncPk = ek
            .try_into()
            .map_err(|_| ProtocolKeyError::ImportEncryptPublicKeyError)?;
        Ok((vk, ek))
    }
}
