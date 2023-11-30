use crate::commitment::{EncryptedNote, Note};
use crate::error::ProtocolError;
use crate::types::{AuditingPk, AuditingSk, EncPk, EncSk, RandomSk, SigPk, TxAmount, VerifyPk, VerifySk};
use crate::types::{AUDITING_THRESHOLD, DECRYPTED_NOTE_SIZE, NUM_OF_AUDITORS};
use crate::utils::{compute_nullifier, compute_sig_pk_hash};
use anyhow::Result;
use ff::hex;
use mystiko_crypto::constants::FIELD_SIZE;
use mystiko_crypto::crypto::decrypt_asymmetric;
use mystiko_crypto::ecies;
use mystiko_crypto::shamir;
use mystiko_crypto::zkp::proof::ZKProof;
use num_bigint::BigUint;
use std::ops::Shr;
use typed_builder::TypedBuilder;

#[derive(Debug, Clone, TypedBuilder)]
pub struct Transaction {
    pub inputs: Vec<TransactionCommitmentInput>,
    pub outputs: Vec<TransactionCommitmentOutput>,
    pub tree_root: BigUint,
    pub sig_pk: SigPk,
    pub public_amount: TxAmount,
    pub relayer_fee_amount: TxAmount,
    pub random_auditing_secret_key: Option<AuditingSk>,
    pub auditor_public_keys: Vec<AuditingPk>,
    pub program: Vec<u8>,
    pub abi: Vec<u8>,
    pub proving_key: Vec<u8>,
}

#[derive(Debug, Clone, TypedBuilder)]
pub struct TransactionProof {
    pub proof: ZKProof,
    pub zk_input: TransactionZKInput,
}

impl Transaction {
    pub fn prove(&self) -> Result<TransactionProof, ProtocolError> {
        let zk_input = TransactionZKInput::from(self)?;
        let tx_param = zk_input.to_json_param()?;
        let proof = ZKProof::generate(
            self.program.as_slice(),
            self.abi.as_slice(),
            self.proving_key.as_slice(),
            &tx_param,
        )?;
        Ok(TransactionProof::builder().proof(proof).zk_input(zk_input).build())
    }

    fn build_auditing_data(&self) -> AuditingKeys {
        let random_auditing_sk = if let Some(key) = self.random_auditing_secret_key {
            key
        } else {
            ecies::generate_secret_key()
        };

        let random_auditing_pk = ecies::public_key(&random_auditing_sk);
        let (unpacked_random_k_x, unpacked_random_k_y) = ecies::unpack_public_key(&random_auditing_pk);
        let keys = self
            .auditor_public_keys
            .iter()
            .map(|pk| {
                let (unpacked_key_x, unpacked_key_y) = ecies::unpack_public_key(pk);
                AuditingUnpackedPublicKey::builder()
                    .x_signs(is_neg(&unpacked_key_x))
                    .x(unpacked_key_x)
                    .y(unpacked_key_y)
                    .build()
            })
            .collect::<Vec<_>>();
        AuditingKeys::builder()
            .random_sk(random_auditing_sk)
            .random_pk(random_auditing_pk)
            .random_unpacked_pk(
                AuditingUnpackedPublicKey::builder()
                    .x_signs(is_neg(&unpacked_random_k_x))
                    .x(unpacked_random_k_x)
                    .y(unpacked_random_k_y)
                    .build(),
            )
            .auditors(keys)
            .build()
    }
}

#[derive(Debug, Clone, TypedBuilder)]
pub struct TransactionZKInput {
    pub tree_root: BigUint,
    pub in_nullifiers: Vec<BigUint>,
    pub in_sig_hashes: Vec<BigUint>,
    pub sig_public_key: SigPk,
    pub public_amount: BigUint,
    pub relayer_fee_amount: BigUint,
    pub out_commitments: Vec<BigUint>,
    pub out_rollup_fee_amounts: Vec<BigUint>,
    pub random_public_key_x_signs: bool,
    pub random_public_key_y: BigUint,
    pub auditor_public_key_x_signs: Vec<bool>,
    pub auditor_public_key_ys: Vec<BigUint>,
    pub encrypted_commitment_shares: Vec<Vec<BigUint>>,
    pub in_commitments: Vec<BigUint>,
    pub in_amounts: Vec<BigUint>,
    pub in_random_p: Vec<BigUint>,
    pub in_random_r: Vec<BigUint>,
    pub in_random_s: Vec<BigUint>,
    pub in_secret_key: Vec<BigUint>,
    pub in_public_key: Vec<BigUint>,
    pub in_path_elements: Vec<Vec<BigUint>>,
    pub in_path_indices: Vec<Vec<bool>>,
    pub out_amounts: Vec<BigUint>,
    pub out_random_p: Vec<BigUint>,
    pub out_random_r: Vec<BigUint>,
    pub out_random_s: Vec<BigUint>,
    pub out_public_key: Vec<BigUint>,
    pub random_public_key_x: BigUint,
    pub auditor_public_key_xs: Vec<BigUint>,
    pub random_public_key: BigUint,
    pub random_secret_key: BigUint,
    pub coefficients: Vec<Vec<BigUint>>,
    pub in_commitment_shares: Vec<Vec<BigUint>>,
}

impl TransactionZKInput {
    fn from(t: &Transaction) -> Result<Self, ProtocolError> {
        let input_details = t
            .inputs
            .iter()
            .map(|input| input.decrypt(&t.sig_pk))
            .collect::<Result<Vec<_>, _>>()?;
        let auditing_keys = t.build_auditing_data();
        let shares = t
            .inputs
            .iter()
            .map(|input| input.split_commitments(&t.auditor_public_keys, &auditing_keys))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(TransactionZKInput {
            tree_root: t.tree_root.clone(),
            in_nullifiers: clone_biguint_vec(&input_details, |d| d.nullifier.clone()),
            in_sig_hashes: clone_biguint_vec(&input_details, |d| d.sig_hash.clone()),
            sig_public_key: t.sig_pk,
            public_amount: t.public_amount.clone(),
            relayer_fee_amount: t.relayer_fee_amount.clone(),
            out_commitments: clone_biguint_vec(&t.outputs, |o| o.commitment.clone()),
            out_rollup_fee_amounts: clone_biguint_vec(&t.outputs, |o| o.rollup_fee_amount.clone()),
            random_public_key_x_signs: auditing_keys.random_unpacked_pk.x_signs,
            random_public_key_y: BigUint::from_bytes_le(&auditing_keys.random_unpacked_pk.y),
            auditor_public_key_x_signs: auditing_keys.auditors.iter().map(|k| k.x_signs).collect(),
            auditor_public_key_ys: clone_biguint_vec(&auditing_keys.auditors, |k| BigUint::from_bytes_le(&k.y)),
            encrypted_commitment_shares: shares.iter().map(|s| &s.encrypted_shares).cloned().collect(),
            in_commitments: clone_biguint_vec(&t.inputs, |i| i.commitment.clone()),
            in_amounts: clone_biguint_vec(&input_details, |i| i.amount.clone()),
            in_random_p: clone_biguint_vec(&input_details, |i| BigUint::from_bytes_le(&i.random_p)),
            in_random_r: clone_biguint_vec(&input_details, |i| BigUint::from_bytes_le(&i.random_r)),
            in_random_s: clone_biguint_vec(&input_details, |i| BigUint::from_bytes_le(&i.random_s)),
            in_secret_key: clone_biguint_vec(&t.inputs, |i| BigUint::from_bytes_le(&i.sk_verify)),
            in_public_key: clone_biguint_vec(&t.inputs, |i| BigUint::from_bytes_le(&i.pk_verify)),
            in_path_elements: t.inputs.iter().map(|i| i.path_elements.clone()).collect(),
            in_path_indices: input_details.iter().map(|i| i.path_indices.clone()).collect(),
            out_amounts: clone_biguint_vec(&t.outputs, |o| o.amount.clone()),
            out_random_p: clone_biguint_vec(&t.outputs, |o| BigUint::from_bytes_le(&o.random_p)),
            out_random_r: clone_biguint_vec(&t.outputs, |o| BigUint::from_bytes_le(&o.random_r)),
            out_random_s: clone_biguint_vec(&t.outputs, |o| BigUint::from_bytes_le(&o.random_s)),
            out_public_key: clone_biguint_vec(&t.outputs, |o| BigUint::from_bytes_le(&o.pk_verify)),
            random_public_key_x: BigUint::from_bytes_le(&auditing_keys.random_unpacked_pk.x),
            auditor_public_key_xs: clone_biguint_vec(&auditing_keys.auditors, |k| BigUint::from_bytes_le(&k.x)),
            random_public_key: BigUint::from_bytes_le(&auditing_keys.random_pk),
            random_secret_key: BigUint::from_bytes_le(&auditing_keys.random_sk),
            coefficients: shares.iter().map(|s| s.coefficient.clone()).collect(),
            in_commitment_shares: shares.iter().map(|s| s.shares.clone()).collect(),
        })
    }

    fn to_json_param(&self) -> Result<String, ProtocolError> {
        let mut array: Vec<serde_json::Value> = vec![json_biguint(&self.tree_root)];
        array.push(json_biguint_vec(&self.in_nullifiers));
        array.push(json_biguint_vec(&self.in_sig_hashes));
        array.push(serde_json::json!(hex::encode(self.sig_public_key)));
        array.push(json_biguint(&self.public_amount));
        array.push(json_biguint(&self.relayer_fee_amount));
        array.push(json_biguint_vec(&self.out_commitments));
        array.push(json_biguint_vec(&self.out_rollup_fee_amounts));
        array.push(serde_json::json!(self.random_public_key_x_signs));
        array.push(json_biguint(&self.random_public_key_y));
        array.push(serde_json::json!(self.auditor_public_key_x_signs));
        array.push(json_biguint_vec(&self.auditor_public_key_ys));
        array.push(json_biguint_vec_vec(&self.encrypted_commitment_shares));
        array.push(json_biguint_vec(&self.in_commitments));
        array.push(json_biguint_vec(&self.in_amounts));
        array.push(json_biguint_vec(&self.in_random_p));
        array.push(json_biguint_vec(&self.in_random_r));
        array.push(json_biguint_vec(&self.in_random_s));
        array.push(json_biguint_vec(&self.in_secret_key));
        array.push(json_biguint_vec(&self.in_public_key));
        array.push(json_biguint_vec_vec(&self.in_path_elements));
        array.push(serde_json::json!(self.in_path_indices));
        array.push(json_biguint_vec(&self.out_amounts));
        array.push(json_biguint_vec(&self.out_random_p));
        array.push(json_biguint_vec(&self.out_random_r));
        array.push(json_biguint_vec(&self.out_random_s));
        array.push(json_biguint_vec(&self.out_public_key));
        array.push(json_biguint(&self.random_public_key_x));
        array.push(json_biguint_vec(&self.auditor_public_key_xs));
        array.push(json_biguint(&self.random_secret_key));
        array.push(json_biguint_vec_vec(&self.coefficients));
        array.push(json_biguint_vec_vec(&self.in_commitment_shares));

        Ok(serde_json::Value::Array(array).to_string())
    }
}

#[derive(Debug, Clone, TypedBuilder)]
pub struct TransactionCommitmentInput {
    pub commitment: BigUint,
    pub private_note: EncryptedNote,
    pub path_indices: Vec<usize>,
    pub path_elements: Vec<BigUint>,
    pub pk_verify: VerifyPk,
    pub sk_verify: VerifySk,
    pub pk_enc: EncPk,
    pub sk_enc: EncSk,
}

impl TransactionCommitmentInput {
    fn decrypt(&self, sig_pk: &SigPk) -> Result<TransactionInputDetails, ProtocolError> {
        let note = decrypt_asymmetric(&self.sk_enc, self.private_note.as_slice())?;
        assert_eq!(note.len(), DECRYPTED_NOTE_SIZE);
        let note = Note::from_vec(note)?;
        let path = self.path_indices.iter().map(|&x| x != 0).collect::<Vec<_>>();
        Ok(TransactionInputDetails::builder()
            .random_p(note.random_p)
            .random_r(note.random_r)
            .random_s(note.random_s)
            .amount(note.amount)
            .nullifier(compute_nullifier(&self.sk_verify, &note.random_p))
            .sig_hash(compute_sig_pk_hash(sig_pk, &self.sk_verify))
            .path_indices(path)
            .build())
    }

    fn split_commitments(
        &self,
        auditor_public_keys: &[AuditingPk],
        auditing_keys: &AuditingKeys,
    ) -> Result<TransactionCommitmentShares, ProtocolError> {
        let s_shares = shamir::split(self.commitment.clone(), NUM_OF_AUDITORS, AUDITING_THRESHOLD, None)?;
        let coefficient = s_shares.coefficients.clone();
        let p_ys = s_shares.shares.iter().map(|p| p.y.clone()).collect::<Vec<_>>();
        let mut encrypted_shares = vec![];
        for (share, pk) in s_shares.shares.iter().zip(auditor_public_keys.iter()) {
            let encrypted_share = ecies::encrypt(&share.y, pk, &auditing_keys.random_sk);
            encrypted_shares.push(encrypted_share);
        }
        Ok(TransactionCommitmentShares::builder()
            .coefficient(coefficient)
            .shares(p_ys)
            .encrypted_shares(encrypted_shares)
            .build())
    }
}

#[derive(Debug, Clone, TypedBuilder)]
pub struct TransactionCommitmentOutput {
    pub commitment: BigUint,
    pub pk_verify: VerifyPk,
    pub random_p: RandomSk,
    pub random_r: RandomSk,
    pub random_s: RandomSk,
    pub amount: TxAmount,
    pub rollup_fee_amount: TxAmount,
}
#[derive(Debug, Clone, TypedBuilder)]
struct TransactionInputDetails {
    pub random_p: RandomSk,
    pub random_r: RandomSk,
    pub random_s: RandomSk,
    pub amount: TxAmount,
    pub nullifier: BigUint,
    pub sig_hash: BigUint,
    pub path_indices: Vec<bool>,
}

#[derive(Debug, Clone, TypedBuilder)]
struct TransactionCommitmentShares {
    pub coefficient: Vec<BigUint>,
    pub shares: Vec<BigUint>,
    pub encrypted_shares: Vec<BigUint>,
}

#[derive(Debug, Clone, TypedBuilder)]
struct AuditingKeys {
    pub random_sk: AuditingSk,
    pub random_pk: AuditingPk,
    pub random_unpacked_pk: AuditingUnpackedPublicKey,
    pub auditors: Vec<AuditingUnpackedPublicKey>,
}

#[derive(Debug, Clone, TypedBuilder)]
struct AuditingUnpackedPublicKey {
    pub x_signs: bool,
    pub x: AuditingPk,
    pub y: AuditingPk,
}

fn is_neg(key: &[u8]) -> bool {
    let key_big_int = BigUint::from_bytes_le(key);
    let field_size_half: BigUint = FIELD_SIZE.clone().shr(1);
    key_big_int.gt(&field_size_half)
}

fn clone_biguint_vec<T, F>(data: &[T], extractor: F) -> Vec<BigUint>
where
    F: Fn(&T) -> BigUint,
{
    data.iter().map(extractor).collect()
}

fn json_biguint(value: &BigUint) -> serde_json::Value {
    serde_json::json!(value.to_string())
}

fn json_biguint_vec(values: &[BigUint]) -> serde_json::Value {
    serde_json::json!(values.iter().map(|v| v.to_string()).collect::<Vec<_>>())
}

fn json_biguint_vec_vec(values: &[Vec<BigUint>]) -> serde_json::Value {
    serde_json::json!(values
        .iter()
        .map(|v| v.iter().map(|v| v.to_string()).collect::<Vec<_>>())
        .collect::<Vec<_>>())
}
