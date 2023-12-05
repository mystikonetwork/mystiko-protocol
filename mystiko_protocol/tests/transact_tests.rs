use ethers_core::rand::thread_rng;
use ethers_core::types::U256;
use ethers_signers::{LocalWallet, Signer};
use mystiko_crypto::ecies;
use mystiko_crypto::merkle_tree::MerkleTree;
use mystiko_crypto::utils::random_bytes;
use mystiko_crypto::zkp::proof::{G16Proof, G16Prover};
use mystiko_crypto::zkp::ZKProver;
use mystiko_fs::{read_file_bytes, read_gzip_file_bytes};
use mystiko_protocol::address::ShieldedAddress;
use mystiko_protocol::commitment::{Commitment, Note};
use mystiko_protocol::key::{
    encryption_public_key, encryption_secret_key, verification_public_key, verification_secret_key,
};
use mystiko_protocol::transact::{Transaction, TransactionCommitmentInput, TransactionCommitmentOutput};
use mystiko_protocol::types::{AuditingPk, SigPk, NUM_OF_AUDITORS};
use mystiko_protocol::types::{ENC_SK_SIZE, MERKLE_TREE_LEVELS, VERIFY_SK_SIZE};
use num_bigint::BigUint;
use num_traits::identities::Zero;
use std::ops::Sub;
use std::sync::Arc;

fn generate_eth_address() -> SigPk {
    let wallet = LocalWallet::new(&mut thread_rng());
    let wallet = wallet.with_chain_id(1u64);
    wallet.address().as_bytes().try_into().unwrap()
}

fn u256_to_big_int(u: &U256) -> BigUint {
    let mut arr = [0u8; 32];
    u.to_little_endian(&mut arr[..]);
    BigUint::from_bytes_le(&arr[..])
}

fn generate_transaction(
    num_inputs: u32,
    num_outputs: u32,
    program: Vec<u8>,
    abi: Vec<u8>,
    proving_key: Vec<u8>,
    generate_auditing_key: Option<bool>,
) -> Transaction {
    let in_amount = u256_to_big_int(&ethers_core::utils::parse_ether("200").unwrap());
    let out_amount = u256_to_big_int(&ethers_core::utils::parse_ether("50").unwrap());
    let rollup_fee_amount = u256_to_big_int(&ethers_core::utils::parse_ether("10").unwrap());
    let relayer_fee_amount = u256_to_big_int(&ethers_core::utils::parse_ether("20").unwrap());

    let mut inputs = vec![];
    let mut in_amounts = vec![];
    for _ in 0..num_inputs as usize {
        let raw_verify_sk = random_bytes(VERIFY_SK_SIZE);
        let raw_enc_sk = random_bytes(ENC_SK_SIZE);
        let sk_verify = verification_secret_key(raw_verify_sk.as_slice().try_into().unwrap()).unwrap();
        let pk_verify = verification_public_key(raw_verify_sk.as_slice().try_into().unwrap()).unwrap();
        let sk_enc = encryption_secret_key(raw_enc_sk.as_slice().try_into().unwrap());
        let pk_enc = encryption_public_key(raw_enc_sk.as_slice().try_into().unwrap()).unwrap();
        let cm = Commitment::new(
            ShieldedAddress::from_public_key(&pk_verify, &pk_enc),
            Some(Note::new(Some(in_amount.clone()), None).unwrap()),
            None,
        )
        .unwrap();
        in_amounts.push(in_amount.clone());
        inputs.push(
            TransactionCommitmentInput::builder()
                .commitment(cm.commitment_hash)
                .private_note(cm.encrypted_note)
                .path_elements(vec![])
                .path_indices(vec![])
                .pk_verify(pk_verify)
                .sk_verify(sk_verify)
                .pk_enc(pk_enc)
                .sk_enc(sk_enc)
                .build(),
        );
    }
    let in_commitments = inputs.iter().map(|x| x.commitment.clone()).collect();
    let merkle_tree = MerkleTree::new(Some(in_commitments), Some(MERKLE_TREE_LEVELS), None).unwrap();
    for (i, input) in inputs.iter_mut().enumerate().take(num_inputs as usize) {
        let path = merkle_tree.path(i).unwrap();
        input.path_elements = path.0;
        input.path_indices = path.1;
    }

    let mut out_amounts = vec![];
    let mut rollup_fee_amounts = vec![];
    let mut outputs = vec![];
    for _ in 0..num_outputs as usize {
        let raw_verify_sk = random_bytes(VERIFY_SK_SIZE);
        let raw_enc_sk = random_bytes(ENC_SK_SIZE);
        let pk_verify = verification_public_key(raw_verify_sk.as_slice().try_into().unwrap()).unwrap();
        let pk_enc = encryption_public_key(raw_enc_sk.as_slice().try_into().unwrap()).unwrap();
        let cm = Commitment::new(
            ShieldedAddress::from_public_key(&pk_verify, &pk_enc),
            Some(Note::new(Some(out_amount.clone()), None).unwrap()),
            None,
        )
        .unwrap();

        out_amounts.push(out_amount.clone());
        rollup_fee_amounts.push(rollup_fee_amount.clone());
        outputs.push(
            TransactionCommitmentOutput::builder()
                .commitment(cm.commitment_hash.clone())
                .pk_verify(pk_verify)
                .amount(out_amount.clone())
                .random_p(cm.note.random_p)
                .random_r(cm.note.random_r)
                .random_s(cm.note.random_s)
                .rollup_fee_amount(rollup_fee_amount.clone())
                .build(),
        )
    }

    let sig_pk = generate_eth_address();

    let total_in = in_amounts.iter().fold(BigUint::zero(), |acc, x| acc + x);
    let total_out = out_amounts.iter().fold(BigUint::zero(), |acc, x| acc + x);
    let total_rollup_fee = rollup_fee_amounts.iter().fold(BigUint::zero(), |acc, x| acc + x);

    let public_amount = total_in
        .sub(total_out)
        .sub(total_rollup_fee)
        .sub(relayer_fee_amount.clone());

    let random_auditing_secret_key = if generate_auditing_key.unwrap_or(false) {
        Some(ecies::generate_secret_key())
    } else {
        None
    };

    let mut auditor_public_keys: Vec<AuditingPk> = vec![];
    for _ in 0..NUM_OF_AUDITORS {
        let pk = ecies::public_key(&ecies::generate_secret_key());
        auditor_public_keys.push(pk);
    }

    Transaction::builder()
        .inputs(inputs)
        .outputs(outputs)
        .tree_root(merkle_tree.root())
        .sig_pk(sig_pk)
        .public_amount(public_amount)
        .relayer_fee_amount(relayer_fee_amount)
        .random_auditing_secret_key(random_auditing_secret_key)
        .auditor_public_keys(auditor_public_keys.clone())
        .program(program)
        .abi(abi)
        .proving_key(proving_key)
        .build()
}

const FILE_PATH: &str = "./../mystiko_circuits/dist/zokrates/dev";

#[tokio::test]
async fn test_transaction1x0() {
    let tx = generate_transaction(
        1u32,
        0u32,
        read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Transaction1x0.program.gz"))
            .await
            .unwrap(),
        read_file_bytes(&format!("{}/{}", FILE_PATH, "/Transaction1x0.abi.json"))
            .await
            .unwrap(),
        read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Transaction1x0.pkey.gz"))
            .await
            .unwrap(),
        None,
    );
    let prover = Arc::new(G16Prover);
    let proof = tx.prove::<G16Prover, G16Proof>(prover.clone()).unwrap();
    let vk = read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Transaction1x0.vkey.gz"))
        .await
        .unwrap();
    let options = mystiko_crypto::zkp::ZKVerifyOptions::builder()
        .proof(&proof.proof)
        .verification_key(vk.as_slice())
        .build();
    let verify = prover.verify(&options).unwrap();
    assert!(verify);
}

#[tokio::test]
async fn test_transaction1x1() {
    let tx = generate_transaction(
        1u32,
        1u32,
        read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Transaction1x1.program.gz"))
            .await
            .unwrap(),
        read_file_bytes(&format!("{}/{}", FILE_PATH, "/Transaction1x1.abi.json"))
            .await
            .unwrap(),
        read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Transaction1x1.pkey.gz"))
            .await
            .unwrap(),
        Some(true),
    );
    let prover = Arc::new(G16Prover);
    let proof = tx.prove::<G16Prover, G16Proof>(prover.clone()).unwrap();
    let vk = read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Transaction1x1.vkey.gz"))
        .await
        .unwrap();
    let options = mystiko_crypto::zkp::ZKVerifyOptions::builder()
        .proof(&proof.proof)
        .verification_key(vk.as_slice())
        .build();
    let verify = prover.verify(&options).unwrap();
    assert!(verify);
}

#[tokio::test]
async fn test_transaction1x2() {
    let tx = generate_transaction(
        1u32,
        2u32,
        read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Transaction1x2.program.gz"))
            .await
            .unwrap(),
        read_file_bytes(&format!("{}/{}", FILE_PATH, "/Transaction1x2.abi.json"))
            .await
            .unwrap(),
        read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Transaction1x2.pkey.gz"))
            .await
            .unwrap(),
        Some(true),
    );

    let prover = Arc::new(G16Prover);
    let proof = tx.prove::<G16Prover, G16Proof>(prover.clone()).unwrap();
    let vk = read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Transaction1x2.vkey.gz"))
        .await
        .unwrap();
    let options = mystiko_crypto::zkp::ZKVerifyOptions::builder()
        .proof(&proof.proof)
        .verification_key(vk.as_slice())
        .build();
    let verify = prover.verify(&options).unwrap();
    assert!(verify);
}

#[tokio::test]
async fn test_transaction2x0() {
    let tx = generate_transaction(
        2u32,
        0u32,
        read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Transaction2x0.program.gz"))
            .await
            .unwrap(),
        read_file_bytes(&format!("{}/{}", FILE_PATH, "/Transaction2x0.abi.json"))
            .await
            .unwrap(),
        read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Transaction2x0.pkey.gz"))
            .await
            .unwrap(),
        Some(true),
    );

    let prover = Arc::new(G16Prover);
    let proof = tx.prove::<G16Prover, G16Proof>(prover.clone()).unwrap();
    let vk = read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Transaction2x0.vkey.gz"))
        .await
        .unwrap();
    let options = mystiko_crypto::zkp::ZKVerifyOptions::builder()
        .proof(&proof.proof)
        .verification_key(vk.as_slice())
        .build();
    let verify = prover.verify(&options).unwrap();
    assert!(verify);
}

#[tokio::test]
async fn test_transaction2x1() {
    let tx = generate_transaction(
        2u32,
        1u32,
        read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Transaction2x1.program.gz"))
            .await
            .unwrap(),
        read_file_bytes(&format!("{}/{}", FILE_PATH, "/Transaction2x1.abi.json"))
            .await
            .unwrap(),
        read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Transaction2x1.pkey.gz"))
            .await
            .unwrap(),
        Some(true),
    );

    let prover = Arc::new(G16Prover);
    let proof = tx.prove::<G16Prover, G16Proof>(prover.clone()).unwrap();
    let vk = read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Transaction2x1.vkey.gz"))
        .await
        .unwrap();
    let options = mystiko_crypto::zkp::ZKVerifyOptions::builder()
        .proof(&proof.proof)
        .verification_key(vk.as_slice())
        .build();
    let verify = prover.verify(&options).unwrap();
    assert!(verify);
}

#[tokio::test]
async fn test_transaction2x2() {
    let tx = generate_transaction(
        2u32,
        2u32,
        read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Transaction2x2.program.gz"))
            .await
            .unwrap(),
        read_file_bytes(&format!("{}/{}", FILE_PATH, "/Transaction2x2.abi.json"))
            .await
            .unwrap(),
        read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Transaction2x2.pkey.gz"))
            .await
            .unwrap(),
        Some(true),
    );

    let prover = Arc::new(G16Prover);
    let proof = tx.prove::<G16Prover, G16Proof>(prover.clone()).unwrap();
    let vk = read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Transaction2x2.vkey.gz"))
        .await
        .unwrap();
    let options = mystiko_crypto::zkp::ZKVerifyOptions::builder()
        .proof(&proof.proof)
        .verification_key(vk.as_slice())
        .build();
    let verify = prover.verify(&options).unwrap();
    assert!(verify);
    let _ = tx.clone();
}
