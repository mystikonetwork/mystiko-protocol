use num_bigint::BigUint;
use std::sync::Arc;

use mystiko_crypto::merkle_tree::MerkleTree;
use mystiko_crypto::zkp::proof::G16Prover;
use mystiko_crypto::zkp::ZKProver;
use mystiko_fs::{read_file_bytes, read_gzip_file_bytes};
use mystiko_protocol::rollup::Rollup;

const FILE_PATH: &str = "./../mystiko_circuits/dist/zokrates/dev";

#[tokio::test]
async fn test_rollup1() {
    let in_initial_elements = vec![BigUint::from(100u32), BigUint::from(200u32), BigUint::from(300u32)];
    let in_initial_elements_count = in_initial_elements.len();
    let mut tree = MerkleTree::new(Some(in_initial_elements), None, None).unwrap();
    let new_leaves = vec![BigUint::from(1u32)];
    let new_leaves_count = new_leaves.len();
    let program = read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Rollup1.program.gz"))
        .await
        .unwrap();
    let abi = read_file_bytes(&format!("{}/{}", FILE_PATH, "/Rollup1.abi.json"))
        .await
        .unwrap();
    let pkey = read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Rollup1.pkey.gz"))
        .await
        .unwrap();

    assert_eq!(tree.count(), in_initial_elements_count);
    let mut rollup = Rollup::builder()
        .tree(&mut tree)
        .new_leaves(new_leaves)
        .program(program)
        .abi(abi)
        .proving_key(pkey)
        .build();

    let prover = Arc::new(G16Prover);
    let r = rollup.prove(prover.clone()).unwrap();
    let vk = read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Rollup1.vkey.gz"))
        .await
        .unwrap();
    let options = mystiko_crypto::zkp::ZKVerifyOptions::builder()
        .proof(&r.zk_proof)
        .verification_key(vk.as_slice())
        .build();
    let verify = prover.verify(&options).unwrap();
    assert!(verify);
    assert_eq!(tree.count(), in_initial_elements_count + new_leaves_count);
}

#[tokio::test]
async fn test_rollup2() {
    let in_initial_elements = vec![BigUint::from(100u32), BigUint::from(200u32)];
    let in_initial_elements_count = in_initial_elements.len();
    let mut tree = MerkleTree::new(Some(in_initial_elements), None, None).unwrap();
    let new_leaves = vec![BigUint::from(1u32), BigUint::from(2u32)];
    let new_leaves_count = new_leaves.len();
    let program = read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Rollup2.program.gz"))
        .await
        .unwrap();
    let abi = read_file_bytes(&format!("{}/{}", FILE_PATH, "/Rollup2.abi.json"))
        .await
        .unwrap();
    let pkey = read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Rollup2.pkey.gz"))
        .await
        .unwrap();

    assert_eq!(tree.count(), in_initial_elements_count);
    let mut rollup = Rollup::builder()
        .tree(&mut tree)
        .new_leaves(new_leaves)
        .program(program)
        .abi(abi)
        .proving_key(pkey)
        .build();
    let prover = Arc::new(G16Prover);
    let r = rollup.prove(prover.clone()).unwrap();
    let vk = read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Rollup2.vkey.gz"))
        .await
        .unwrap();
    let options = mystiko_crypto::zkp::ZKVerifyOptions::builder()
        .proof(&r.zk_proof)
        .verification_key(vk.as_slice())
        .build();
    let verify = prover.verify(&options).unwrap();
    assert!(verify);
    assert_eq!(tree.count(), in_initial_elements_count + new_leaves_count);
}

#[tokio::test]
async fn test_rollup4() {
    let in_initial_elements = (100u32..=400u32)
        .step_by(100)
        .map(BigUint::from)
        .collect::<Vec<BigUint>>();
    let in_initial_elements_count = in_initial_elements.len();
    let new_leaves = (1u32..=4u32).map(BigUint::from).collect::<Vec<BigUint>>();
    let new_leaves_count = new_leaves.len();
    let mut tree = MerkleTree::new(Some(in_initial_elements), None, None).unwrap();
    let program = read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Rollup4.program.gz"))
        .await
        .unwrap();
    let abi = read_file_bytes(&format!("{}/{}", FILE_PATH, "/Rollup4.abi.json"))
        .await
        .unwrap();
    let pkey = read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Rollup4.pkey.gz"))
        .await
        .unwrap();

    assert_eq!(tree.count(), in_initial_elements_count);
    let mut rollup = Rollup::builder()
        .tree(&mut tree)
        .new_leaves(new_leaves)
        .program(program)
        .abi(abi)
        .proving_key(pkey)
        .build();
    let prover = Arc::new(G16Prover);
    let r = rollup.prove(prover.clone()).unwrap();
    let vk = read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Rollup4.vkey.gz"))
        .await
        .unwrap();
    let options = mystiko_crypto::zkp::ZKVerifyOptions::builder()
        .proof(&r.zk_proof)
        .verification_key(vk.as_slice())
        .build();
    let verify = prover.verify(&options).unwrap();
    assert!(verify);
    assert_eq!(tree.count(), in_initial_elements_count + new_leaves_count);
}

#[tokio::test]
async fn test_rollup8() {
    let in_initial_elements = (100u32..=800u32)
        .step_by(100)
        .map(BigUint::from)
        .collect::<Vec<BigUint>>();
    let in_initial_elements_count = in_initial_elements.len();
    let new_leaves = (1u32..=8u32).map(BigUint::from).collect::<Vec<BigUint>>();
    let new_leaves_count = new_leaves.len();
    let mut tree = MerkleTree::new(Some(in_initial_elements), None, None).unwrap();
    let program = read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Rollup8.program.gz"))
        .await
        .unwrap();
    let abi = read_file_bytes(&format!("{}/{}", FILE_PATH, "/Rollup8.abi.json"))
        .await
        .unwrap();
    let pkey = read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Rollup8.pkey.gz"))
        .await
        .unwrap();

    assert_eq!(tree.count(), in_initial_elements_count);
    let mut rollup = Rollup::builder()
        .tree(&mut tree)
        .new_leaves(new_leaves)
        .program(program)
        .abi(abi)
        .proving_key(pkey)
        .build();
    let prover = Arc::new(G16Prover);
    let r = rollup.prove(prover.clone()).unwrap();
    let vk = read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Rollup8.vkey.gz"))
        .await
        .unwrap();
    let options = mystiko_crypto::zkp::ZKVerifyOptions::builder()
        .proof(&r.zk_proof)
        .verification_key(vk.as_slice())
        .build();
    let verify = prover.verify(&options).unwrap();
    assert!(verify);
    assert_eq!(tree.count(), in_initial_elements_count + new_leaves_count);
}

#[tokio::test]
async fn test_rollup16() {
    let in_initial_elements = (100u32..=1600u32)
        .step_by(100)
        .map(BigUint::from)
        .collect::<Vec<BigUint>>();
    let in_initial_elements_count = in_initial_elements.len();
    let new_leaves = (1u32..=16u32).map(BigUint::from).collect::<Vec<BigUint>>();
    let new_leaves_count = new_leaves.len();
    let mut tree = MerkleTree::new(Some(in_initial_elements), None, None).unwrap();
    let program = read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Rollup16.program.gz"))
        .await
        .unwrap();
    let abi = read_file_bytes(&format!("{}/{}", FILE_PATH, "/Rollup16.abi.json"))
        .await
        .unwrap();
    let pkey = read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Rollup16.pkey.gz"))
        .await
        .unwrap();

    assert_eq!(tree.count(), in_initial_elements_count);
    let mut rollup = Rollup::builder()
        .tree(&mut tree)
        .new_leaves(new_leaves)
        .program(program)
        .abi(abi)
        .proving_key(pkey)
        .build();
    let prover = Arc::new(G16Prover);
    let r = rollup.prove(prover.clone()).unwrap();
    let vk = read_gzip_file_bytes(&format!("{}/{}", FILE_PATH, "/Rollup16.vkey.gz"))
        .await
        .unwrap();
    let options = mystiko_crypto::zkp::ZKVerifyOptions::builder()
        .proof(&r.zk_proof)
        .verification_key(vk.as_slice())
        .build();
    let verify = prover.verify(&options).unwrap();
    assert!(verify);
    assert_eq!(tree.count(), in_initial_elements_count + new_leaves_count);
}
