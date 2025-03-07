extern crate k256;
extern crate mystiko_crypto;
extern crate rand_core;

use k256::SecretKey;
use rand_core::OsRng;

use mystiko_crypto::eccrypto::{decrypt, encrypt, equal_const_time, public_key_to_vec, ECCryptoData};
use mystiko_crypto::error::CryptoError;
use mystiko_crypto::utils::random_bytes;

#[tokio::test]
async fn test_equal_const_time() {
    let b1 = [1, 2, 3];
    let b2 = [1, 2, 3, 4, 5, 6];
    assert!(!equal_const_time(&b1, &b2))
}

#[tokio::test]
async fn test_random_data() {
    let mut rng = OsRng;
    let sk = SecretKey::random(&mut rng);
    let pk = sk.public_key();
    let pk = public_key_to_vec(&pk, true);

    let text = random_bytes(80);
    let data = encrypt(pk.as_slice(), text.as_slice()).unwrap();
    let dec_text = decrypt(sk.to_bytes().to_vec().as_slice(), &data).unwrap();
    assert_eq!(text, dec_text);

    let ec_data = ECCryptoData::from_bytes(data.as_slice()).unwrap();
    let ec_data2 = ec_data;
    let ec_data3 = ECCryptoData::from_bytes(&ec_data2.to_vec().as_slice()[0..2]);
    assert!(matches!(ec_data3.err().unwrap(), CryptoError::DataLengthError));

    let data = encrypt(&pk.as_slice()[0..32], text.as_slice());
    assert!(matches!(data.err().unwrap(), CryptoError::KeyLengthError));

    let data = vec![1, 2, 3];
    let dec_text = decrypt(sk.to_bytes().to_vec().as_slice(), &data);
    assert!(matches!(dec_text.err().unwrap(), CryptoError::DataLengthError));
}

#[tokio::test]
async fn test_decrypt_compatible_with_js() {
    let sk = SecretKey::from_slice(b"98765432101234567890123456789012").unwrap();
    let text = b"mystiko is awesome";

    let js_dec_data: &[u8] = &[
        0x91, 0x93, 0x06, 0xFC, 0x77, 0xF9, 0xAA, 0x65, 0xFA, 0xF9, 0x77, 0x30, 0xDF, 0x13, 0x35, 0x82, 0x04, 0xDA,
        0xE8, 0x38, 0x3F, 0x49, 0xCF, 0x70, 0x50, 0x86, 0x0B, 0x85, 0x13, 0x3A, 0x03, 0x22, 0x25, 0xB7, 0xFA, 0x28,
        0x7F, 0x6E, 0xFE, 0xCD, 0xAD, 0xDB, 0xC5, 0x6F, 0x3C, 0xBF, 0x08, 0x04, 0x29, 0xAA, 0x01, 0xAC, 0xDA, 0x08,
        0x3C, 0xAA, 0xB3, 0xC4, 0x41, 0xD6, 0xA5, 0x0B, 0x98, 0x6F, 0xD4, 0x50, 0xF1, 0xC7, 0xCC, 0x3B, 0x76, 0x00,
        0xB8, 0x47, 0x41, 0x64, 0x5E, 0x59, 0x15, 0x58, 0xFA, 0xF8, 0x9F, 0x3B, 0x96, 0xFF, 0xD2, 0xBC, 0x96, 0x50,
        0x24, 0x99, 0x6E, 0x7F, 0x4E, 0x28, 0xEE, 0x06, 0xC0, 0x32, 0xF4, 0x10, 0xD7, 0xC1, 0xC4, 0x4F, 0x87, 0x83,
        0xDA, 0x1B, 0x48, 0xB1, 0x74, 0x0D, 0x8C, 0x1C, 0x18, 0xD7, 0x9C, 0x29, 0x4A, 0xE3, 0xFC, 0xCF, 0x68, 0xF9,
        0x68, 0x6A, 0x1C, 0xC4, 0x41, 0x3E, 0xCA, 0x2C, 0x0E, 0xDD, 0x34, 0x18, 0xAB, 0xE7, 0x97, 0x67, 0x1B, 0x6A,
        0x97,
    ];
    let dec_text = decrypt(sk.to_bytes().to_vec().as_slice(), js_dec_data).unwrap();
    assert_eq!(text, dec_text.as_slice());
}

#[tokio::test]
async fn test_decrypt_compatible_with_js_by_leading_zeros() {
    use ff::hex;
    let sk = SecretKey::from_slice(b"98765432101234567890123456789012").unwrap();
    let text = hex::decode("e20a031ae3479c59b0a95119a5d06373e4177673e3b95f7189a456fee40a").unwrap();
    let js_enc_data = hex::decode(
        "db531f7f93fe850fbc2e2b28fcb0ebf5049c223ea8fb5d9cb9d937187bd6885fd1888809\
        70fbda4ce14406e83510c0539fbf06d69c86e927c247962312ac8a504bf14b0ef16125087\
        3c15b7cec79ad72b740414f721c89dbd906b36bbc394aa9b3e8037b561ac4e2b72e9f0f04\
        44770a10e7e9fedf7045b25077ea8b31115b323a0c7278e4a9b66e6a8f6045e9147c3b38",
    )
    .unwrap();
    let dec_text = decrypt(sk.to_bytes().to_vec().as_slice(), js_enc_data.to_vec().as_slice()).unwrap();
    assert_eq!(dec_text, text);
}
