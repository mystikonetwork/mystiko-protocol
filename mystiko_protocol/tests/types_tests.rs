use num_bigint::BigUint;

use mystiko_protocol::commitment::Note;

#[tokio::test]
async fn test_decrypted_note() {
    let note = Note::new(Some(BigUint::from(10u32)), None).unwrap();
    let enc_vec = note.to_vec().unwrap();
    let note_dec = Note::from_vec(enc_vec).unwrap();
    assert_eq!(note, note_dec);
}
