//! Content scrambling roundtrip tests.

use oxideav_aacs::{decrypt_aligned_unit, encrypt_aligned_unit, AacsError, ALIGNED_UNIT_SIZE};

fn deterministic(seed: u8, n: usize) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_add(seed)).collect()
}

#[test]
fn encrypt_then_decrypt_recovers_plaintext() {
    let cps_unit_key = [0x37u8; 16];
    let plaintext = deterministic(0xA5, ALIGNED_UNIT_SIZE);
    let ct = encrypt_aligned_unit(&cps_unit_key, &plaintext).unwrap();
    let rt = decrypt_aligned_unit(&cps_unit_key, &ct).unwrap();
    assert_eq!(&rt[..], &plaintext[..]);
}

#[test]
fn seed_passes_through_encryption() {
    let cps_unit_key = [0x12u8; 16];
    let plaintext = deterministic(0xCC, ALIGNED_UNIT_SIZE);
    let ct = encrypt_aligned_unit(&cps_unit_key, &plaintext).unwrap();
    // First 16 bytes are clear.
    assert_eq!(&ct[..16], &plaintext[..16]);
    // Body must differ from plaintext (very unlikely to coincide).
    assert_ne!(&ct[16..], &plaintext[16..]);
}

#[test]
fn ciphertext_bitflip_perturbs_decryption() {
    let cps_unit_key = [0xFFu8; 16];
    let plaintext = deterministic(0x10, ALIGNED_UNIT_SIZE);
    let mut ct = encrypt_aligned_unit(&cps_unit_key, &plaintext).unwrap();
    ct[1024] ^= 1;
    let rt = decrypt_aligned_unit(&cps_unit_key, &ct).unwrap();
    assert_ne!(&rt[..], &plaintext[..]);
}

#[test]
fn rejects_wrong_size() {
    let key = [0u8; 16];
    let bad = vec![0u8; 1000];
    assert!(matches!(
        decrypt_aligned_unit(&key, &bad),
        Err(AacsError::BadAlignedUnitLength(1000))
    ));
}

#[test]
fn wrong_key_does_not_recover_plaintext() {
    let cps_unit_key = [0x37u8; 16];
    let wrong_key = [0x38u8; 16];
    let plaintext = deterministic(0xA5, ALIGNED_UNIT_SIZE);
    let ct = encrypt_aligned_unit(&cps_unit_key, &plaintext).unwrap();
    let rt = decrypt_aligned_unit(&wrong_key, &ct).unwrap();
    // Seed survives (it's clear), but the body cannot.
    assert_eq!(&rt[..16], &plaintext[..16]);
    assert_ne!(&rt[16..], &plaintext[16..]);
}
