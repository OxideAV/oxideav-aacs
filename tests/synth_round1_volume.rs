//! End-to-end volume test: build a synthetic AACS/ directory tree
//! under a tempdir, open it through `AacsVolume::open`, unwrap title
//! keys via a VUK, and decrypt a freshly-encrypted Aligned Unit back
//! to the original plaintext.

use oxideav_aacs::{encrypt_aligned_unit, AacsVolume, Vuk, ALIGNED_UNIT_SIZE};
use std::fs;

fn write_record(tag: u8, body: &[u8]) -> Vec<u8> {
    let length = 4 + body.len();
    let mut out = vec![
        tag,
        ((length >> 16) & 0xFF) as u8,
        ((length >> 8) & 0xFF) as u8,
        (length & 0xFF) as u8,
    ];
    out.extend_from_slice(body);
    out
}

fn build_mkb() -> Vec<u8> {
    let mut bytes = Vec::new();
    // Type and Version (Type 3, version 1).
    let mut tv = Vec::new();
    tv.extend_from_slice(&0x0003_1003u32.to_be_bytes());
    tv.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend(write_record(0x10, &tv));
    // Verify Media Key Record (dummy 16 bytes — we won't verify in
    // this test since we're using KEYDB.cfg-style VUK delivery).
    bytes.extend(write_record(0x81, &[0u8; 16]));
    // End of MKB.
    bytes.extend(write_record(0x02, &[0u8; 40]));
    bytes
}

fn build_unit_key_file(vuk: &Vuk, title_keys: &[[u8; 16]]) -> Vec<u8> {
    let kbs: u32 = 0x80;
    let mut out = vec![0u8; kbs as usize];
    out[0..4].copy_from_slice(&kbs.to_be_bytes());
    out[16] = 0x01;
    out[17] = 0x01;
    out[18] = 0x00;
    out[19] = 0x00;
    out[20..22].copy_from_slice(&1u16.to_be_bytes());
    out[22..24].copy_from_slice(&1u16.to_be_bytes());
    out[24..26].copy_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&(title_keys.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0u8; 14]);
    for tk in title_keys {
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&[0u8; 16]);
        let enc = oxideav_aacs::aes::aes_128_ecb_encrypt(vuk.as_bytes(), tk);
        out.extend_from_slice(&enc);
    }
    out
}

#[test]
fn open_walk_unwrap_decrypt_roundtrip() {
    let vuk = Vuk::from_bytes([0x44u8; 16]);
    let title_key = [0x99u8; 16];

    let tmp = tempfile::tempdir().unwrap();
    let aacs_dir = tmp.path().join("AACS");
    fs::create_dir_all(&aacs_dir).unwrap();
    fs::write(aacs_dir.join("MKB_RO.inf"), build_mkb()).unwrap();
    fs::write(
        aacs_dir.join("Unit_Key_RO.inf"),
        build_unit_key_file(&vuk, &[title_key]),
    )
    .unwrap();

    let mut vol = AacsVolume::open(tmp.path()).unwrap();
    assert_eq!(vol.cps_units.len(), 1);
    vol.unwrap_title_keys(&vuk).unwrap();
    let cps = vol.cps_units[0];
    assert_eq!(cps.title_key.unwrap().0, title_key);

    // Freshly-encrypted Aligned Unit roundtrips through decrypt_unit.
    let plaintext: Vec<u8> = (0..ALIGNED_UNIT_SIZE).map(|i| (i % 7) as u8).collect();
    let ct = encrypt_aligned_unit(&title_key, &plaintext).unwrap();
    let pt = vol.decrypt_unit(&cps, &ct).unwrap();
    assert_eq!(&pt[..], &plaintext[..]);
}

#[test]
fn falls_back_to_duplicate_directory() {
    let vuk = Vuk::from_bytes([0x55u8; 16]);
    let title_key = [0x77u8; 16];

    let tmp = tempfile::tempdir().unwrap();
    let dup_dir = tmp.path().join("AACS").join("DUPLICATE");
    fs::create_dir_all(&dup_dir).unwrap();
    fs::write(dup_dir.join("MKB_RO.inf"), build_mkb()).unwrap();
    fs::write(
        dup_dir.join("Unit_Key_RO.inf"),
        build_unit_key_file(&vuk, &[title_key]),
    )
    .unwrap();

    // No primary files present — must still open via DUPLICATE/.
    let vol = AacsVolume::open(tmp.path()).unwrap();
    assert_eq!(vol.cps_units.len(), 1);
}

#[test]
fn missing_disc_layout_errors() {
    let tmp = tempfile::tempdir().unwrap();
    // No AACS dir at all.
    let err = AacsVolume::open(tmp.path()).unwrap_err();
    match err {
        oxideav_aacs::AacsError::MissingDiscFile(name) => assert_eq!(name, "MKB_RO.inf"),
        other => panic!("unexpected: {other:?}"),
    }
}
