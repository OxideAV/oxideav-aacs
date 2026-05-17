//! MKB parser tests against hand-crafted byte streams built from the
//! AACS Common spec §3.2.5 record definitions.

use oxideav_aacs::{aes_g3, Mkb, MkbType};

fn write_record(tag: u8, body: &[u8]) -> Vec<u8> {
    let length = 4 + body.len();
    assert!(length <= 0xFF_FFFF);
    let mut out = vec![
        tag,
        ((length >> 16) & 0xFF) as u8,
        ((length >> 8) & 0xFF) as u8,
        (length & 0xFF) as u8,
    ];
    out.extend_from_slice(body);
    out
}

#[test]
fn parses_full_type3_mkb() {
    let mut bytes = Vec::new();

    // Type-and-Version: MKBType = 0x00031003 (Type 3), Version = 42.
    let mut tv = Vec::new();
    tv.extend_from_slice(&0x0003_1003u32.to_be_bytes());
    tv.extend_from_slice(&42u32.to_be_bytes());
    bytes.extend(write_record(0x10, &tv));

    // Host Revocation List: 0 total entries, but include the header
    // structure: total=0, block-of-0 entries, 40-byte signature.
    let mut hrl = Vec::new();
    hrl.extend_from_slice(&0u32.to_be_bytes()); // Total Number of Entries
    hrl.extend_from_slice(&0u32.to_be_bytes()); // N1 = 0 in first block
    hrl.extend_from_slice(&[0u8; 40]); // signature
    bytes.extend(write_record(0x21, &hrl));

    // Drive Revocation List: same shape but with one entry.
    let mut drl = Vec::new();
    drl.extend_from_slice(&1u32.to_be_bytes()); // Total = 1
    drl.extend_from_slice(&1u32.to_be_bytes()); // N1 = 1
    drl.extend_from_slice(&0x0010u16.to_be_bytes()); // range = 16
    drl.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34]); // drive id
    drl.extend_from_slice(&[0u8; 40]); // signature
    bytes.extend(write_record(0x20, &drl));

    // Verify Media Key Record: precompute a Vd that matches our Km.
    let km = [0x55u8; 16];
    let known_plaintext = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA,
        0xBE,
    ];
    let vd = oxideav_aacs::aes::aes_128_ecb_encrypt(&km, &known_plaintext);
    bytes.extend(write_record(0x81, &vd));

    // Explicit Subset-Difference: two entries.
    let mut esd = Vec::new();
    esd.extend_from_slice(&[0x01, 0x12, 0x34, 0x56, 0x78]);
    esd.extend_from_slice(&[0x02, 0x9A, 0xBC, 0xDE, 0xF0]);
    bytes.extend(write_record(0x04, &esd));

    // Media Key Data: two entries matching the explicit subdiff.
    let mut mkd = Vec::new();
    mkd.extend_from_slice(&[0x10u8; 16]);
    mkd.extend_from_slice(&[0x20u8; 16]);
    bytes.extend(write_record(0x05, &mkd));

    // End-of-MKB Record.
    bytes.extend(write_record(0x02, &[0u8; 40]));

    let mkb = Mkb::parse(&bytes).unwrap();
    assert_eq!(mkb.mkb_type, Some(MkbType::Type3));
    assert_eq!(mkb.version, 42);
    assert!(mkb.host_revocation_list.is_empty());
    assert_eq!(mkb.drive_revocation_list.len(), 1);
    assert_eq!(mkb.drive_revocation_list[0].range, 16);
    assert_eq!(
        mkb.drive_revocation_list[0].id,
        [0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34]
    );
    assert_eq!(mkb.verify_media_key.unwrap(), vd);
    assert_eq!(mkb.explicit_subdiff.len(), 2);
    assert_eq!(mkb.media_key_data.len(), 2);
    assert!(mkb.end_of_block);

    // Verify_media_key cross-check.
    mkb.verify_media_key(&km).unwrap();
    let mut flipped = km;
    flipped[0] ^= 1;
    assert!(mkb.verify_media_key(&flipped).is_err());
}

#[test]
fn aes_g3_outputs_match_step_formula() {
    // Cross-check that aes_g3 against an empirical reference:
    // re-derive each output by stepping AES-128D + XOR ourselves.
    let dk = [0x77u8; 16];
    let out = aes_g3(&dk);
    let mut s0 = oxideav_aacs::subdiff::AES_G3_SEED_S0;
    for (i, expected) in [out.left_child, out.processing_key, out.right_child]
        .iter()
        .enumerate()
    {
        let mut s = s0;
        // Add i to s (big-endian 128-bit).
        let cur = u128::from_be_bytes(s);
        s = (cur.wrapping_add(i as u128)).to_be_bytes();
        let d = oxideav_aacs::aes::aes_128_ecb_decrypt(&dk, &s);
        let mut ref_ = [0u8; 16];
        for j in 0..16 {
            ref_[j] = d[j] ^ s[j];
        }
        assert_eq!(&ref_, expected, "AES-G3 step {i} mismatch");
        // s0 stays constant across iterations — we add `i` from it each time.
        let _ = &mut s0;
    }
}
