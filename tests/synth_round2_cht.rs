//! Integration tests for the Content Hash Table layer
//! (`oxideav_aacs::cht`) per AACS BD-Prerecorded Final 0.953 §2.3.
//!
//! All fixtures are synthetic: a `tempdir()` `AACS/` directory holds a
//! `ContentHash000.tbl` (and optionally `ContentHash001.tbl`) crafted
//! by `synth_cht_bytes` below, paired with the minimum-viable
//! `MKB_RO.inf` + `Unit_Key_RO.inf` already exercised by
//! `synth_round1_volume`. No real disc CHT bytes are used.

use oxideav_aacs::cht::{
    compute_hash_value, DigestRecord, DIGEST_RECORD_LEN, HASH_UNIT_SIZE, HASH_VALUE_LEN,
};
use oxideav_aacs::{AacsError, AacsVolume, Vuk};
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn synth_cht_bytes(digests: &[DigestRecord], hash_values: &[[u8; 8]]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(digests.len() * DIGEST_RECORD_LEN + hash_values.len() * HASH_VALUE_LEN);
    for d in digests {
        out.extend_from_slice(&d.starting_hu_num.to_be_bytes());
        out.extend_from_slice(&d.clip_num.to_be_bytes());
        out.extend_from_slice(&d.hu_offset_in_clip.to_be_bytes());
    }
    for hv in hash_values {
        out.extend_from_slice(hv);
    }
    out
}

fn write_synthetic_aacs_dir(root: &Path, files: &[(&str, &[u8])]) {
    let aacs = root.join("AACS");
    fs::create_dir_all(&aacs).unwrap();
    for (name, bytes) in files {
        fs::write(aacs.join(name), bytes).unwrap();
    }
}

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

/// Minimal MKB byte stream (Type-3, version 1, one Verify-Media-Key
/// record, End-of-MKB). Mirrors the synth_round1_volume shape so the
/// CHT tests can `AacsVolume::open` against a real directory.
fn minimal_mkb_bytes() -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut tv = Vec::new();
    tv.extend_from_slice(&0x0003_1003u32.to_be_bytes());
    tv.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend(write_record(0x10, &tv));
    bytes.extend(write_record(0x81, &[0u8; 16]));
    bytes.extend(write_record(0x02, &[0u8; 40]));
    bytes
}

/// Minimal Unit_Key_RO.inf — exact same shape proven by
/// `tests/synth_round1_volume.rs::build_unit_key_file`, with one
/// dummy title key so the inner header layout is valid. The CHT tests
/// don't exercise the unit-key path; they just need
/// `AacsVolume::open` to succeed.
fn minimal_unit_key_bytes() -> Vec<u8> {
    let vuk = Vuk::from_bytes([0u8; 16]);
    let title_key = [0u8; 16];
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
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0u8; 14]);
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&[0u8; 16]);
    let enc = oxideav_aacs::aes::aes_128_ecb_encrypt(vuk.as_bytes(), &title_key);
    out.extend_from_slice(&enc);
    out
}

#[test]
fn load_content_hash_table_layer0_from_aacs_directory() {
    let tmp = tempdir().unwrap();
    let digests = vec![DigestRecord {
        starting_hu_num: 0,
        clip_num: 1,
        hu_offset_in_clip: 0,
    }];
    let hvs = vec![[0xA1u8; 8], [0xA2u8; 8]];
    let cht_bytes = synth_cht_bytes(&digests, &hvs);
    write_synthetic_aacs_dir(
        tmp.path(),
        &[
            ("MKB_RO.inf", &minimal_mkb_bytes()),
            ("Unit_Key_RO.inf", &minimal_unit_key_bytes()),
            ("ContentHash000.tbl", &cht_bytes),
        ],
    );
    let vol = AacsVolume::open(tmp.path()).unwrap();
    let cht = vol.load_content_hash_table(0, 1, 2).unwrap();
    assert_eq!(cht.digests, digests);
    assert_eq!(cht.hash_values, hvs);
}

#[test]
fn load_content_hash_table_falls_back_to_duplicate_dir() {
    // Primary `AACS/ContentHash000.tbl` missing; `AACS/DUPLICATE/...`
    // present — matches the §2.3.1 + §3.1 "DUPLICATE directory holds
    // backups when the primaries cannot be read" rule.
    let tmp = tempdir().unwrap();
    let aacs = tmp.path().join("AACS");
    fs::create_dir_all(aacs.join("DUPLICATE")).unwrap();
    fs::write(aacs.join("MKB_RO.inf"), minimal_mkb_bytes()).unwrap();
    fs::write(aacs.join("Unit_Key_RO.inf"), minimal_unit_key_bytes()).unwrap();
    let digests = vec![DigestRecord {
        starting_hu_num: 0,
        clip_num: 5,
        hu_offset_in_clip: 0,
    }];
    let hvs = vec![[0xBBu8; 8]];
    let cht_bytes = synth_cht_bytes(&digests, &hvs);
    fs::write(aacs.join("DUPLICATE/ContentHash000.tbl"), &cht_bytes).unwrap();

    let vol = AacsVolume::open(tmp.path()).unwrap();
    let cht = vol.load_content_hash_table(0, 1, 1).unwrap();
    assert_eq!(cht.digests, digests);
    assert_eq!(cht.hash_values, hvs);
}

#[test]
fn load_content_hash_table_rejects_invalid_layer_number() {
    let tmp = tempdir().unwrap();
    write_synthetic_aacs_dir(
        tmp.path(),
        &[
            ("MKB_RO.inf", &minimal_mkb_bytes()),
            ("Unit_Key_RO.inf", &minimal_unit_key_bytes()),
        ],
    );
    let vol = AacsVolume::open(tmp.path()).unwrap();
    // BD-Prerecorded discs only ever have 1 or 2 layers (BD9 / BD25),
    // so layer 2..255 has no defined `ContentHashNNN.tbl` filename.
    assert!(matches!(
        vol.load_content_hash_table(2, 0, 0),
        Err(AacsError::InvalidValue { .. })
    ));
}

#[test]
fn load_content_hash_table_layer1_dual_layer() {
    // Dual-layer disc: both ContentHash000.tbl + ContentHash001.tbl
    // are present; load each independently.
    let tmp = tempdir().unwrap();
    let l0 = synth_cht_bytes(
        &[DigestRecord {
            starting_hu_num: 0,
            clip_num: 1,
            hu_offset_in_clip: 0,
        }],
        &[[0x10u8; 8]],
    );
    let l1 = synth_cht_bytes(
        &[DigestRecord {
            starting_hu_num: 0,
            clip_num: 1,
            hu_offset_in_clip: 5,
        }],
        &[[0x20u8; 8], [0x21u8; 8]],
    );
    write_synthetic_aacs_dir(
        tmp.path(),
        &[
            ("MKB_RO.inf", &minimal_mkb_bytes()),
            ("Unit_Key_RO.inf", &minimal_unit_key_bytes()),
            ("ContentHash000.tbl", &l0),
            ("ContentHash001.tbl", &l1),
        ],
    );
    let vol = AacsVolume::open(tmp.path()).unwrap();

    let cht0 = vol.load_content_hash_table(0, 1, 1).unwrap();
    assert_eq!(cht0.digests[0].hu_offset_in_clip, 0);
    assert_eq!(cht0.hash_values.len(), 1);

    let cht1 = vol.load_content_hash_table(1, 1, 2).unwrap();
    assert_eq!(cht1.digests[0].hu_offset_in_clip, 5);
    assert_eq!(cht1.hash_values.len(), 2);
}

#[test]
fn end_to_end_verify_authored_clip_two_hash_units() {
    // Build a synthetic two-hash-unit Clip payload, author its
    // ContentHashTable, parse via AacsVolume::load_content_hash_table,
    // and verify both Hash Units round-trip.
    let mut hu0 = vec![0u8; HASH_UNIT_SIZE];
    for (i, b) in hu0.iter_mut().enumerate() {
        *b = (i & 0xFF) as u8;
    }
    let mut hu1 = vec![0u8; HASH_UNIT_SIZE];
    for (i, b) in hu1.iter_mut().enumerate() {
        *b = ((i.wrapping_mul(7)) & 0xFF) as u8;
    }
    let hv0 = compute_hash_value(&hu0);
    let hv1 = compute_hash_value(&hu1);

    let digests = vec![DigestRecord {
        starting_hu_num: 0,
        clip_num: 1,
        hu_offset_in_clip: 0,
    }];
    let hvs = vec![hv0, hv1];

    let tmp = tempdir().unwrap();
    write_synthetic_aacs_dir(
        tmp.path(),
        &[
            ("MKB_RO.inf", &minimal_mkb_bytes()),
            ("Unit_Key_RO.inf", &minimal_unit_key_bytes()),
            ("ContentHash000.tbl", &synth_cht_bytes(&digests, &hvs)),
        ],
    );

    let vol = AacsVolume::open(tmp.path()).unwrap();
    let cht = vol.load_content_hash_table(0, 1, 2).unwrap();

    cht.verify_hash_unit(1, 0, &hu0)
        .expect("HU 0 should verify");
    cht.verify_hash_unit(1, 1, &hu1)
        .expect("HU 1 should verify");

    // A single-byte tamper flip in HU 0 must produce
    // `ContentHashMismatch` with the failing (clip_num, hu_in_clip).
    let mut tampered = hu0.clone();
    tampered[42] ^= 0x55;
    match cht.verify_hash_unit(1, 0, &tampered) {
        Err(AacsError::ContentHashMismatch {
            clip_num,
            hu_in_clip,
        }) => {
            assert_eq!(clip_num, 1);
            assert_eq!(hu_in_clip, 0);
        }
        other => panic!("expected ContentHashMismatch, got {other:?}"),
    }
}

#[test]
fn empty_cht_when_no_clip_meets_96_logical_sectors() {
    // §2.3.1: "the size of CHT is zero bytes if there is no Clip AV
    // stream that has a file greater than or equal to 96 Logical
    // Sectors on the corresponding layer". An empty `.tbl` paired
    // with (0, 0) Content-Certificate counts must parse cleanly.
    let tmp = tempdir().unwrap();
    write_synthetic_aacs_dir(
        tmp.path(),
        &[
            ("MKB_RO.inf", &minimal_mkb_bytes()),
            ("Unit_Key_RO.inf", &minimal_unit_key_bytes()),
            ("ContentHash000.tbl", &[][..]),
        ],
    );
    let vol = AacsVolume::open(tmp.path()).unwrap();
    let cht = vol.load_content_hash_table(0, 0, 0).unwrap();
    assert!(cht.digests.is_empty());
    assert!(cht.hash_values.is_empty());
}
