//! Content Hash Table (CHT) integration tests — BD-Prerecorded
//! Final 0.953 §2.3.
//!
//! These build a synthetic `ContentHash00N.tbl` byte image through
//! the public API, parse it back, and verify Hash Units. No
//! disc-derived material: every Hash Unit is generated from a seed.

use oxideav_aacs::{
    encrypt_aligned_unit, hash_value_of_unit, AacsError, ClipDescriptor, ContentHashTable,
    ALIGNED_UNIT_SIZE, HASH_UNIT_SIZE,
};

/// A Hash Unit is 96 Logical Sectors = 196608 bytes = exactly 32
/// Aligned Units of 6144 bytes (96 * 2048 == 32 * 6144). This test
/// also documents that arithmetic.
#[test]
fn hash_unit_is_thirty_two_aligned_units() {
    assert_eq!(HASH_UNIT_SIZE, 32 * ALIGNED_UNIT_SIZE);
}

fn synth_unit(seed: u8) -> Vec<u8> {
    (0..HASH_UNIT_SIZE)
        .map(|i| (i as u8).wrapping_mul(7).wrapping_add(seed))
        .collect()
}

/// Author a CHT file image: header descriptors then 8-byte Hash
/// Values, exactly as Table 2-2 lays it out.
fn author_cht(clips: &[ClipDescriptor], hash_values: &[[u8; 8]]) -> Vec<u8> {
    let mut buf = Vec::new();
    for c in clips {
        buf.extend_from_slice(&c.starting_hu_num.to_be_bytes());
        buf.extend_from_slice(&c.clip_num.to_be_bytes());
        buf.extend_from_slice(&c.hu_offset_in_clip.to_be_bytes());
    }
    for hv in hash_values {
        buf.extend_from_slice(hv);
    }
    buf
}

#[test]
fn authored_table_round_trips_and_verifies() {
    // Two clips: clip 0 owns HU 0..=1, clip 7 owns HU 2.
    let clips = [
        ClipDescriptor {
            starting_hu_num: 0,
            clip_num: 0,
            hu_offset_in_clip: 0,
        },
        ClipDescriptor {
            starting_hu_num: 2,
            clip_num: 7,
            hu_offset_in_clip: 0,
        },
    ];
    let units: Vec<Vec<u8>> = (0..3u8).map(synth_unit).collect();
    let hvs: Vec<[u8; 8]> = units.iter().map(|u| hash_value_of_unit(u)).collect();

    let image = author_cht(&clips, &hvs);
    let cht = ContentHashTable::parse(&image, clips.len() as u32, units.len() as u32).unwrap();

    assert_eq!(cht.clips, clips);
    assert_eq!(cht.len(), 3);
    for (i, u) in units.iter().enumerate() {
        cht.verify_hash_unit(i, u).unwrap();
    }
}

/// The headline §2.3.2.1 property: the hash is taken over the
/// *encrypted* bytes, so a Licensed Player verifies integrity
/// **without** holding the Title Key.
#[test]
fn verifies_encrypted_bytes_without_decryption() {
    let title_key = [0x5Au8; 16];

    // Build one Hash Unit out of 32 freshly-encrypted Aligned Units.
    let mut encrypted_unit = Vec::with_capacity(HASH_UNIT_SIZE);
    for au in 0..32u8 {
        let plaintext: Vec<u8> = (0..ALIGNED_UNIT_SIZE)
            .map(|i| (i as u8).wrapping_add(au))
            .collect();
        let ct = encrypt_aligned_unit(&title_key, &plaintext).unwrap();
        encrypted_unit.extend_from_slice(&ct);
    }
    assert_eq!(encrypted_unit.len(), HASH_UNIT_SIZE);

    // Author the CHT over the encrypted bytes.
    let hv = hash_value_of_unit(&encrypted_unit);
    let clips = [ClipDescriptor {
        starting_hu_num: 0,
        clip_num: 0,
        hu_offset_in_clip: 0,
    }];
    let image = author_cht(&clips, &[hv]);
    let cht = ContentHashTable::parse(&image, 1, 1).unwrap();

    // A player with no key verifies the encrypted unit directly.
    cht.verify_hash_unit(0, &encrypted_unit).unwrap();

    // Flipping a single ciphertext byte is detected.
    let mut tampered = encrypted_unit.clone();
    tampered[100_000] ^= 0x80;
    assert_eq!(
        cht.verify_hash_unit(0, &tampered),
        Err(AacsError::ContentHashMismatch { index: 0 })
    );
}

#[test]
fn parse_rejects_short_buffer() {
    // Declare 3 hash units but author only 2.
    let units: Vec<Vec<u8>> = (0..2u8).map(synth_unit).collect();
    let hvs: Vec<[u8; 8]> = units.iter().map(|u| hash_value_of_unit(u)).collect();
    let image = author_cht(&[], &hvs);
    assert!(matches!(
        ContentHashTable::parse(&image, 0, 3),
        Err(AacsError::OversizedRecord { .. })
    ));
}
