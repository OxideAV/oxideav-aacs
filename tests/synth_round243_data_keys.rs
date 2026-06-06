//! Round 243 integration tests — READ DISC STRUCTURE Format `0x84`
//! (AACS Data Keys) sub-payload round-trips through the in-process
//! [`MockDrive`].
//!
//! Wire layout exercised: `[length:u16=0x0022][reserved:u16][Krd:16]
//! [Kwd:16]` per AACS Common §4.14.3.5 Table 4-19 — 36 bytes total,
//! comprising a 4-byte header + 16-byte encrypted Read Data Key + 16-byte
//! encrypted Write Data Key. Both keys are wrapped under the Bus Key
//! established by the §4.3 AKE using AES-128E per §4.11.
//!
//! No real disc, no real drive — every byte sequence is synthesised
//! from values defined in this file. The Bus-Key wrap step in `auth`
//! mode is exercised against a Bus Key the test computes from a
//! synthetic AKE; the static-fixture path is exercised via the plain
//! `with_test_fixture` constructor without an `auth` slot.

use oxideav_aacs::{
    parse_data_keys_response, DataDirection, DataKeysResponse, DriveCommand, MockDrive,
    ReadDiscStructure,
};

const DATA_KEY_LEN: usize = 16;

#[test]
fn read_disc_structure_data_keys_static_mode_roundtrip() {
    // No `auth` slot → the mock returns the plaintext Data Keys
    // verbatim. The test parses the on-wire layout and asserts the
    // parsed bytes match the mock's fixture values.
    let mut drive = MockDrive::with_test_fixture();
    let cdb = ReadDiscStructure::aacs_data_keys(2).cdb();
    let response = drive
        .execute(&cdb, DataDirection::FromDevice, &[], 36)
        .expect("MockDrive must accept READ_DISC_STRUCTURE Format 0x84");
    assert_eq!(response.status, 0x00);
    assert_eq!(response.data.len(), 36);
    // Length field 0x0022 = 34 (counts bytes 2..35).
    assert_eq!(response.data[0], 0x00);
    assert_eq!(response.data[1], 0x22);
    assert_eq!(response.data[2], 0x00);
    assert_eq!(response.data[3], 0x00);

    let parsed = parse_data_keys_response(&response.data).unwrap();
    assert_eq!(parsed.read_data_key_encrypted, drive.read_data_key);
    assert_eq!(parsed.write_data_key_encrypted, drive.write_data_key);
    assert!(drive.last_data_keys_read);
}

#[test]
fn data_keys_cdb_byte_layout_matches_mmc6_table_381() {
    // AACS Common §4.14.3.5 + MMC-6 Table 381: Media Type BD, Format
    // 0x84, AGID in bits 7..6 of byte 10, allocation length 36
    // (0x0024 big-endian). The Reserved/Address bytes 2..5 are zero
    // for Format 0x84 (only the Binding Nonce formats use them).
    let cdb = ReadDiscStructure::aacs_data_keys(3).cdb();
    assert_eq!(cdb[0], 0xAD);
    assert_eq!(cdb[1] & 0x0F, 0x01);
    assert_eq!(cdb[2..6], [0x00, 0x00, 0x00, 0x00]);
    assert_eq!(cdb[6], 0x00);
    assert_eq!(cdb[7], 0x84);
    assert_eq!(cdb[8], 0x00);
    assert_eq!(cdb[9], 0x24);
    // AGID=3 in bits 7..6.
    assert_eq!(cdb[10] >> 6, 3);
    assert_eq!(cdb[11], 0x00);
}

#[test]
fn data_keys_response_length_matches_table_4_19() {
    // Table 4-19: 4-byte header + 16-byte Krd + 16-byte Kwd = 36 bytes.
    let mut drive = MockDrive::with_test_fixture();
    let cdb = ReadDiscStructure::aacs_data_keys(0).cdb();
    let response = drive
        .execute(&cdb, DataDirection::FromDevice, &[], 36)
        .unwrap();
    assert_eq!(response.data.len(), 4 + DATA_KEY_LEN + DATA_KEY_LEN);
}

#[test]
fn data_keys_response_decrypt_round_trip_recovers_plaintext() {
    // Standalone AES-128E/AES-128D round-trip property under a known
    // Bus Key — independent of the MockDrive: wrap the plaintext keys
    // ourselves, hand the wrapped pair to a `DataKeysResponse`, then
    // confirm the decrypt_* helpers recover the original bytes.
    use oxideav_aacs::aes::aes_128_ecb_encrypt;

    let bus_key = [0x77u8; 16];
    let krd_pt = {
        let mut k = [0u8; DATA_KEY_LEN];
        for (i, b) in k.iter_mut().enumerate() {
            *b = 0xC0 | (i as u8);
        }
        k
    };
    let kwd_pt = {
        let mut k = [0u8; DATA_KEY_LEN];
        for (i, b) in k.iter_mut().enumerate() {
            *b = 0xD0 | (i as u8);
        }
        k
    };

    let resp = DataKeysResponse {
        read_data_key_encrypted: aes_128_ecb_encrypt(&bus_key, &krd_pt),
        write_data_key_encrypted: aes_128_ecb_encrypt(&bus_key, &kwd_pt),
    };
    assert_eq!(resp.decrypt_read_data_key(&bus_key), krd_pt);
    assert_eq!(resp.decrypt_write_data_key(&bus_key), kwd_pt);
}

#[test]
fn data_keys_parser_rejects_wrong_length_field() {
    // Spec mandates length = 0x0022. A trailing 0x0010 must be
    // rejected as a malformed wire payload — the mock would never
    // emit one, but the parser must defend against an untrusted
    // drive.
    let mut wire = vec![0x00, 0x10, 0x00, 0x00];
    wire.resize(36, 0);
    assert!(parse_data_keys_response(&wire).is_err());
}

#[test]
fn data_keys_parser_rejects_truncated_payload() {
    // Correct length field but the payload is short of the expected
    // 36 bytes. The parser must reject rather than read past the
    // buffer.
    let wire = [0x00, 0x22, 0x00, 0x00, 0xAA, 0xBB, 0xCC];
    assert!(parse_data_keys_response(&wire).is_err());
}

#[test]
fn data_keys_zeroed_buffer_is_valid_wire_shape() {
    // A 36-byte buffer with the canonical length header and all-zero
    // key bytes is well-formed (the spec does not constrain key
    // values). The parser returns the zero keys without error.
    let mut wire = vec![0x00, 0x22, 0x00, 0x00];
    wire.resize(36, 0);
    let parsed = parse_data_keys_response(&wire).unwrap();
    assert_eq!(parsed.read_data_key_encrypted, [0u8; DATA_KEY_LEN]);
    assert_eq!(parsed.write_data_key_encrypted, [0u8; DATA_KEY_LEN]);
}

#[test]
fn data_keys_response_field_offsets_match_table_4_19() {
    // Verify the parser picks up Krd from bytes 4..19 and Kwd from
    // bytes 20..35 — i.e. the two 16-byte fields are not transposed
    // or off by one. Use a buffer where every byte is its own index
    // so a position error surfaces as a wrong byte value.
    let mut wire = vec![0x00, 0x22, 0x00, 0x00];
    for i in 4..36u8 {
        wire.push(i);
    }
    assert_eq!(wire.len(), 36);
    let parsed = parse_data_keys_response(&wire).unwrap();
    assert_eq!(
        parsed.read_data_key_encrypted,
        [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]
    );
    assert_eq!(
        parsed.write_data_key_encrypted,
        [20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35]
    );
}

#[test]
fn mock_drive_wraps_data_keys_under_synthetic_bus_key_in_auth_mode() {
    // When the mock's `auth` slot carries a Bus Key, the response Krd
    // and Kwd bytes are AES-128E(BK, plaintext), so the host's
    // decrypt_* helpers recover the plaintext under the same Bus Key.
    // The §4.3 AKE state itself is exercised by the Phase C tests;
    // here we synthesise a minimal `DriveAuthState` and plant a Bus
    // Key directly so the test focuses on the §4.11 wrap step alone.
    use oxideav_aacs::ake::DriveAuthState;
    use oxideav_aacs::ec::Point;

    let mut drive = MockDrive::with_test_fixture();
    let synthetic_bus_key = [0xAAu8; 16];
    // Build a placeholder `DriveAuthState` via `::new`, then set
    // `bus_key` directly. The §4.3 fields are unused by the §4.14.3.5
    // dispatcher branch — it reads only `auth.bus_key`.
    let mut nonzero_be = [0u8; 20];
    nonzero_be[19] = 1;
    let mut state = DriveAuthState::new(
        [0u8; 92],
        oxideav_aacs::ec::U160::from_be_bytes(&nonzero_be),
        oxideav_aacs::ec::U160::from_be_bytes(&nonzero_be),
        [0u8; 20],
        Point::generator(),
    );
    state.bus_key = Some(synthetic_bus_key);
    drive.auth = Some(state);

    let cdb = ReadDiscStructure::aacs_data_keys(1).cdb();
    let response = drive
        .execute(&cdb, DataDirection::FromDevice, &[], 36)
        .unwrap();
    let parsed = parse_data_keys_response(&response.data).unwrap();

    let recovered_krd = parsed.decrypt_read_data_key(&synthetic_bus_key);
    let recovered_kwd = parsed.decrypt_write_data_key(&synthetic_bus_key);
    assert_eq!(recovered_krd, drive.read_data_key);
    assert_eq!(recovered_kwd, drive.write_data_key);
    // Confirm the wrapped bytes differ from the plaintext — i.e. the
    // wrap step actually ran.
    assert_ne!(parsed.read_data_key_encrypted, drive.read_data_key);
    assert_ne!(parsed.write_data_key_encrypted, drive.write_data_key);
    assert!(drive.last_data_keys_read);
}
