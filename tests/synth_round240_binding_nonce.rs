//! Round 240 integration tests — REPORT KEY Key Format `0x20` /
//! `0x21` (AACS Binding Nonce) sub-payload round-trips through the
//! in-process [`MockDrive`].
//!
//! Wire layout exercised: `[length:u16=0x0022][reserved:u16][nonce:16]
//! [mac:16]` for both the generate-and-store (`0x20`) and
//! read-from-medium (`0x21`) variants. CDB byte layout exercised: the
//! LBA Extent triple from AACS Common §4.14.2 final paragraph — bytes
//! 2..5 (starting LBA, big-endian) and byte 6 (block count).
//!
//! No real disc, no real drive, no real Bus Key — every byte sequence
//! is synthesised from values defined in this file. The MAC the mock
//! returns matches its fixture `binding_nonce_mac` field verbatim when
//! the mock's `auth` slot is `None`; the synthetic-AKE Bus-Key path
//! (with `aes_128_cmac`) is covered by the round 96 Phase C tests
//! independently.

use oxideav_aacs::{
    parse_report_key_binding_nonce, DataDirection, DriveCommand, MockDrive, ReportKey,
};

const BINDING_NONCE_LEN: usize = 16;
const BINDING_NONCE_MAC_LEN: usize = 16;

#[test]
fn report_key_binding_nonce_gen_roundtrip_through_mock_drive() {
    let mut drive = MockDrive::with_test_fixture();
    // AGID=2, starting LBA=0x000123AB, block count=0x08.
    let starting_lba: u32 = 0x0001_23AB;
    let block_count: u8 = 0x08;
    let cdb = ReportKey::aacs_binding_nonce_gen(2, starting_lba, block_count).cdb();
    let response = drive
        .execute(&cdb, DataDirection::FromDevice, &[], 36)
        .expect("MockDrive must accept REPORT_KEY Binding Nonce generate");
    assert_eq!(response.status, 0x00);
    assert_eq!(response.data.len(), 36);
    // Length field 0x0022 = 34 (payload size, header excluded).
    assert_eq!(response.data[0], 0x00);
    assert_eq!(response.data[1], 0x22);

    let parsed = parse_report_key_binding_nonce(&response.data).unwrap();
    assert_eq!(parsed.binding_nonce, drive.binding_nonce);
    assert_eq!(parsed.mac, drive.binding_nonce_mac);

    // The mock must have captured the LBA Extent the host targeted.
    let (kf, lba, bc) = drive
        .last_binding_nonce_op
        .expect("MockDrive must capture the Binding Nonce CDB context");
    assert_eq!(kf, 0x20);
    assert_eq!(lba, starting_lba);
    assert_eq!(bc, block_count);
}

#[test]
fn report_key_binding_nonce_read_roundtrip_through_mock_drive() {
    let mut drive = MockDrive::with_test_fixture();
    // AGID=1, LBA=0, block_count=1 — typical "read the nonce for the
    // first managed LBA Extent" call shape.
    let cdb = ReportKey::aacs_binding_nonce_read(1, 0, 1).cdb();
    let response = drive
        .execute(&cdb, DataDirection::FromDevice, &[], 36)
        .expect("MockDrive must accept REPORT_KEY Binding Nonce read");
    assert_eq!(response.data.len(), 36);
    let parsed = parse_report_key_binding_nonce(&response.data).unwrap();
    assert_eq!(parsed.binding_nonce, drive.binding_nonce);
    assert_eq!(parsed.mac, drive.binding_nonce_mac);
    let (kf, lba, bc) = drive.last_binding_nonce_op.unwrap();
    assert_eq!(kf, 0x21);
    assert_eq!(lba, 0);
    assert_eq!(bc, 1);
}

#[test]
fn binding_nonce_response_length_matches_table_4_10() {
    // AACS Common §4.14.2.4 Table 4-10: 4-byte header + 16-byte nonce
    // + 16-byte MAC = 36 bytes total. Both the generate and read
    // variants share this layout.
    let mut drive = MockDrive::with_test_fixture();
    for cdb in [
        ReportKey::aacs_binding_nonce_gen(0, 0, 0).cdb(),
        ReportKey::aacs_binding_nonce_read(0, 0, 0).cdb(),
    ] {
        let response = drive
            .execute(&cdb, DataDirection::FromDevice, &[], 36)
            .unwrap();
        assert_eq!(
            response.data.len(),
            4 + BINDING_NONCE_LEN + BINDING_NONCE_MAC_LEN
        );
    }
}

#[test]
fn binding_nonce_cdb_packs_lba_extent_big_endian() {
    // Sanity-check that the LBA bytes land in the documented order
    // (bytes 2..5 big-endian) and that block-count is byte 6. AACS
    // Common §4.14.2 final paragraph (LBA Extent semantics) +
    // MMC-6 Table 513 (CDB layout).
    let rk = ReportKey::aacs_binding_nonce_gen(0, 0xDEAD_BEEF, 0xCD);
    let cdb = rk.cdb();
    assert_eq!(cdb[2], 0xDE);
    assert_eq!(cdb[3], 0xAD);
    assert_eq!(cdb[4], 0xBE);
    assert_eq!(cdb[5], 0xEF);
    assert_eq!(cdb[6], 0xCD);
}

#[test]
fn binding_nonce_gen_and_read_use_distinct_key_format_codes() {
    // The two commands share the response wire layout but the CDB Key
    // Format field is the spec's only way to distinguish them. Verify
    // we don't accidentally collapse them.
    let gen_cdb = ReportKey::aacs_binding_nonce_gen(0, 0, 0).cdb();
    let read_cdb = ReportKey::aacs_binding_nonce_read(0, 0, 0).cdb();
    // Bits 5..0 of byte 10 carry the Key Format.
    assert_eq!(gen_cdb[10] & 0x3F, 0x20);
    assert_eq!(read_cdb[10] & 0x3F, 0x21);
    // Allocation length is identical between the two (36 bytes,
    // 0x0024 big-endian).
    assert_eq!(&gen_cdb[8..10], &[0x00, 0x24]);
    assert_eq!(&read_cdb[8..10], &[0x00, 0x24]);
}

#[test]
fn binding_nonce_parser_rejects_wrong_length_field() {
    // Length field 0x0010 != 0x0022 — mismatched declared length.
    let mut wire = vec![0x00, 0x10, 0x00, 0x00];
    wire.resize(36, 0);
    assert!(parse_report_key_binding_nonce(&wire).is_err());
}

#[test]
fn binding_nonce_parser_rejects_truncated_payload() {
    // Correct length field but payload short of the expected 36 bytes.
    let wire = [0x00, 0x22, 0x00, 0x00, 0xAA];
    assert!(parse_report_key_binding_nonce(&wire).is_err());
}
