//! Round 246 integration tests — READ DISC STRUCTURE Format `0x85`
//! (AACS Bus-Encryption Sector Extents) sub-payload round-trips through
//! the in-process [`MockDrive`].
//!
//! Wire layout exercised: variable-length response of
//! `[length:u16 = N*16 + 2][reserved:u8][maximum:u8]` followed by `N`
//! 16-byte Bus-Encryption Sector Extent records of
//! `[reserved:8 || Start LBA:u32 || LBA Count:u32]`, per AACS Common
//! §4.14.3.6 Table 4-20 / MMC-6 §6.22.3.1.6 Table 389. The `maximum`
//! field is `1..=256`; the on-wire encoding represents `256` as the
//! byte value `0` per the §4.14.3.6 paragraph 3 sentinel. This Format
//! Code does not require AACS authentication (§4.14.3.6 final
//! sentence).
//!
//! No real disc, no real drive — every byte sequence is synthesised
//! from values defined in this file.

use oxideav_aacs::{
    parse_bus_encryption_sector_extents_response, BusEncryptionSectorExtent, DataDirection,
    DriveCommand, MockDrive, ReadDiscStructure,
};

const EXTENT_RECORD_LEN: usize = 16;

#[test]
fn read_disc_structure_bus_encryption_sector_extents_default_fixture_round_trip() {
    // The default `with_test_fixture` mock advertises a maximum of 4
    // and two pre-populated, non-overlapping extents in ascending
    // Start LBA order.
    let mut drive = MockDrive::with_test_fixture();
    let cdb = ReadDiscStructure::aacs_bus_encryption_sector_extents().cdb();
    let response = drive
        .execute(&cdb, DataDirection::FromDevice, &[], 4108)
        .expect("MockDrive must accept READ_DISC_STRUCTURE Format 0x85");
    assert_eq!(response.status, 0x00);
    // length field: N=2 ⇒ 2*16 + 2 = 34 = 0x0022.
    assert_eq!(response.data[0], 0x00);
    assert_eq!(response.data[1], 0x22);
    // byte 2: Reserved.
    assert_eq!(response.data[2], 0x00);
    // byte 3: Maximum = 4 (fixture).
    assert_eq!(response.data[3], 0x04);
    // 4 (header) + 2 * 16 (extents) = 36 bytes total.
    assert_eq!(response.data.len(), 36);

    let parsed = parse_bus_encryption_sector_extents_response(&response.data).unwrap();
    assert_eq!(parsed.maximum, 4);
    assert_eq!(parsed.extents, drive.bus_encryption_sector_extents);
    assert_eq!(parsed.extents[0].start_lba, 0x0001_0000);
    assert_eq!(parsed.extents[0].lba_count, 0x0000_2000);
    assert_eq!(parsed.extents[1].start_lba, 0x0080_0000);
    assert_eq!(parsed.extents[1].lba_count, 0x0000_4000);
}

#[test]
fn bus_encryption_sector_extents_cdb_byte_layout_matches_mmc6_table_381() {
    // §4.14.3.6 + MMC-6 Table 381: Media Type BD, Format 0x85, AGID
    // reserved (no auth required), Address + Layer reserved.
    let cdb = ReadDiscStructure::aacs_bus_encryption_sector_extents().cdb();
    // READ DISC STRUCTURE opcode.
    assert_eq!(cdb[0], 0xAD);
    // Media Type BD.
    assert_eq!(cdb[1] & 0x0F, 0x01);
    // Address reserved.
    assert_eq!(cdb[2..6], [0u8; 4]);
    // Layer Number reserved.
    assert_eq!(cdb[6], 0);
    // Format Code.
    assert_eq!(cdb[7], 0x85);
    // Allocation length = 12 + 256*16 = 4108 = 0x100C (worst case).
    assert_eq!(cdb[8], 0x10);
    assert_eq!(cdb[9], 0x0C);
    // AGID field zeroed: no authentication required.
    assert_eq!(cdb[10], 0x00);
    // Control byte default.
    assert_eq!(cdb[11], 0x00);
}

#[test]
fn bus_encryption_sector_extents_empty_table_emits_length_2() {
    // §4.14.3.6 paragraph 2: "If no Bus-Encryption Sector Extents are
    // currently defined, the Data Length field shall be 2."
    let mut drive = MockDrive::with_test_fixture();
    drive.bus_encryption_sector_extents.clear();
    drive.max_bus_encryption_sector_extents = 16;
    let cdb = ReadDiscStructure::aacs_bus_encryption_sector_extents().cdb();
    let response = drive
        .execute(&cdb, DataDirection::FromDevice, &[], 4108)
        .unwrap();
    assert_eq!(response.data.len(), 4);
    assert_eq!(response.data[0], 0x00);
    assert_eq!(response.data[1], 0x02);
    assert_eq!(response.data[2], 0x00);
    assert_eq!(response.data[3], 0x10);

    let parsed = parse_bus_encryption_sector_extents_response(&response.data).unwrap();
    assert_eq!(parsed.maximum, 16);
    assert!(parsed.extents.is_empty());
}

#[test]
fn bus_encryption_sector_extents_maximum_256_encodes_as_wire_zero() {
    // §4.14.3.6 paragraph 3: "The value 256 is denoted by a '0' in the
    // field."
    let mut drive = MockDrive::with_test_fixture();
    drive.bus_encryption_sector_extents.clear();
    drive.max_bus_encryption_sector_extents = 256;
    let cdb = ReadDiscStructure::aacs_bus_encryption_sector_extents().cdb();
    let response = drive
        .execute(&cdb, DataDirection::FromDevice, &[], 4108)
        .unwrap();
    assert_eq!(response.data[3], 0x00); // on-wire sentinel.
    let parsed = parse_bus_encryption_sector_extents_response(&response.data).unwrap();
    assert_eq!(parsed.maximum, 256); // decoded back to semantic 256.
}

#[test]
fn bus_encryption_sector_extents_record_stride_is_16_bytes() {
    // Walk the wire byte-by-byte against a hand-written reference and
    // confirm each extent occupies 16 bytes: 8 Reserved + 4 Start LBA
    // + 4 LBA Count.
    let mut drive = MockDrive::with_test_fixture();
    drive.bus_encryption_sector_extents = vec![
        BusEncryptionSectorExtent {
            start_lba: 0x1122_3344,
            lba_count: 0x5566_7788,
        },
        BusEncryptionSectorExtent {
            start_lba: 0x9900_AABB,
            lba_count: 0x00CC_DDEE,
        },
        BusEncryptionSectorExtent {
            start_lba: 0xFFFF_0000,
            lba_count: 0x0000_FFFF,
        },
    ];
    drive.max_bus_encryption_sector_extents = 3;
    let cdb = ReadDiscStructure::aacs_bus_encryption_sector_extents().cdb();
    let response = drive
        .execute(&cdb, DataDirection::FromDevice, &[], 4108)
        .unwrap();
    // length = 3*16 + 2 = 50 = 0x0032.
    assert_eq!(response.data[0], 0x00);
    assert_eq!(response.data[1], 0x32);
    assert_eq!(response.data[3], 0x03);
    // Total wire size = 4 + 3*16 = 52.
    assert_eq!(response.data.len(), 52);

    // Extent 0 starts at byte 4 with the 8 Reserved bytes.
    assert_eq!(&response.data[4..12], &[0u8; 8]);
    // Start LBA 0 at bytes 12..15 big-endian.
    assert_eq!(&response.data[12..16], &[0x11, 0x22, 0x33, 0x44]);
    // LBA Count 0 at bytes 16..19 big-endian.
    assert_eq!(&response.data[16..20], &[0x55, 0x66, 0x77, 0x88]);

    // Extent 1 stride = 16, starts at byte 20.
    assert_eq!(&response.data[20..28], &[0u8; 8]);
    assert_eq!(&response.data[28..32], &[0x99, 0x00, 0xAA, 0xBB]);
    assert_eq!(&response.data[32..36], &[0x00, 0xCC, 0xDD, 0xEE]);

    // Extent 2 starts at byte 36.
    assert_eq!(&response.data[36..44], &[0u8; 8]);
    assert_eq!(&response.data[44..48], &[0xFF, 0xFF, 0x00, 0x00]);
    assert_eq!(&response.data[48..52], &[0x00, 0x00, 0xFF, 0xFF]);

    let parsed = parse_bus_encryption_sector_extents_response(&response.data).unwrap();
    assert_eq!(parsed.maximum, 3);
    assert_eq!(parsed.extents, drive.bus_encryption_sector_extents);
    // Confirm the parser does not silently swap the two u32 fields.
    assert_eq!(parsed.extents[0].start_lba, 0x1122_3344);
    assert_eq!(parsed.extents[0].lba_count, 0x5566_7788);
}

#[test]
fn bus_encryption_sector_extents_parser_rejects_misaligned_stride() {
    // length = 0x0011 = 17 ⇒ extent section length = 15, not a
    // multiple of 16 ⇒ malformed table.
    let mut wire = vec![0x00, 0x11, 0x00, 0x01];
    wire.resize(2 + 17, 0);
    assert_eq!(wire.len(), 19);
    assert!(parse_bus_encryption_sector_extents_response(&wire).is_err());
}

#[test]
fn bus_encryption_sector_extents_parser_rejects_short_length_field() {
    // length = 0 ⇒ violates §4.14.3.6 paragraph 2 minimum of 2.
    let wire = [0x00, 0x00, 0x00, 0x00];
    assert!(parse_bus_encryption_sector_extents_response(&wire).is_err());
    // length = 1 ⇒ likewise invalid.
    let wire = [0x00, 0x01, 0x00, 0x00];
    assert!(parse_bus_encryption_sector_extents_response(&wire).is_err());
}

#[test]
fn bus_encryption_sector_extents_parser_rejects_truncated_buffer() {
    // length claims 0x0012 = 18 (one extent + trailer) but the buffer
    // is shorter.
    let wire = [0x00, 0x12, 0x00, 0x01, 0xAA];
    assert!(parse_bus_encryption_sector_extents_response(&wire).is_err());
}

#[test]
fn bus_encryption_sector_extents_parser_handles_single_extent() {
    // One extent: length = 16 + 2 = 18 = 0x0012. Buffer = 4 + 16 = 20.
    let mut wire = vec![0x00, 0x12, 0x00, 0x02];
    wire.extend_from_slice(&[0u8; 8]); // Reserved.
    wire.extend_from_slice(&[0x00, 0x00, 0x12, 0x34]); // Start LBA.
    wire.extend_from_slice(&[0x00, 0x00, 0x56, 0x78]); // LBA Count.
    assert_eq!(wire.len(), 20);
    let parsed = parse_bus_encryption_sector_extents_response(&wire).unwrap();
    assert_eq!(parsed.maximum, 2);
    assert_eq!(parsed.extents.len(), 1);
    assert_eq!(parsed.extents[0].start_lba, 0x0000_1234);
    assert_eq!(parsed.extents[0].lba_count, 0x0000_5678);
}

#[test]
fn bus_encryption_sector_extents_static_fixture_extents_are_sorted() {
    // The §4.14.3.6 paragraph 3 ordering rule: extents in the response
    // are sorted by Start LBA ascending. The default fixture honours
    // this; the parser preserves the wire order verbatim.
    let mut drive = MockDrive::with_test_fixture();
    drive.bus_encryption_sector_extents = vec![
        BusEncryptionSectorExtent {
            start_lba: 0x0000_1000,
            lba_count: 0x0000_0100,
        },
        BusEncryptionSectorExtent {
            start_lba: 0x0001_0000,
            lba_count: 0x0000_0200,
        },
        BusEncryptionSectorExtent {
            start_lba: 0x0010_0000,
            lba_count: 0x0000_0400,
        },
    ];
    drive.max_bus_encryption_sector_extents = 3;
    let cdb = ReadDiscStructure::aacs_bus_encryption_sector_extents().cdb();
    let response = drive
        .execute(&cdb, DataDirection::FromDevice, &[], 4108)
        .unwrap();
    let parsed = parse_bus_encryption_sector_extents_response(&response.data).unwrap();
    let starts: Vec<u32> = parsed.extents.iter().map(|e| e.start_lba).collect();
    let mut sorted = starts.clone();
    sorted.sort();
    assert_eq!(starts, sorted);
}

#[test]
fn bus_encryption_sector_extents_does_not_require_authentication() {
    // §4.14.3.6 final sentence: "This command does not require AACS
    // authentication." The mock without an `auth` slot dispatches the
    // Format 0x85 path without error.
    // Default initialises `max_bus_encryption_sector_extents = 1` and
    // an empty extent list — exactly the no-auth no-table fixture.
    let mut drive = MockDrive::default();
    let cdb = ReadDiscStructure::aacs_bus_encryption_sector_extents().cdb();
    let response = drive
        .execute(&cdb, DataDirection::FromDevice, &[], 4108)
        .unwrap();
    assert_eq!(response.status, 0x00);
    // Empty extent list ⇒ length 2.
    assert_eq!(response.data[0], 0x00);
    assert_eq!(response.data[1], 0x02);
}

#[test]
fn bus_encryption_sector_extents_consistent_stride_with_named_constant() {
    // Pins the per-record stride at 16 bytes (Reserved:8 + Start LBA:4
    // + LBA Count:4) to lock the named constant against accidental
    // drift. Per AACS Common §4.14.3.6 Table 4-20.
    assert_eq!(EXTENT_RECORD_LEN, 16);
}
