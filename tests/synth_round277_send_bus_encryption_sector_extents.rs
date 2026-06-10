//! Round 277 integration tests — SEND DISC STRUCTURE Format `0x85`
//! (Bus-Encryption Sector Extents) host→drive ingest through the
//! in-process [`MockDrive`].
//!
//! Wire layout exercised: CDB per AACS Common §4.14.5 Table 4-26
//! (opcode `0xBF`, Media Type BD, Format Code `0x85`, Parameter List
//! Length `4 + N*16`, AGID reserved — §4.14.5.2 requires no AACS
//! authentication) and the parameter list per §4.14.5.2 Table 4-29
//! (`[length:u16 = 2 + N*16][reserved:u16]` + `N` 16-byte LBA Extent
//! Structures `[reserved:8 || Start LBA:u32 || LBA Count:u32]`).
//!
//! The §4.14.5.2 ingest rules are pinned: an `N == 0` list clears the
//! drive's current extents; overlapping, unsorted, zero-count, or
//! beyond-capacity extents are rejected with INVALID FIELD IN PARAMETER
//! LIST; an `N` exceeding the drive's storable maximum is rejected with
//! SYSTEM RESOURCE FAILURE. No real disc, no real drive.

use oxideav_aacs::{
    build_send_disc_structure_bus_encryption_sector_extents,
    parse_bus_encryption_sector_extents_response,
    parse_send_disc_structure_bus_encryption_sector_extents,
    validate_bus_encryption_sector_extents, BusEncryptionSectorExtent, DataDirection, DriveCommand,
    MockDrive, ReadDiscStructure, SendDiscStructure,
};

const EXTENT_LEN: usize = 16;

fn extent(start_lba: u32, lba_count: u32) -> BusEncryptionSectorExtent {
    BusEncryptionSectorExtent {
        start_lba,
        lba_count,
    }
}

#[test]
fn send_extents_cdb_layout_matches_table_4_26() {
    // §4.14.5 Table 4-26: opcode 0xBF, Media Type BD in the low nibble
    // of byte 1, bytes 2..6 Reserved, Format Code 0x85, Parameter List
    // Length = 4 + N*16 big-endian, AGID reserved (Format 0x85 does not
    // use the AGID per MMC-6 §6.36.2.4), Control 0.
    let cdb = SendDiscStructure::aacs_bus_encryption_sector_extents(3).cdb();
    assert_eq!(cdb[0], 0xBF);
    assert_eq!(cdb[1] & 0x0F, 0x01);
    assert_eq!(cdb[2..7], [0x00, 0x00, 0x00, 0x00, 0x00]);
    assert_eq!(cdb[7], 0x85);
    // 4 + 3*16 = 52 = 0x0034.
    assert_eq!(cdb[8], 0x00);
    assert_eq!(cdb[9], 0x34);
    assert_eq!(
        cdb[10], 0x00,
        "AGID + Reserved are all zero for Format 0x85"
    );
    assert_eq!(cdb[11], 0x00);

    let parsed = SendDiscStructure::parse_cdb(&cdb).unwrap();
    assert_eq!(parsed.format, 0x85);
    assert_eq!(parsed.parameter_list_length, 52);
    assert_eq!(parsed.agid, 0);
}

#[test]
fn empty_send_extents_cdb_is_clear_request() {
    // N == 0 → parameter list is just the 4-byte header (length 0x0002).
    let cdb = SendDiscStructure::aacs_bus_encryption_sector_extents(0).cdb();
    assert_eq!(cdb[7], 0x85);
    assert_eq!(cdb[8], 0x00);
    assert_eq!(cdb[9], 0x04);
}

#[test]
fn parameter_list_layout_matches_table_4_29() {
    // Table 4-29: length field = 2 + N*16 (does not count itself);
    // bytes 2..3 Reserved; each extent record is 8 Reserved bytes then
    // Start LBA (u32 BE) then LBA Count (u32 BE).
    let extents = [extent(0x0001_0000, 0x0000_2000), extent(0x0008_0000, 0x40)];
    let wire = build_send_disc_structure_bus_encryption_sector_extents(&extents);
    assert_eq!(wire.len(), 4 + 2 * EXTENT_LEN);
    // length = 2 + 2*16 = 34 = 0x0022.
    assert_eq!(wire[0], 0x00);
    assert_eq!(wire[1], 0x22);
    assert_eq!(wire[2], 0x00);
    assert_eq!(wire[3], 0x00);
    // Extent 0: 8 reserved, then 0x0001_0000, then 0x0000_2000.
    assert_eq!(wire[4..12], [0u8; 8]);
    assert_eq!(wire[12..16], [0x00, 0x01, 0x00, 0x00]);
    assert_eq!(wire[16..20], [0x00, 0x00, 0x20, 0x00]);
    // Extent 1: 8 reserved, then 0x0008_0000, then 0x0000_0040.
    assert_eq!(wire[20..28], [0u8; 8]);
    assert_eq!(wire[28..32], [0x00, 0x08, 0x00, 0x00]);
    assert_eq!(wire[32..36], [0x00, 0x00, 0x00, 0x40]);
}

#[test]
fn build_parse_round_trip() {
    let extents = vec![
        extent(0, 0x1000),
        extent(0x1000, 0x800),
        extent(0xFFFF_0000, 0x10),
    ];
    let wire = build_send_disc_structure_bus_encryption_sector_extents(&extents);
    let recovered = parse_send_disc_structure_bus_encryption_sector_extents(&wire).unwrap();
    assert_eq!(recovered, extents);

    // Empty list → 4-byte header, length 0x0002, parses to empty Vec.
    let empty = build_send_disc_structure_bus_encryption_sector_extents(&[]);
    assert_eq!(empty, vec![0x00, 0x02, 0x00, 0x00]);
    assert!(
        parse_send_disc_structure_bus_encryption_sector_extents(&empty)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn parser_rejects_malformed_lists() {
    // length < 2.
    assert!(parse_send_disc_structure_bus_encryption_sector_extents(&[0x00, 0x01, 0, 0]).is_err());
    // length declares one extent (0x12 = 18 = 2 + 16) but buffer is short.
    assert!(
        parse_send_disc_structure_bus_encryption_sector_extents(&[0x00, 0x12, 0x00, 0x00]).is_err()
    );
    // (length - 2) not a multiple of 16.
    let mut bad_stride = vec![0x00, 0x0A, 0x00, 0x00];
    bad_stride.resize(12, 0u8);
    assert!(parse_send_disc_structure_bus_encryption_sector_extents(&bad_stride).is_err());
    // Truncated header.
    assert!(parse_send_disc_structure_bus_encryption_sector_extents(&[0x00]).is_err());
}

#[test]
fn mock_drive_accepts_valid_sorted_extents() {
    let mut drive = MockDrive::with_test_fixture();
    drive.max_bus_encryption_sector_extents = 4;
    drive.media_capacity_lba = 0x0100_0000;
    let new_extents = vec![
        extent(0x10, 0x20),
        extent(0x100, 0x40),
        extent(0x1000, 0x80),
    ];

    let cdb = SendDiscStructure::aacs_bus_encryption_sector_extents(new_extents.len()).cdb();
    let wire = build_send_disc_structure_bus_encryption_sector_extents(&new_extents);
    let resp = drive
        .execute(&cdb, DataDirection::ToDevice, &wire, 0)
        .expect("MockDrive must accept a valid Format 0x85 ingest");
    assert_eq!(resp.status, 0x00);
    assert!(resp.data.is_empty(), "no data-in phase on a SEND");
    assert_eq!(drive.bus_encryption_sector_extents, new_extents);
}

#[test]
fn mock_drive_empty_list_clears_extents() {
    // §4.14.5.2 paragraph 1: an N == 0 list clears the current extents.
    let mut drive = MockDrive::with_test_fixture();
    assert!(!drive.bus_encryption_sector_extents.is_empty());
    let cdb = SendDiscStructure::aacs_bus_encryption_sector_extents(0).cdb();
    let wire = build_send_disc_structure_bus_encryption_sector_extents(&[]);
    drive
        .execute(&cdb, DataDirection::ToDevice, &wire, 0)
        .unwrap();
    assert!(drive.bus_encryption_sector_extents.is_empty());
}

#[test]
fn mock_drive_rejects_unsorted_and_leaves_state() {
    let mut drive = MockDrive::with_test_fixture();
    let before = drive.bus_encryption_sector_extents.clone();
    // Descending Start LBA — not sorted.
    let bad = vec![extent(0x2000, 0x10), extent(0x1000, 0x10)];
    let cdb = SendDiscStructure::aacs_bus_encryption_sector_extents(bad.len()).cdb();
    let wire = build_send_disc_structure_bus_encryption_sector_extents(&bad);
    assert!(drive
        .execute(&cdb, DataDirection::ToDevice, &wire, 0)
        .is_err());
    assert_eq!(drive.bus_encryption_sector_extents, before);
}

#[test]
fn mock_drive_rejects_overlapping_extents() {
    let mut drive = MockDrive::with_test_fixture();
    let before = drive.bus_encryption_sector_extents.clone();
    // [0x1000, 0x1100) overlaps [0x1080, 0x1090).
    let bad = vec![extent(0x1000, 0x100), extent(0x1080, 0x10)];
    let cdb = SendDiscStructure::aacs_bus_encryption_sector_extents(bad.len()).cdb();
    let wire = build_send_disc_structure_bus_encryption_sector_extents(&bad);
    assert!(drive
        .execute(&cdb, DataDirection::ToDevice, &wire, 0)
        .is_err());
    assert_eq!(drive.bus_encryption_sector_extents, before);
}

#[test]
fn mock_drive_rejects_zero_lba_count() {
    let mut drive = MockDrive::with_test_fixture();
    let bad = vec![extent(0x1000, 0)];
    let cdb = SendDiscStructure::aacs_bus_encryption_sector_extents(bad.len()).cdb();
    let wire = build_send_disc_structure_bus_encryption_sector_extents(&bad);
    assert!(drive
        .execute(&cdb, DataDirection::ToDevice, &wire, 0)
        .is_err());
}

#[test]
fn mock_drive_rejects_extent_beyond_capacity() {
    let mut drive = MockDrive::with_test_fixture();
    drive.media_capacity_lba = 0x1_0000;
    // End = 0xFFF0 + 0x20 = 0x10010 > 0x10000 capacity.
    let bad = vec![extent(0xFFF0, 0x20)];
    let cdb = SendDiscStructure::aacs_bus_encryption_sector_extents(bad.len()).cdb();
    let wire = build_send_disc_structure_bus_encryption_sector_extents(&bad);
    assert!(drive
        .execute(&cdb, DataDirection::ToDevice, &wire, 0)
        .is_err());

    // An extent ending exactly at capacity is accepted.
    drive.max_bus_encryption_sector_extents = 1;
    let ok = vec![extent(0xFFF0, 0x10)];
    let cdb = SendDiscStructure::aacs_bus_encryption_sector_extents(ok.len()).cdb();
    let wire = build_send_disc_structure_bus_encryption_sector_extents(&ok);
    drive
        .execute(&cdb, DataDirection::ToDevice, &wire, 0)
        .unwrap();
    assert_eq!(drive.bus_encryption_sector_extents, ok);
}

#[test]
fn mock_drive_rejects_too_many_extents() {
    // §4.14.5.2: N exceeding the storable maximum → SYSTEM RESOURCE
    // FAILURE. With a storable maximum of 2, a 3-extent list is rejected.
    let mut drive = MockDrive::with_test_fixture();
    drive.max_bus_encryption_sector_extents = 2;
    drive.media_capacity_lba = u32::MAX;
    let before = drive.bus_encryption_sector_extents.clone();
    let bad = vec![extent(0, 0x10), extent(0x10, 0x10), extent(0x20, 0x10)];
    let cdb = SendDiscStructure::aacs_bus_encryption_sector_extents(bad.len()).cdb();
    let wire = build_send_disc_structure_bus_encryption_sector_extents(&bad);
    assert!(drive
        .execute(&cdb, DataDirection::ToDevice, &wire, 0)
        .is_err());
    assert_eq!(drive.bus_encryption_sector_extents, before);
}

#[test]
fn send_then_read_round_trips_extents() {
    // Host-visible coherence: after a SEND Format 0x85, a READ DISC
    // STRUCTURE Format 0x85 returns exactly the ingested extent table.
    let mut drive = MockDrive::with_test_fixture();
    drive.max_bus_encryption_sector_extents = 4;
    drive.media_capacity_lba = u32::MAX;
    let new_extents = vec![extent(0x40, 0x10), extent(0x80, 0x20)];

    let send_cdb = SendDiscStructure::aacs_bus_encryption_sector_extents(new_extents.len()).cdb();
    let wire = build_send_disc_structure_bus_encryption_sector_extents(&new_extents);
    drive
        .execute(&send_cdb, DataDirection::ToDevice, &wire, 0)
        .unwrap();

    let read_cdb = ReadDiscStructure::aacs_bus_encryption_sector_extents().cdb();
    let resp = drive
        .execute(&read_cdb, DataDirection::FromDevice, &[], 4108)
        .unwrap();
    let parsed = parse_bus_encryption_sector_extents_response(&resp.data).unwrap();
    assert_eq!(parsed.extents, new_extents);
    assert_eq!(parsed.maximum, 4);
}

#[test]
fn validate_standalone_rules() {
    // Empty list is always valid (the clear request).
    assert!(validate_bus_encryption_sector_extents(&[], 0).is_ok());
    // Sorted, non-overlapping, within capacity, non-zero counts.
    let good = [extent(0, 0x10), extent(0x10, 0x10), extent(0x100, 0x10)];
    assert!(validate_bus_encryption_sector_extents(&good, 0x200).is_ok());
    // Adjacent (touching but not overlapping) extents are valid.
    let touching = [extent(0, 0x10), extent(0x10, 0x10)];
    assert!(validate_bus_encryption_sector_extents(&touching, 0x20).is_ok());
    // u32::MAX capacity sentinel skips the capacity check.
    let high = [extent(0xFFFF_FF00, 0x10)];
    assert!(validate_bus_encryption_sector_extents(&high, u32::MAX).is_ok());
    // Each failure mode is rejected.
    assert!(validate_bus_encryption_sector_extents(&[extent(0, 0)], 0x100).is_err());
    assert!(
        validate_bus_encryption_sector_extents(&[extent(0x100, 0x10), extent(0, 0x10)], 0x200)
            .is_err()
    );
    assert!(
        validate_bus_encryption_sector_extents(&[extent(0, 0x100), extent(0x80, 0x10)], 0x200)
            .is_err()
    );
    assert!(validate_bus_encryption_sector_extents(&[extent(0x1F0, 0x20)], 0x200).is_err());
}
