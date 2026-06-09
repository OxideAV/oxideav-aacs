//! Round 265 integration tests — Format `0x85` Bus-Encryption Sector
//! Extents handshake semantics complementary to the wire-shape coverage in
//! `synth_round246_bus_encryption_sector_extents.rs` and the unit suite in
//! `src/mmc.rs`.
//!
//! These cases exercise the host-side discovery flow as a whole: idempotent
//! re-fetch under [`MockDrive`], runtime mutation of the advertised extent
//! table between two CDB issuances, no cross-talk against other READ DISC
//! STRUCTURE Format Codes (e.g. `0x80` Volume ID), worst-case allocation
//! sizing, AGID-zeroed-regardless-of-fixture invariant, semantic
//! "is LBA X bus-encrypted" derivations, u32 boundary values, and an
//! encode → decode → re-encode round-trip equality test.
//!
//! All wire bytes are synthesised in-process. Truth sources:
//!
//!   * `docs/container/aacs/AACS_Spec_Common_Final_0953.pdf`
//!     §4.14.3.6 Table 4-20 (Format `0x85` response wire layout,
//!     "Maximum = 0 ⇒ 256" sentinel, ascending-Start-LBA ordering,
//!     no-AACS-authentication-required note).
//!   * `docs/container/aacs/mmc/aacs-keyclass-02-wire-format.md`
//!     §4.3 Format Code `0x85` (factual reference table for the same
//!     layout).

use oxideav_aacs::{
    parse_bus_encryption_sector_extents_response, parse_volume_id_response,
    BusEncryptionSectorExtent, BusEncryptionSectorExtentsResponse, DataDirection, DriveCommand,
    MockDrive, ReadDiscStructure,
};

/// 4-byte fixed wire header: `[Data Length:u16][Reserved:u8][Maximum:u8]`.
const HEADER_LEN: usize = 4;
const EXTENT_RECORD_LEN: usize = 16;
/// Worst-case CDB allocation: `12 + 256 * 16 = 4108` (§4.14.3.6 ceiling;
/// the 12-byte header allowance includes the 8 reserved bytes prefixing
/// the first extent record).
const WORST_CASE_ALLOC: u16 = 4108;

fn ext(start: u32, count: u32) -> BusEncryptionSectorExtent {
    BusEncryptionSectorExtent {
        start_lba: start,
        lba_count: count,
    }
}

fn fetch(drive: &mut MockDrive) -> Vec<u8> {
    let cdb = ReadDiscStructure::aacs_bus_encryption_sector_extents().cdb();
    drive
        .execute(&cdb, DataDirection::FromDevice, &[], WORST_CASE_ALLOC)
        .unwrap()
        .data
}

/// First extent (by index) whose half-open `[start, start+count)` window
/// contains `lba`. Pure host-side helper — not a re-implementation of any
/// spec rule; §4.14.3.6 fixes the wire layout only.
fn extent_covering(resp: &BusEncryptionSectorExtentsResponse, lba: u32) -> Option<usize> {
    resp.extents.iter().position(|e| {
        match e.start_lba.checked_add(e.lba_count) {
            Some(end) => lba >= e.start_lba && lba < end,
            // Overflow at top of u32 LBA space: covers everything ≥ start.
            None => lba >= e.start_lba,
        }
    })
}

#[test]
fn repeated_fetches_return_identical_wire_bytes() {
    // Format 0x85 requires no authentication: back-to-back fetches with
    // unchanged drive state must yield byte-equal responses (idempotent
    // dispatch).
    let mut drive = MockDrive::with_test_fixture();
    let r1 = fetch(&mut drive);
    let r2 = fetch(&mut drive);
    let r3 = fetch(&mut drive);
    assert_eq!(r1, r2);
    assert_eq!(r2, r3);
}

#[test]
fn mutating_extent_table_between_fetches_is_reflected_on_the_wire() {
    // Host workflow: fetch, observe an update, re-fetch. The second
    // fetch must show the mutated table — confirms the dispatcher reads
    // the field live rather than caching the prior serialisation.
    let mut drive = MockDrive::with_test_fixture();
    let first = fetch(&mut drive);
    assert_eq!(
        parse_bus_encryption_sector_extents_response(&first)
            .unwrap()
            .extents
            .len(),
        2
    );
    // Append a third extent in ascending order (§4.14.3.6 paragraph 3).
    drive
        .bus_encryption_sector_extents
        .push(ext(0x00FF_0000, 0x0000_0100));
    let second = fetch(&mut drive);
    let parsed = parse_bus_encryption_sector_extents_response(&second).unwrap();
    assert_eq!(parsed.extents.len(), 3);
    assert_eq!(parsed.extents[2], ext(0x00FF_0000, 0x0000_0100));
    assert_eq!(second.len(), first.len() + EXTENT_RECORD_LEN);
    let first_len = u16::from_be_bytes([first[0], first[1]]);
    let second_len = u16::from_be_bytes([second[0], second[1]]);
    assert_eq!(second_len, first_len + EXTENT_RECORD_LEN as u16);
}

#[test]
fn agid_byte_stays_zero_regardless_of_mock_drive_agid_field() {
    // The CDB constructor is fixed; setting MockDrive's `agid_to_return`
    // must not influence Format 0x85 dispatching (no auth required,
    // §4.14.3.6 final sentence).
    let mut drive = MockDrive::with_test_fixture();
    drive.agid_to_return = 3;
    let cdb = ReadDiscStructure::aacs_bus_encryption_sector_extents().cdb();
    assert_eq!(cdb[10], 0x00);
    let resp = drive
        .execute(&cdb, DataDirection::FromDevice, &[], WORST_CASE_ALLOC)
        .unwrap();
    assert_eq!(resp.status, 0x00);
}

#[test]
fn format_0x85_does_not_disturb_other_format_dispatch_paths() {
    // Format 0x80 (Volume ID) responses must be byte-equal before and
    // after a Format 0x85 call — pins the dispatcher's per-format arms
    // as side-effect-free with respect to one another.
    let mut drive = MockDrive::with_test_fixture();
    let cdb_volume = ReadDiscStructure::aacs_volume_id(1).cdb();
    let v1 = drive
        .execute(&cdb_volume, DataDirection::FromDevice, &[], 36)
        .unwrap();
    let _ = fetch(&mut drive);
    let v2 = drive
        .execute(&cdb_volume, DataDirection::FromDevice, &[], 36)
        .unwrap();
    assert_eq!(v1.data, v2.data);
    assert_eq!(
        parse_volume_id_response(&v1.data).unwrap().volume_id,
        parse_volume_id_response(&v2.data).unwrap().volume_id
    );
}

#[test]
fn worst_case_allocation_length_accommodates_256_extent_response() {
    // §4.14.3.6 caps the table at 256 extents; the CDB allocation length
    // is `12 + 256 * 16 = 4108` bytes so a fully-populated response fits.
    assert_eq!(WORST_CASE_ALLOC, 12u16 + 256u16 * EXTENT_RECORD_LEN as u16);
    let cdb = ReadDiscStructure::aacs_bus_encryption_sector_extents().cdb();
    assert_eq!(u16::from_be_bytes([cdb[8], cdb[9]]), WORST_CASE_ALLOC);
}

#[test]
fn encode_decode_re_encode_round_trips_identically() {
    // Serialise via the MockDrive dispatcher, parse back, then re-encode
    // by hand and demand byte equality. Pins the parser and dispatcher
    // as inverses on the §4.14.3.6 Table 4-20 layout.
    let mut drive = MockDrive::with_test_fixture();
    drive.bus_encryption_sector_extents = vec![
        ext(0x0000_0042, 0x0000_0001),
        ext(0x000A_0000, 0x0000_F000),
        ext(0x1234_5678, 0x0000_0010),
    ];
    drive.max_bus_encryption_sector_extents = 5;
    let wire = fetch(&mut drive);
    let parsed = parse_bus_encryption_sector_extents_response(&wire).unwrap();

    let n = parsed.extents.len();
    let length = (n * EXTENT_RECORD_LEN + 2) as u16;
    let mut reencoded = Vec::with_capacity(HEADER_LEN + n * EXTENT_RECORD_LEN);
    reencoded.extend_from_slice(&length.to_be_bytes());
    reencoded.push(0x00);
    // 256 → wire byte 0 sentinel; other values pass through.
    let max_byte = if parsed.maximum == 256 {
        0x00
    } else {
        parsed.maximum as u8
    };
    reencoded.push(max_byte);
    for e in &parsed.extents {
        reencoded.extend_from_slice(&[0u8; 8]);
        reencoded.extend_from_slice(&e.start_lba.to_be_bytes());
        reencoded.extend_from_slice(&e.lba_count.to_be_bytes());
    }
    assert_eq!(reencoded, wire);
}

#[test]
fn host_can_classify_lba_membership_against_advertised_extents() {
    // Pins the half-open `[start, start + count)` interpretation of
    // Table 4-20's Start LBA / LBA Count pair. Two extents with a gap
    // between them.
    let mut drive = MockDrive::with_test_fixture();
    drive.bus_encryption_sector_extents =
        vec![ext(0x0000_1000, 0x0000_0100), ext(0x0001_0000, 0x0000_0010)];
    drive.max_bus_encryption_sector_extents = 4;
    let wire = fetch(&mut drive);
    let parsed = parse_bus_encryption_sector_extents_response(&wire).unwrap();
    // Extent 0: 0x1000..0x1100.
    assert_eq!(extent_covering(&parsed, 0x0000_1000), Some(0));
    assert_eq!(extent_covering(&parsed, 0x0000_10FF), Some(0));
    assert_eq!(extent_covering(&parsed, 0x0000_1100), None);
    assert_eq!(extent_covering(&parsed, 0x0000_0FFF), None);
    // Extent 1: 0x10000..0x10010.
    assert_eq!(extent_covering(&parsed, 0x0001_0000), Some(1));
    assert_eq!(extent_covering(&parsed, 0x0001_000F), Some(1));
    assert_eq!(extent_covering(&parsed, 0x0001_0010), None);
    // Gap.
    assert_eq!(extent_covering(&parsed, 0x0000_8000), None);
}

#[test]
fn u32_boundary_extents_round_trip_through_the_wire() {
    // Pin big-endian field decoding at the u32 boundaries: LBA 0 and an
    // extent that saturates the top of the 32-bit LBA space. The helper
    // must not panic on the overflow case.
    let mut drive = MockDrive::with_test_fixture();
    drive.bus_encryption_sector_extents =
        vec![ext(0x0000_0000, 0x0000_0008), ext(0xFFFF_FFF0, 0x0000_0010)];
    drive.max_bus_encryption_sector_extents = 2;
    let wire = fetch(&mut drive);
    let parsed = parse_bus_encryption_sector_extents_response(&wire).unwrap();
    assert_eq!(parsed.extents[0], ext(0, 0x0000_0008));
    assert_eq!(parsed.extents[1], ext(0xFFFF_FFF0, 0x0000_0010));
    assert_eq!(extent_covering(&parsed, 0), Some(0));
    assert_eq!(extent_covering(&parsed, 7), Some(0));
    assert_eq!(extent_covering(&parsed, 8), None);
    assert_eq!(extent_covering(&parsed, 0xFFFF_FFEF), None);
    assert_eq!(extent_covering(&parsed, 0xFFFF_FFF0), Some(1));
    assert_eq!(extent_covering(&parsed, 0xFFFF_FFFF), Some(1));
}

#[test]
fn maximum_field_is_a_capacity_claim_not_a_count() {
    // §4.14.3.6 byte 3 is the *maximum* extents the drive can ever
    // store, not the count currently published. Round-trip both fields
    // independently across several combinations.
    for (max, n) in [(1u16, 0usize), (16, 2), (4, 1), (256, 0)] {
        let mut drive = MockDrive::with_test_fixture();
        drive.max_bus_encryption_sector_extents = max;
        drive.bus_encryption_sector_extents = (0..n)
            .map(|i| ext(0x0001_0000 + (i as u32) * 0x10_0000, 0x0000_0100))
            .collect();
        let wire = fetch(&mut drive);
        let parsed = parse_bus_encryption_sector_extents_response(&wire).unwrap();
        assert_eq!(parsed.maximum, max);
        assert_eq!(parsed.extents.len(), n);
    }
}

#[test]
fn default_mock_drive_advertises_empty_table_with_maximum_1() {
    // The non-fixture `Default` initialiser publishes an empty table and
    // Maximum = 1 (the spec-required minimum). The host sees Data
    // Length = 2 and an empty extent list.
    let mut drive = MockDrive::default();
    let cdb = ReadDiscStructure::aacs_bus_encryption_sector_extents().cdb();
    let resp = drive
        .execute(&cdb, DataDirection::FromDevice, &[], WORST_CASE_ALLOC)
        .unwrap();
    assert_eq!(resp.status, 0x00);
    assert_eq!(resp.data, [0x00, 0x02, 0x00, 0x01]);
    let parsed = parse_bus_encryption_sector_extents_response(&resp.data).unwrap();
    assert_eq!(parsed.maximum, 1);
    assert!(parsed.extents.is_empty());
}

#[test]
fn data_length_field_matches_extent_count_in_both_dimensions() {
    // Cross-check: for N in 0..=8, on-wire Data Length = N*16 + 2 AND
    // total buffer length = HEADER_LEN + N*16. Catches off-by-ones that
    // pass the wire-shape unit tests but slip the dispatcher arithmetic.
    for n in 0..=8usize {
        let mut drive = MockDrive::with_test_fixture();
        drive.max_bus_encryption_sector_extents = 8;
        drive.bus_encryption_sector_extents = (0..n)
            .map(|i| ext((i as u32) * 0x0000_2000, 0x0000_0100))
            .collect();
        let wire = fetch(&mut drive);
        let length = u16::from_be_bytes([wire[0], wire[1]]);
        assert_eq!(length as usize, n * EXTENT_RECORD_LEN + 2);
        assert_eq!(wire.len(), HEADER_LEN + n * EXTENT_RECORD_LEN);
        assert_eq!(
            parse_bus_encryption_sector_extents_response(&wire)
                .unwrap()
                .extents
                .len(),
            n
        );
    }
}
