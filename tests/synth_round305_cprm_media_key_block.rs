//! Round 305 integration tests — READ DISC STRUCTURE Format `0x86`
//! (CPRM Media Key Block) sub-payload wire format + handshake semantics.
//!
//! Format `0x86` transfers the CPRM Media Key Block recorded in the
//! Lead-in Area of AACS Recordable Media. Unlike the AACS MKB
//! (Format `0x83`, self-protected) the CPRM MKB's *first* pack is
//! transferred under the AACS authentication process: the drive
//! replaces the first 16 bytes of pack 0 with `CMAC(BK, MKB_Hash)`.
//! A header-only query (CDB Address `0x000000FF`) returns just the
//! 4-byte DISC STRUCTURE header (Total Packs) without authentication.
//!
//! All wire bytes are synthesised in-process. Truth sources:
//!
//!   * `docs/container/aacs/AACS_Spec_Common_Final_0953.pdf`
//!     §4.14.3.7 Table 4-21 (Format `0x86` response wire layout: 4-byte
//!     header `[Data Length:u16][Reserved:u8][Total Packs:u8]`, the
//!     24,576-byte MEDIA KEY BLOCK Pack Data, the `0x6002` full-pack
//!     length, the `0x000000FF` header-only Address sentinel returning
//!     length `0x0002`, the `CMAC(BK, MKB_Hash)` first-pack MAC, and
//!     the Total Packs = ceil(len / 24,576) rule).
//!   * `docs/container/aacs/mmc/aacs-keyclass-02-wire-format.md`
//!     §4.3 Format Code `0x86` (factual reference for the same layout).

use oxideav_aacs::aes::aes_128_cmac;
use oxideav_aacs::ake::DriveAuthState;
use oxideav_aacs::mmc::{
    CPRM_MKB_HEADER_ONLY_ADDRESS, CPRM_MKB_PACK_LEN, FORMAT_AACS_CPRM_MEDIA_KEY_BLOCK,
    MEDIA_TYPE_BD, READ_DISC_STRUCTURE_OPCODE,
};
use oxideav_aacs::{
    parse_cprm_mkb_pack_response, parse_volume_id_response, CprmMkbPackResponse, DataDirection,
    DriveCommand, MockDrive, Point, ReadDiscStructure, U160,
};

/// Plant a synthetic Bus Key directly into a placeholder
/// `DriveAuthState` (the §4.14.3.7 dispatcher branch reads only
/// `auth.bus_key` for the first-pack CMAC).
fn drive_with_bus_key(bus_key: [u8; 16]) -> MockDrive {
    let mut drive = MockDrive::with_test_fixture();
    let mut nonzero_be = [0u8; 20];
    nonzero_be[19] = 1;
    let mut state = DriveAuthState::new(
        [0u8; 92],
        U160::from_be_bytes(&nonzero_be),
        U160::from_be_bytes(&nonzero_be),
        [0u8; 20],
        Point::generator(),
    );
    state.bus_key = Some(bus_key);
    drive.auth = Some(state);
    drive
}

/// 4-byte fixed wire header: `[Data Length:u16][Reserved:u8][Total Packs:u8]`.
const HEADER_LEN: usize = 4;

fn read_pack(drive: &mut MockDrive, pack_number: u32) -> oxideav_aacs::ScsiResponse {
    let cdb = ReadDiscStructure::aacs_cprm_media_key_block_pack(1, pack_number).cdb();
    drive
        .execute(
            &cdb,
            DataDirection::FromDevice,
            &[],
            (HEADER_LEN + CPRM_MKB_PACK_LEN) as u16,
        )
        .unwrap()
}

#[test]
fn cdb_encodes_format_0x86_address_and_allocation() {
    let cdb = ReadDiscStructure::aacs_cprm_media_key_block_pack(2, 5).cdb();
    assert_eq!(cdb[0], READ_DISC_STRUCTURE_OPCODE);
    assert_eq!(cdb[1] & 0x0F, MEDIA_TYPE_BD);
    // Address (bytes 2..5, big-endian) = pack number 5.
    assert_eq!(u32::from_be_bytes([cdb[2], cdb[3], cdb[4], cdb[5]]), 5);
    assert_eq!(cdb[7], FORMAT_AACS_CPRM_MEDIA_KEY_BLOCK);
    // Allocation length = 4-byte header + 24,576-byte pack body.
    assert_eq!(
        u16::from_be_bytes([cdb[8], cdb[9]]),
        (HEADER_LEN + CPRM_MKB_PACK_LEN) as u16
    );
    // AGID in high 2 bits of byte 10.
    assert_eq!(cdb[10] >> 6, 2);
}

#[test]
fn header_only_address_query_returns_total_packs_without_body() {
    // §4.14.3.7 paragraph 3: Address 0x000000FF returns only the 4-byte
    // header (length 0x0002, no MKB Pack Data) and requires no auth.
    let mut drive = MockDrive::with_test_fixture();
    let cdb =
        ReadDiscStructure::aacs_cprm_media_key_block_pack(0, CPRM_MKB_HEADER_ONLY_ADDRESS).cdb();
    let resp = drive
        .execute(&cdb, DataDirection::FromDevice, &[], HEADER_LEN as u16)
        .unwrap();
    assert_eq!(resp.status, 0x00);
    // Fixture spans 24,577 bytes ⇒ ceil(24577 / 24576) = 2 packs.
    assert_eq!(resp.data, [0x00, 0x02, 0x00, 0x02]);
    let parsed = parse_cprm_mkb_pack_response(&resp.data).unwrap();
    assert_eq!(parsed.total_packs, 2);
    assert!(parsed.pack_data.is_empty());
}

#[test]
fn full_pack_response_has_spec_length_and_24576_byte_body() {
    let mut drive = MockDrive::with_test_fixture();
    let resp = read_pack(&mut drive, 0);
    assert_eq!(resp.status, 0x00);
    // DISC STRUCTURE Data Length = 0x6002 (24,576 body + 2 header tail).
    assert_eq!(u16::from_be_bytes([resp.data[0], resp.data[1]]), 0x6002);
    assert_eq!(resp.data[2], 0x00); // Reserved.
    assert_eq!(resp.data[3], 2); // Total Packs.
    assert_eq!(resp.data.len(), HEADER_LEN + CPRM_MKB_PACK_LEN);
    let parsed = parse_cprm_mkb_pack_response(&resp.data).unwrap();
    assert_eq!(parsed.total_packs, 2);
    assert_eq!(parsed.pack_data.len(), CPRM_MKB_PACK_LEN);
}

#[test]
fn static_mode_pack0_returns_verbatim_bytes() {
    // With no `auth` session the mock returns the verbatim fixture
    // bytes — pack 0 body is `0x86 ^ index` for index 0..24,576.
    let mut drive = MockDrive::with_test_fixture();
    let parsed = parse_cprm_mkb_pack_response(&read_pack(&mut drive, 0).data).unwrap();
    for (i, b) in parsed.pack_data.iter().enumerate() {
        assert_eq!(*b, 0x86u8 ^ (i as u8), "byte {i} mismatch");
    }
}

#[test]
fn final_pack_is_zero_padded_to_full_pack_length() {
    // Fixture pack 1 carries exactly one body byte (index 24,576 of the
    // source) then zero-padding to 24,576 bytes.
    let mut drive = MockDrive::with_test_fixture();
    let parsed = parse_cprm_mkb_pack_response(&read_pack(&mut drive, 1).data).unwrap();
    assert_eq!(parsed.pack_data.len(), CPRM_MKB_PACK_LEN);
    // First body byte = source index 24,576 ⇒ 0x86 ^ (24576 % 256) = 0x86.
    assert_eq!(parsed.pack_data[0], 0x86u8 ^ (CPRM_MKB_PACK_LEN as u8));
    // Everything after is zero-fill.
    assert!(parsed.pack_data[1..].iter().all(|&b| b == 0));
}

#[test]
fn out_of_range_pack_index_is_rejected() {
    // Fixture has 2 packs; requesting pack 2 fails.
    let mut drive = MockDrive::with_test_fixture();
    let cdb = ReadDiscStructure::aacs_cprm_media_key_block_pack(1, 2).cdb();
    let err = drive.execute(
        &cdb,
        DataDirection::FromDevice,
        &[],
        (HEADER_LEN + CPRM_MKB_PACK_LEN) as u16,
    );
    assert!(err.is_err());
}

#[test]
fn empty_cprm_mkb_reports_zero_total_packs() {
    // Media with no CPRM MKB: Total Packs = 0, header-only query works.
    let mut drive = MockDrive::with_test_fixture();
    drive.cprm_media_key_block = Vec::new();
    let cdb =
        ReadDiscStructure::aacs_cprm_media_key_block_pack(0, CPRM_MKB_HEADER_ONLY_ADDRESS).cdb();
    let resp = drive
        .execute(&cdb, DataDirection::FromDevice, &[], HEADER_LEN as u16)
        .unwrap();
    assert_eq!(resp.data, [0x00, 0x02, 0x00, 0x00]);
    assert_eq!(
        parse_cprm_mkb_pack_response(&resp.data)
            .unwrap()
            .total_packs,
        0
    );
}

#[test]
fn total_packs_is_ceiling_of_length_over_24576() {
    // ceil(len / 24,576): exercise exact-multiple and remainder cases.
    for (len, expected) in [
        (0usize, 0u8),
        (1, 1),
        (CPRM_MKB_PACK_LEN, 1),
        (CPRM_MKB_PACK_LEN + 1, 2),
        (3 * CPRM_MKB_PACK_LEN, 3),
        (3 * CPRM_MKB_PACK_LEN - 1, 3),
    ] {
        let mut drive = MockDrive::with_test_fixture();
        drive.cprm_media_key_block = vec![0xAB; len];
        let cdb =
            ReadDiscStructure::aacs_cprm_media_key_block_pack(0, CPRM_MKB_HEADER_ONLY_ADDRESS)
                .cdb();
        let resp = drive
            .execute(&cdb, DataDirection::FromDevice, &[], HEADER_LEN as u16)
            .unwrap();
        assert_eq!(
            parse_cprm_mkb_pack_response(&resp.data)
                .unwrap()
                .total_packs,
            expected,
            "len {len}"
        );
    }
}

#[test]
fn parser_rejects_invalid_body_length() {
    // The parser accepts only body lengths 0 or 24,576; a length of,
    // say, 100 is an error.
    let mut buf = vec![0x00, 0x66, 0x00, 0x01]; // length 0x0066 = 102 ⇒ body 100.
    buf.extend_from_slice(&[0u8; 100]);
    assert!(parse_cprm_mkb_pack_response(&buf).is_err());
}

#[test]
fn parser_rejects_truncated_payload() {
    // Claims a full pack but only 10 body bytes present.
    let mut buf = vec![0x60, 0x02, 0x00, 0x01];
    buf.extend_from_slice(&[0u8; 10]);
    assert!(parse_cprm_mkb_pack_response(&buf).is_err());
}

#[test]
fn parser_rejects_length_below_minimum() {
    // Length < 2 is invalid (must at least cover reserved + total_packs).
    let buf = [0x00, 0x01, 0x00, 0x00];
    assert!(parse_cprm_mkb_pack_response(&buf).is_err());
}

#[test]
fn round_trips_through_dispatcher_and_parser() {
    // Serialise via the dispatcher, parse back, demand structural
    // equality against a hand-built expectation.
    let mut drive = MockDrive::with_test_fixture();
    let wire = read_pack(&mut drive, 0).data;
    let parsed = parse_cprm_mkb_pack_response(&wire).unwrap();
    let mut expected_body = vec![0u8; CPRM_MKB_PACK_LEN];
    for (i, b) in expected_body.iter_mut().enumerate() {
        *b = 0x86u8 ^ (i as u8);
    }
    assert_eq!(
        parsed,
        CprmMkbPackResponse {
            total_packs: 2,
            pack_data: expected_body,
        }
    );
}

#[test]
fn auth_mode_pack0_first_16_bytes_are_cmac_of_mkb_hash() {
    // §4.14.3.7 final paragraph: for the first pack the drive replaces
    // the first 16 bytes of the MKB Descriptor with CMAC(BK, MKB_Hash).
    let bus_key = [0x12u8; 16];
    let mut drive = drive_with_bus_key(bus_key);
    let mkb_hash = drive.cprm_mkb_hash;
    let parsed = parse_cprm_mkb_pack_response(&read_pack(&mut drive, 0).data).unwrap();
    let expected_mac = aes_128_cmac(&bus_key, &mkb_hash);
    assert_eq!(&parsed.pack_data[..16], &expected_mac);
    // Bytes 16.. are the verbatim fixture body (0x86 ^ index).
    for i in 16..CPRM_MKB_PACK_LEN {
        assert_eq!(parsed.pack_data[i], 0x86u8 ^ (i as u8), "byte {i}");
    }
}

#[test]
fn auth_mode_non_first_pack_is_not_mac_replaced() {
    // Only pack 0 carries the CMAC; pack 1 is verbatim (then padded).
    let bus_key = [0x34u8; 16];
    let mut drive = drive_with_bus_key(bus_key);
    let parsed = parse_cprm_mkb_pack_response(&read_pack(&mut drive, 1).data).unwrap();
    // First body byte = source index 24,576 ⇒ 0x86 ^ (24576 % 256) = 0x86.
    assert_eq!(parsed.pack_data[0], 0x86u8 ^ (CPRM_MKB_PACK_LEN as u8));
    assert!(parsed.pack_data[1..].iter().all(|&b| b == 0));
}

#[test]
fn auth_started_but_no_bus_key_fails_for_pack0() {
    // §4.14.3.7: the first pack requires the AACS authentication
    // process. An `auth` slot present but without a derived Bus Key is
    // the spec-mandated error path.
    let mut drive = MockDrive::with_test_fixture();
    drive.auth = Some(DriveAuthState::new(
        [0u8; 92],
        U160 {
            limbs: [1, 0, 0, 0, 0],
        },
        U160 {
            limbs: [1, 0, 0, 0, 0],
        },
        [0u8; 20],
        Point::generator(),
    ));
    let cdb = ReadDiscStructure::aacs_cprm_media_key_block_pack(1, 0).cdb();
    let err = drive.execute(
        &cdb,
        DataDirection::FromDevice,
        &[],
        (HEADER_LEN + CPRM_MKB_PACK_LEN) as u16,
    );
    assert!(err.is_err());
}

#[test]
fn auth_started_but_no_bus_key_still_allows_header_only_query() {
    // The header-only Total-Packs query requires no authentication even
    // when an auth session is mid-flight without a Bus Key.
    let mut drive = MockDrive::with_test_fixture();
    drive.auth = Some(DriveAuthState::new(
        [0u8; 92],
        U160 {
            limbs: [1, 0, 0, 0, 0],
        },
        U160 {
            limbs: [1, 0, 0, 0, 0],
        },
        [0u8; 20],
        Point::generator(),
    ));
    let cdb =
        ReadDiscStructure::aacs_cprm_media_key_block_pack(0, CPRM_MKB_HEADER_ONLY_ADDRESS).cdb();
    let resp = drive
        .execute(&cdb, DataDirection::FromDevice, &[], HEADER_LEN as u16)
        .unwrap();
    assert_eq!(resp.data, [0x00, 0x02, 0x00, 0x02]);
}

#[test]
fn format_0x86_does_not_disturb_other_format_dispatch_paths() {
    // Format 0x80 (Volume ID) responses must be byte-equal before and
    // after a Format 0x86 call — the dispatcher arms are side-effect-free
    // with respect to one another.
    let mut drive = MockDrive::with_test_fixture();
    let cdb_volume = ReadDiscStructure::aacs_volume_id(1).cdb();
    let v1 = drive
        .execute(&cdb_volume, DataDirection::FromDevice, &[], 36)
        .unwrap();
    let _ = read_pack(&mut drive, 0);
    let v2 = drive
        .execute(&cdb_volume, DataDirection::FromDevice, &[], 36)
        .unwrap();
    assert_eq!(v1.data, v2.data);
    assert_eq!(
        parse_volume_id_response(&v1.data).unwrap().volume_id,
        parse_volume_id_response(&v2.data).unwrap().volume_id
    );
}
