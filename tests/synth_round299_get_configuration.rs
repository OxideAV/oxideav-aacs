//! Round 299 integration tests — `GET CONFIGURATION` (`0x46`) CDB +
//! the **AACS Feature Descriptor** (Feature Code `0x010D`) per AACS
//! Common Final 0.953 §4.14.1 Table 4-4 and MMC-6 r02g §6.5 (Table 256,
//! Table 257) / §5.2 (Tables 86–88).
//!
//! Wire layout exercised:
//! - the 10-byte GET CONFIGURATION CDB (opcode `0x46`, RT in byte 1 low
//!   2 bits, Starting Feature Number bytes 2..3 big-endian, Allocation
//!   Length bytes 7..8 big-endian),
//! - the 8-byte AACS Feature Descriptor (generic 4-byte Feature
//!   Descriptor header — Feature Code `0x010D`, Version `0010b`,
//!   Persistent/Current bits, Additional Length `04h` — plus the 4-byte
//!   Feature Dependent Data: byte 4 RDC/RMC/WBE/BEC/BNG flags, byte 5
//!   Block Count for Binding Nonce, byte 6 Number of AGIDs, byte 7 AACS
//!   version `01h`),
//! - the Feature-list walk that locates the AACS descriptor inside a
//!   full GET CONFIGURATION response (8-byte Feature Header + variable
//!   descriptors).
//!
//! No real disc, no real drive, no real key material.

use oxideav_aacs::mmc::{
    AACS_FEATURE_AACS_VERSION, AACS_FEATURE_ADDITIONAL_LENGTH, AACS_FEATURE_DESCRIPTOR_LEN,
    AACS_FEATURE_VERSION, FEATURE_AACS, FEATURE_HEADER_LEN, GET_CONFIGURATION_CDB_LEN,
    GET_CONFIGURATION_OPCODE, GET_CONFIG_RT_ONE,
};
use oxideav_aacs::{
    build_get_configuration_aacs_response, find_aacs_feature_descriptor,
    parse_aacs_feature_descriptor, AacsError, AacsFeatureDescriptor, GetConfiguration,
};

fn sample_descriptor() -> AacsFeatureDescriptor {
    AacsFeatureDescriptor {
        current: true,
        persistent: false,
        version: AACS_FEATURE_VERSION,
        read_drive_certificate: true,
        return_mkb_of_cprm: false,
        write_bus_encryption: true,
        bus_encryption_capable: true,
        binding_nonce_generation: true,
        block_count_for_binding_nonce: 1,
        number_of_agids: 4,
        aacs_version: AACS_FEATURE_AACS_VERSION,
    }
}

#[test]
fn get_configuration_aacs_cdb_byte_layout() {
    let cdb = GetConfiguration::aacs_feature().cdb();
    assert_eq!(cdb.len(), GET_CONFIGURATION_CDB_LEN);
    assert_eq!(cdb[0], GET_CONFIGURATION_OPCODE, "opcode must be 0x46");
    assert_eq!(cdb[0], 0x46);
    assert_eq!(cdb[1] & 0x03, GET_CONFIG_RT_ONE, "RT = 10b");
    // Starting Feature Number = 0x010D, big-endian in bytes 2..3.
    assert_eq!(cdb[2], 0x01);
    assert_eq!(cdb[3], 0x0D);
    // Reserved bytes.
    assert_eq!(cdb[4], 0);
    assert_eq!(cdb[5], 0);
    assert_eq!(cdb[6], 0);
    // Allocation Length = header (8) + descriptor (8) = 16, big-endian.
    assert_eq!(cdb[7], 0x00);
    assert_eq!(cdb[8], 0x10);
    assert_eq!(cdb[9], 0, "control");
}

#[test]
fn get_configuration_cdb_round_trip() {
    let cmd = GetConfiguration {
        rt: GET_CONFIG_RT_ONE,
        starting_feature: FEATURE_AACS,
        allocation_length: 0xABCD,
        control: 0x00,
    };
    let parsed = GetConfiguration::parse_cdb(&cmd.cdb()).unwrap();
    assert_eq!(parsed, cmd);
}

#[test]
fn get_configuration_parse_rejects_wrong_opcode() {
    let mut cdb = GetConfiguration::aacs_feature().cdb();
    cdb[0] = 0xA4;
    assert!(matches!(
        GetConfiguration::parse_cdb(&cdb),
        Err(AacsError::InvalidValue { .. })
    ));
}

#[test]
fn aacs_feature_descriptor_byte_layout() {
    let desc = sample_descriptor();
    let bytes = desc.to_bytes();
    assert_eq!(bytes.len(), AACS_FEATURE_DESCRIPTOR_LEN);
    // Feature Code 0x010D big-endian.
    assert_eq!(bytes[0], 0x01);
    assert_eq!(bytes[1], 0x0D);
    // byte 2: Version (0010b) << 2 | Persistent(0) << 1 | Current(1).
    assert_eq!(bytes[2], (AACS_FEATURE_VERSION << 2) | 0b01);
    assert_eq!(bytes[2] & 0x01, 1, "Current bit");
    assert_eq!(bytes[2] & 0x02, 0, "Persistent bit clear");
    assert_eq!((bytes[2] >> 2) & 0x0F, AACS_FEATURE_VERSION);
    // byte 3: Additional Length 04h.
    assert_eq!(bytes[3], AACS_FEATURE_ADDITIONAL_LENGTH);
    assert_eq!(bytes[3], 0x04);
    // byte 4 flags: RDC(1) RMC(0) WBE(1) BEC(1) ...(0) BNG(1).
    assert_eq!(bytes[4] & 0x80, 0x80, "RDC");
    assert_eq!(bytes[4] & 0x40, 0x00, "RMC");
    assert_eq!(bytes[4] & 0x20, 0x20, "WBE");
    assert_eq!(bytes[4] & 0x10, 0x10, "BEC");
    assert_eq!(bytes[4] & 0x01, 0x01, "BNG");
    // byte 5 Block Count, byte 6 Number of AGIDs (bits 2..0), byte 7 ver.
    assert_eq!(bytes[5], 1);
    assert_eq!(bytes[6] & 0x07, 4);
    assert_eq!(bytes[7], AACS_FEATURE_AACS_VERSION);
    assert_eq!(bytes[7], 0x01);
}

#[test]
fn aacs_feature_descriptor_round_trip() {
    let desc = sample_descriptor();
    let parsed = parse_aacs_feature_descriptor(&desc.to_bytes()).unwrap();
    assert_eq!(parsed, desc);
}

#[test]
fn aacs_feature_descriptor_all_flags_clear_round_trip() {
    let desc = AacsFeatureDescriptor {
        current: false,
        persistent: false,
        version: AACS_FEATURE_VERSION,
        read_drive_certificate: false,
        return_mkb_of_cprm: false,
        write_bus_encryption: false,
        bus_encryption_capable: false,
        binding_nonce_generation: false,
        block_count_for_binding_nonce: 0,
        number_of_agids: 0,
        aacs_version: AACS_FEATURE_AACS_VERSION,
    };
    let parsed = parse_aacs_feature_descriptor(&desc.to_bytes()).unwrap();
    assert_eq!(parsed, desc);
}

#[test]
fn aacs_feature_descriptor_all_flags_set_round_trip() {
    let desc = AacsFeatureDescriptor {
        current: true,
        persistent: true,
        version: AACS_FEATURE_VERSION,
        read_drive_certificate: true,
        return_mkb_of_cprm: true,
        write_bus_encryption: true,
        bus_encryption_capable: true,
        binding_nonce_generation: true,
        block_count_for_binding_nonce: 0xFF,
        number_of_agids: 7,
        aacs_version: AACS_FEATURE_AACS_VERSION,
    };
    let parsed = parse_aacs_feature_descriptor(&desc.to_bytes()).unwrap();
    assert_eq!(parsed, desc);
}

#[test]
fn aacs_feature_descriptor_number_of_agids_masked_to_three_bits() {
    // The Number of AGIDs field is only 3 bits wide (Table 4-4 byte 6);
    // a value beyond 7 must not bleed into reserved bits.
    let mut desc = sample_descriptor();
    desc.number_of_agids = 5;
    let bytes = desc.to_bytes();
    assert_eq!(bytes[6] & 0xF8, 0, "reserved upper bits of byte 6 clear");
    assert_eq!(
        parse_aacs_feature_descriptor(&bytes)
            .unwrap()
            .number_of_agids,
        5
    );
}

#[test]
fn parse_rejects_truncated_descriptor() {
    let bytes = sample_descriptor().to_bytes();
    assert!(matches!(
        parse_aacs_feature_descriptor(&bytes[..AACS_FEATURE_DESCRIPTOR_LEN - 1]),
        Err(AacsError::Truncated(_))
    ));
}

#[test]
fn parse_rejects_wrong_feature_code() {
    let mut bytes = sample_descriptor().to_bytes();
    bytes[0] = 0x00;
    bytes[1] = 0x10; // Feature Code 0x0010 (Random Readable), not AACS.
    assert!(matches!(
        parse_aacs_feature_descriptor(&bytes),
        Err(AacsError::InvalidValue { .. })
    ));
}

#[test]
fn parse_rejects_wrong_additional_length() {
    let mut bytes = sample_descriptor().to_bytes();
    bytes[3] = 0x08; // Spec fixes Additional Length at 04h for AACS.
    assert!(matches!(
        parse_aacs_feature_descriptor(&bytes),
        Err(AacsError::InvalidValue { .. })
    ));
}

#[test]
fn full_response_round_trip_finds_aacs_descriptor() {
    let desc = sample_descriptor();
    let response = build_get_configuration_aacs_response(&desc, 0x0040);
    // Feature Header (8) + descriptor (8).
    assert_eq!(
        response.len(),
        FEATURE_HEADER_LEN + AACS_FEATURE_DESCRIPTOR_LEN
    );
    // Data Length counts everything after itself: 4 (rest of header) + 8.
    assert_eq!(
        u32::from_be_bytes([response[0], response[1], response[2], response[3]]),
        12
    );
    // Current Profile 0x0040, big-endian, bytes 6..7.
    assert_eq!(response[6], 0x00);
    assert_eq!(response[7], 0x40);
    let found = find_aacs_feature_descriptor(&response).unwrap().unwrap();
    assert_eq!(found, desc);
}

#[test]
fn find_skips_leading_non_aacs_descriptors() {
    let desc = sample_descriptor();
    // Hand-build a response: 8-byte header, then a 12-byte Core feature
    // (Feature Code 0x0001, Additional Length 0x08), then the AACS one.
    let mut response = Vec::new();
    response.extend_from_slice(&0u32.to_be_bytes()); // Data Length (unused by walk)
    response.extend_from_slice(&[0, 0, 0, 0]); // reserved + Current Profile
                                               // Core feature: code 0x0001, byte2=0, additional length 8, 8 bytes data.
    response.extend_from_slice(&[0x00, 0x01, 0x00, 0x08]);
    response.extend_from_slice(&[0u8; 8]);
    // AACS descriptor.
    response.extend_from_slice(&desc.to_bytes());
    let found = find_aacs_feature_descriptor(&response).unwrap().unwrap();
    assert_eq!(found, desc);
}

#[test]
fn find_returns_none_when_no_aacs_descriptor() {
    // Header + one non-AACS descriptor (Random Readable 0x0010).
    let mut response = Vec::new();
    response.extend_from_slice(&[0u8; FEATURE_HEADER_LEN]);
    response.extend_from_slice(&[0x00, 0x10, 0x00, 0x08]);
    response.extend_from_slice(&[0u8; 8]);
    assert_eq!(find_aacs_feature_descriptor(&response).unwrap(), None);
}

#[test]
fn find_rejects_truncated_header() {
    assert!(matches!(
        find_aacs_feature_descriptor(&[0u8; 4]),
        Err(AacsError::Truncated(_))
    ));
}

#[test]
fn find_rejects_descriptor_overrunning_buffer() {
    let mut response = Vec::new();
    response.extend_from_slice(&[0u8; FEATURE_HEADER_LEN]);
    // Declares Additional Length 0x40 but provides no data bytes.
    response.extend_from_slice(&[0x01, 0x0D, 0x00, 0x40]);
    assert!(matches!(
        find_aacs_feature_descriptor(&response),
        Err(AacsError::Truncated(_))
    ));
}

#[test]
fn empty_feature_list_after_header_returns_none() {
    let response = [0u8; FEATURE_HEADER_LEN];
    assert_eq!(find_aacs_feature_descriptor(&response).unwrap(), None);
}
