//! Round 269 integration tests — SEND DISC STRUCTURE Format `0x84`
//! (Write Data Key) host→drive sub-payload through the in-process
//! [`MockDrive`].
//!
//! Wire layout exercised: CDB per AACS Common §4.14.5 Table 4-26
//! (opcode `0xBF`, Media Type BD, Format Code `0x84`, Parameter List
//! Length 20, AGID in bits 7..6 of byte 10) and parameter list per
//! §4.14.5.1 Table 4-28 (`[length:u16=0x0012][reserved:u16][Kwd:16]`,
//! the Write Data Key encrypted by the Bus Key using AES-128E).
//!
//! No real disc, no real drive — every byte sequence is synthesised
//! from values defined in this file. The Bus-Key wrap step is
//! exercised both against a planted synthetic Bus Key and against a
//! Bus Key derived by running the full §4.3 AKE handshake end-to-end.

use oxideav_aacs::aes::{aes_128_ecb_decrypt, aes_128_ecb_encrypt};
use oxideav_aacs::ake::{DriveAuthState, HostCredentials};
use oxideav_aacs::{
    build_send_disc_structure_write_data_key, build_signed_certificate, host_authenticate,
    parse_data_keys_response, DataDirection, DriveCommand, MockDrive, Point, ReadDiscStructure,
    SendDiscStructure, CERT_TYPE_DRIVE, CERT_TYPE_HOST, U160,
};

const DATA_KEY_LEN: usize = 16;

fn scalar(v: u32) -> U160 {
    U160 {
        limbs: [v, 0, 0, 0, 0],
    }
}

/// Index-tagged 16-byte key so positional slips surface as wrong bytes.
fn patterned_key(tag: u8) -> [u8; DATA_KEY_LEN] {
    let mut k = [0u8; DATA_KEY_LEN];
    for (i, b) in k.iter_mut().enumerate() {
        *b = tag ^ (i as u8);
    }
    k
}

/// Plant a synthetic Bus Key directly into a placeholder
/// `DriveAuthState` (the §4.3 fields are unused by the §4.14.5.1
/// dispatcher branch — it reads only `auth.bus_key`).
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

#[test]
fn send_write_data_key_static_mode_roundtrip() {
    // No `auth` slot → the mock adopts the wire bytes verbatim as its
    // new Write Data Key, mirroring the READ-side static behaviour.
    let mut drive = MockDrive::with_test_fixture();
    let old_krd = drive.read_data_key;
    let old_kwd = drive.write_data_key;
    let new_kwd = patterned_key(0xF0);
    assert_ne!(new_kwd, old_kwd);

    let cdb = SendDiscStructure::aacs_write_data_key(2).cdb();
    let wire = build_send_disc_structure_write_data_key(&new_kwd);
    let resp = drive
        .execute(&cdb, DataDirection::ToDevice, &wire, 0)
        .expect("MockDrive must accept SEND_DISC_STRUCTURE Format 0x84");
    assert_eq!(resp.status, 0x00);
    assert!(resp.data.is_empty(), "no data-in phase on a SEND");
    assert_eq!(drive.write_data_key, new_kwd);
    assert_eq!(drive.last_write_data_key_sent, Some(new_kwd));
    // §4.14.5.1 sets only the Write Data Key; Krd is untouched.
    assert_eq!(drive.read_data_key, old_krd);
}

#[test]
fn send_write_data_key_cdb_layout_matches_table_4_26() {
    // AACS Common §4.14.5 Table 4-26: opcode 0xBF, Media Type BD in
    // the low nibble of byte 1, bytes 2..6 Reserved, Format Code 0x84,
    // Parameter List Length 0x0014 big-endian, AGID bits 7..6 of byte
    // 10, Control 0.
    let cdb = SendDiscStructure::aacs_write_data_key(3).cdb();
    assert_eq!(cdb[0], 0xBF);
    assert_eq!(cdb[1] & 0x0F, 0x01);
    assert_eq!(cdb[2..7], [0x00, 0x00, 0x00, 0x00, 0x00]);
    assert_eq!(cdb[7], 0x84);
    assert_eq!(cdb[8], 0x00);
    assert_eq!(cdb[9], 0x14);
    assert_eq!(cdb[10] >> 6, 3);
    assert_eq!(cdb[10] & 0x3F, 0, "low 6 bits of byte 10 are Reserved");
    assert_eq!(cdb[11], 0x00);

    let parsed = SendDiscStructure::parse_cdb(&cdb).unwrap();
    assert_eq!(parsed.format, 0x84);
    assert_eq!(parsed.agid, 3);
    assert_eq!(parsed.parameter_list_length, 20);
}

#[test]
fn write_data_key_parameter_list_layout_matches_table_4_28() {
    // Table 4-28: 20 bytes total; length field 0x0012 (does not count
    // itself); bytes 2..3 Reserved; Kwd at bytes 4..19.
    let kwd = patterned_key(0xA5);
    let wire = build_send_disc_structure_write_data_key(&kwd);
    assert_eq!(wire.len(), 20);
    assert_eq!(wire[0], 0x00);
    assert_eq!(wire[1], 0x12);
    assert_eq!(wire[2], 0x00);
    assert_eq!(wire[3], 0x00);
    assert_eq!(wire[4..20], kwd);
}

#[test]
fn send_write_data_key_wrapped_under_planted_bus_key() {
    // When the mock's `auth` slot carries a Bus Key, the host wraps
    // the replacement Kwd as AES-128E(BK, Kwd) per §4.14.5.1 paragraph
    // 3, and the drive stores the unwrapped plaintext.
    let bus_key = [0xAAu8; 16];
    let mut drive = drive_with_bus_key(bus_key);
    let kwd_plain = patterned_key(0xD0);
    let kwd_wrapped = aes_128_ecb_encrypt(&bus_key, &kwd_plain);
    assert_ne!(kwd_wrapped, kwd_plain);

    let cdb = SendDiscStructure::aacs_write_data_key(1).cdb();
    let wire = build_send_disc_structure_write_data_key(&kwd_wrapped);
    drive
        .execute(&cdb, DataDirection::ToDevice, &wire, 0)
        .unwrap();
    // Drive holds the plaintext; the capture slot holds the on-wire
    // (still-wrapped) bytes.
    assert_eq!(drive.write_data_key, kwd_plain);
    assert_eq!(drive.last_write_data_key_sent, Some(kwd_wrapped));
}

#[test]
fn send_write_data_key_without_bus_key_is_key_not_established() {
    // §4.14.5.1 final paragraph: when the logical unit is not in the
    // Bus Key established state, the command shall terminate with
    // COPY PROTECTION KEY EXCHANGE FAILURE – KEY NOT ESTABLISHED. The
    // mock surfaces this as an error when `auth` is armed but no Bus
    // Key has been derived; the stored Write Data Key is untouched.
    let mut drive = drive_with_bus_key([0u8; 16]);
    drive.auth.as_mut().unwrap().bus_key = None;
    let before = drive.write_data_key;

    let cdb = SendDiscStructure::aacs_write_data_key(0).cdb();
    let wire = build_send_disc_structure_write_data_key(&patterned_key(0x3C));
    assert!(drive
        .execute(&cdb, DataDirection::ToDevice, &wire, 0)
        .is_err());
    assert_eq!(drive.write_data_key, before);
    assert_eq!(drive.last_write_data_key_sent, None);
}

#[test]
fn write_data_key_read_back_after_send_recovers_new_key() {
    // Host-visible coherence: after a SEND Format 0x84, a READ DISC
    // STRUCTURE Format 0x84 returns the new Kwd (wrapped under the
    // same Bus Key) while Krd is unchanged — the §4.11 paragraph-6
    // "Kwd defaults to Krd until the host overwrites it" lifecycle.
    let bus_key = [0x5Eu8; 16];
    let mut drive = drive_with_bus_key(bus_key);
    // Model the insertion default: Kwd starts equal to Krd.
    drive.write_data_key = drive.read_data_key;
    let krd_plain = drive.read_data_key;
    let kwd_plain = patterned_key(0x96);
    assert_ne!(kwd_plain, krd_plain);

    let send_cdb = SendDiscStructure::aacs_write_data_key(1).cdb();
    let wire = build_send_disc_structure_write_data_key(&aes_128_ecb_encrypt(&bus_key, &kwd_plain));
    drive
        .execute(&send_cdb, DataDirection::ToDevice, &wire, 0)
        .unwrap();

    let read_cdb = ReadDiscStructure::aacs_data_keys(1).cdb();
    let resp = drive
        .execute(&read_cdb, DataDirection::FromDevice, &[], 36)
        .unwrap();
    let parsed = parse_data_keys_response(&resp.data).unwrap();
    assert_eq!(parsed.decrypt_write_data_key(&bus_key), kwd_plain);
    assert_eq!(parsed.decrypt_read_data_key(&bus_key), krd_plain);
}

#[test]
fn send_write_data_key_after_full_ake_handshake() {
    // End-to-end handshake-level flow: mint a synthetic AACS LA root,
    // run the full §4.3 AKE through `host_authenticate`, then use the
    // host-side Bus Key to wrap a replacement Kwd. The drive's
    // independently-derived Bus Key must unwrap it to the same
    // plaintext (§4.3 steps 28/29 guarantee both sides agree).
    let la_priv = scalar(0x0abc_def1);
    let la_pub = Point::generator().mul_scalar(&la_priv);

    let drive_priv = scalar(0x0011_2233);
    let drive_pub = Point::generator().mul_scalar(&drive_priv);
    let drive_cert = build_signed_certificate(
        CERT_TYPE_DRIVE,
        0x00,
        &[0xD0, 0x01, 0x02, 0x03, 0x04, 0x05],
        &drive_pub,
        &la_priv,
    );

    let host_priv = scalar(0x0044_5566);
    let host_pub = Point::generator().mul_scalar(&host_priv);
    let host_cert = build_signed_certificate(
        CERT_TYPE_HOST,
        0x00,
        &[0xA0, 0x06, 0x07, 0x08, 0x09, 0x0A],
        &host_pub,
        &la_priv,
    );

    let mut drive_nonce = [0u8; 20];
    for (i, b) in drive_nonce.iter_mut().enumerate() {
        *b = 0xD0 ^ (i as u8);
    }
    let mut drive = MockDrive::with_test_fixture();
    drive.agid_to_return = 1;
    drive.auth = Some(DriveAuthState::new(
        drive_cert,
        drive_priv,
        scalar(0x0013_5790),
        drive_nonce,
        la_pub,
    ));

    let creds = HostCredentials {
        host_cert,
        host_priv,
        aacs_la_pub: la_pub,
    };
    let mut host_nonce = [0u8; 20];
    for (i, b) in host_nonce.iter_mut().enumerate() {
        *b = 0x50 ^ (i as u8);
    }
    let result = host_authenticate(&mut drive, &creds, &host_nonce, &scalar(0x0024_6801))
        .expect("synthetic-cert AKE must authenticate end-to-end");

    // Host wraps the replacement Kwd under ITS Bus Key; the drive
    // unwraps under its own. Equality of the stored plaintext proves
    // the two Bus Keys agree across the SEND DISC STRUCTURE hop.
    let kwd_plain = patterned_key(0x69);
    let cdb = SendDiscStructure::aacs_write_data_key(result.agid).cdb();
    let wire =
        build_send_disc_structure_write_data_key(&aes_128_ecb_encrypt(&result.bus_key, &kwd_plain));
    drive
        .execute(&cdb, DataDirection::ToDevice, &wire, 0)
        .unwrap();
    assert_eq!(drive.write_data_key, kwd_plain);
}

#[test]
fn malformed_parameter_list_is_rejected_and_state_unchanged() {
    // Wrong length field (0x0022 instead of 0x0012) and a truncated
    // buffer must both be rejected without touching the stored key.
    let mut drive = MockDrive::with_test_fixture();
    let before = drive.write_data_key;
    let cdb = SendDiscStructure::aacs_write_data_key(0).cdb();

    let mut bad_length = vec![0x00, 0x22, 0x00, 0x00];
    bad_length.resize(20, 0x11);
    assert!(drive
        .execute(&cdb, DataDirection::ToDevice, &bad_length, 0)
        .is_err());

    let truncated = [0x00, 0x12, 0x00, 0x00, 0xAA, 0xBB, 0xCC];
    assert!(drive
        .execute(&cdb, DataDirection::ToDevice, &truncated, 0)
        .is_err());

    assert_eq!(drive.write_data_key, before);
    assert_eq!(drive.last_write_data_key_sent, None);
}

#[test]
fn parameter_list_round_trip_through_parser() {
    // Encode → decode equality for the host-side builder and the
    // drive-side parser as inverses, plus the standalone wrap/unwrap
    // property under a known Bus Key.
    use oxideav_aacs::parse_send_disc_structure_write_data_key;

    let bus_key = [0x77u8; 16];
    let kwd_plain = patterned_key(0x4B);
    let wrapped = aes_128_ecb_encrypt(&bus_key, &kwd_plain);
    let wire = build_send_disc_structure_write_data_key(&wrapped);
    let recovered_wire = parse_send_disc_structure_write_data_key(&wire).unwrap();
    assert_eq!(recovered_wire, wrapped);
    assert_eq!(aes_128_ecb_decrypt(&bus_key, &recovered_wire), kwd_plain);
}
