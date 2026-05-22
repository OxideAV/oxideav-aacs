//! Phase B integration tests — SCSI MMC drive-command layer.
//!
//! These tests exercise the wire-format constructors and parsers
//! defined in `oxideav_aacs::mmc` round-tripped through the in-process
//! [`MockDrive`] fixture. No real disc, no real drive, no real keys —
//! every byte sequence is synthesised from values defined in this
//! file or randomly generated.

use oxideav_aacs::{
    build_send_key_host_cert_chal, build_send_key_host_key, parse_report_key_agid,
    parse_report_key_drive_cert, parse_report_key_drive_cert_chal, parse_report_key_drive_key,
    parse_send_key_host_cert_chal, parse_send_key_host_key, parse_volume_id_response,
    DataDirection, DriveCommand, MockDrive, ReadDiscStructure, ReportKey, SendKey,
};

// Spec-derived constants (mirrored from the public mmc module so the
// test asserts the public surface). The values come from AACS Common
// §4.1 / §4.2 (Cert lengths), §4.3 (nonce lengths), and §4.14.3.1
// (Volume ID + MAC).
const HOST_NONCE_LEN: usize = 20;
const HOST_CERT_LEN: usize = 92;
const EC_POINT_LEN: usize = 40;
const EC_SIG_LEN: usize = 40;

#[test]
fn report_key_agid_roundtrip_through_mock_drive() {
    let mut drive = MockDrive::with_test_fixture();
    drive.agid_to_return = 2;
    let cdb = ReportKey::aacs_agid().cdb();
    let response = drive
        .execute(&cdb, DataDirection::FromDevice, &[], 8)
        .expect("MockDrive must accept REPORT_KEY AGID");
    assert_eq!(response.status, 0x00);
    let agid = parse_report_key_agid(&response.data).unwrap();
    assert_eq!(agid.agid, 2);
}

#[test]
fn report_key_drive_cert_chal_roundtrip_through_mock_drive() {
    let mut drive = MockDrive::with_test_fixture();
    let cdb = ReportKey::aacs_drive_cert_challenge(1).cdb();
    let response = drive
        .execute(&cdb, DataDirection::FromDevice, &[], 116)
        .expect("MockDrive must accept REPORT_KEY Drive Cert Challenge");
    assert_eq!(response.data.len(), 116);
    let chal = parse_report_key_drive_cert_chal(&response.data).unwrap();
    assert_eq!(chal.drive_nonce, drive.drive_nonce);
    assert_eq!(chal.drive_cert, drive.drive_cert);

    // AACS Common §4.1 invariant: byte 0 of the Drive Certificate is
    // Certificate Type 0x01 (Licensed Drive), bytes 2..3 are the
    // length 0x005C.
    assert_eq!(chal.drive_cert[0], 0x01);
    assert_eq!(chal.drive_cert[2], 0x00);
    assert_eq!(chal.drive_cert[3], 0x5C);
}

#[test]
fn report_key_drive_key_roundtrip_through_mock_drive() {
    let mut drive = MockDrive::with_test_fixture();
    let cdb = ReportKey::aacs_drive_key(0).cdb();
    let response = drive
        .execute(&cdb, DataDirection::FromDevice, &[], 84)
        .expect("MockDrive must accept REPORT_KEY Drive Key");
    assert_eq!(response.data.len(), 84);
    let key = parse_report_key_drive_key(&response.data).unwrap();
    assert_eq!(key.dv, drive.drive_dv);
    assert_eq!(key.dsig, drive.drive_dsig);
}

#[test]
fn report_key_drive_cert_roundtrip_through_mock_drive() {
    let mut drive = MockDrive::with_test_fixture();
    let cdb = ReportKey::aacs_drive_cert().cdb();
    let response = drive
        .execute(&cdb, DataDirection::FromDevice, &[], 96)
        .expect("MockDrive must accept REPORT_KEY Drive Cert");
    assert_eq!(response.data.len(), 96);
    let cert = parse_report_key_drive_cert(&response.data).unwrap();
    assert_eq!(cert.drive_cert, drive.drive_cert);
}

#[test]
fn send_key_host_cert_chal_roundtrip_through_mock_drive() {
    let mut drive = MockDrive::with_test_fixture();
    let cdb = SendKey::aacs_host_cert_challenge(1).cdb();

    // Build a synthetic Host Certificate per AACS Common §4.2.
    let mut host_cert = [0u8; HOST_CERT_LEN];
    host_cert[0] = 0x02; // Certificate Type = 0x02 (Licensed Host)
    host_cert[1] = 0x00; // Reserved + flags clear (BEC=0, DKS=0)
    host_cert[2] = 0x00; // Length high byte
    host_cert[3] = 0x5C; // Length low byte = 92
                         // Host ID = 0x0A0B0C0D0E0F (bytes 4..9)
    host_cert[4] = 0x0A;
    host_cert[5] = 0x0B;
    host_cert[6] = 0x0C;
    host_cert[7] = 0x0D;
    host_cert[8] = 0x0E;
    host_cert[9] = 0x0F;
    for (i, b) in host_cert.iter_mut().enumerate().skip(10) {
        *b = (0x10 + i) as u8;
    }

    let mut host_nonce = [0u8; HOST_NONCE_LEN];
    for (i, b) in host_nonce.iter_mut().enumerate() {
        *b = 0x50 ^ (i as u8);
    }

    let payload = build_send_key_host_cert_chal(&host_nonce, &host_cert);
    assert_eq!(payload.len(), 116);
    // Length field at bytes 0..1 must be 0x0072 per Table 606.
    assert_eq!(payload[0], 0x00);
    assert_eq!(payload[1], 0x72);
    // Bytes 2..3 reserved (zero).
    assert_eq!(payload[2], 0x00);
    assert_eq!(payload[3], 0x00);

    let response = drive
        .execute(&cdb, DataDirection::ToDevice, &payload, 0)
        .expect("MockDrive must accept SEND_KEY Host Cert Challenge");
    assert_eq!(response.status, 0x00);

    let captured = drive
        .last_host_cert_chal
        .as_ref()
        .expect("MockDrive must capture the SEND_KEY payload");
    let (rt_nonce, rt_cert) = parse_send_key_host_cert_chal(captured).unwrap();
    assert_eq!(rt_nonce, host_nonce);
    assert_eq!(rt_cert, host_cert);
}

#[test]
fn send_key_host_key_roundtrip_through_mock_drive() {
    let mut drive = MockDrive::with_test_fixture();
    let cdb = SendKey::aacs_host_key(1).cdb();

    let mut hv = [0u8; EC_POINT_LEN];
    for (i, b) in hv.iter_mut().enumerate() {
        *b = 0x80 ^ (i as u8);
    }
    let mut hsig = [0u8; EC_SIG_LEN];
    for (i, b) in hsig.iter_mut().enumerate() {
        *b = 0x90 ^ (i as u8);
    }

    let payload = build_send_key_host_key(&hv, &hsig);
    assert_eq!(payload.len(), 84);
    // Length field at bytes 0..1 must be 0x0052 per Table 607.
    assert_eq!(payload[0], 0x00);
    assert_eq!(payload[1], 0x52);

    drive
        .execute(&cdb, DataDirection::ToDevice, &payload, 0)
        .expect("MockDrive must accept SEND_KEY Host Key");
    let captured = drive
        .last_host_key
        .as_ref()
        .expect("MockDrive must capture the Host Key payload");
    let (rt_hv, rt_hsig) = parse_send_key_host_key(captured).unwrap();
    assert_eq!(rt_hv, hv);
    assert_eq!(rt_hsig, hsig);
}

#[test]
fn read_disc_structure_volume_id_roundtrip_through_mock_drive() {
    let mut drive = MockDrive::with_test_fixture();
    let cdb = ReadDiscStructure::aacs_volume_id(2).cdb();
    let response = drive
        .execute(&cdb, DataDirection::FromDevice, &[], 36)
        .expect("MockDrive must accept READ_DISC_STRUCTURE Volume ID");
    assert_eq!(response.data.len(), 36);
    // Length field 0x0022 = 34 (payload size, header excluded).
    assert_eq!(response.data[0], 0x00);
    assert_eq!(response.data[1], 0x22);
    let vol = parse_volume_id_response(&response.data).unwrap();
    assert_eq!(vol.volume_id, drive.volume_id);
    assert_eq!(vol.mac, drive.volume_id_mac);
}

#[test]
fn invalidate_agid_via_report_key_marks_mock_drive() {
    let mut drive = MockDrive::with_test_fixture();
    assert!(!drive.agid_invalidated);
    let cdb = ReportKey::aacs_invalidate_agid(2).cdb();
    drive
        .execute(&cdb, DataDirection::None, &[], 0)
        .expect("MockDrive must accept Invalidate AGID");
    assert!(drive.agid_invalidated);
}

#[test]
fn invalidate_agid_via_send_key_marks_mock_drive() {
    let mut drive = MockDrive::with_test_fixture();
    let cdb = SendKey::aacs_invalidate_agid(2).cdb();
    drive
        .execute(&cdb, DataDirection::None, &[], 0)
        .expect("MockDrive must accept SEND_KEY Invalidate AGID");
    assert!(drive.agid_invalidated);
}

#[test]
fn send_key_host_cert_chal_rejects_malformed_payload() {
    let mut drive = MockDrive::with_test_fixture();
    let cdb = SendKey::aacs_host_cert_challenge(0).cdb();
    let bad = vec![0u8; 116]; // length field is 0x0000 instead of 0x0072
    let err = drive
        .execute(&cdb, DataDirection::ToDevice, &bad, 0)
        .unwrap_err();
    // Just confirm the mock surfaces the parse failure rather than
    // silently accepting it.
    let msg = format!("{err}");
    assert!(
        msg.contains("Host Cert Challenge length"),
        "expected length-mismatch diagnostic, got: {msg}"
    );
}

#[test]
fn report_key_parse_rejects_short_input() {
    let buf = [0u8; 3];
    assert!(parse_report_key_agid(&buf).is_err());
}

#[test]
fn report_key_drive_cert_chal_parse_rejects_short_input() {
    let buf = [0x00u8, 0x72, 0x00, 0x00]; // header only
    assert!(parse_report_key_drive_cert_chal(&buf).is_err());
}

#[test]
fn volume_id_parse_rejects_wrong_length_field() {
    let mut wire = vec![0x00, 0x10, 0x00, 0x00]; // 0x0010 instead of 0x0022
    wire.resize(36, 0);
    assert!(parse_volume_id_response(&wire).is_err());
}
