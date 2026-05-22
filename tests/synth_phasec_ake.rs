//! Phase C integration tests — Drive-Host Authentication & Key
//! Exchange (AKE).
//!
//! These tests run the full AACS Common Final 0.953 §4.3 handshake
//! end-to-end through the in-process authenticating [`MockDrive`]: a
//! synthetic AACS LA root key mints valid Drive + Host certificates,
//! the host driver runs the §4.3 protocol over the SCSI MMC wire layer,
//! and both sides independently derive the same 128-bit Bus Key. No real
//! disc, no real drive, no real keys — every value is synthesised here.

use oxideav_aacs::ake::DriveAuthState;
use oxideav_aacs::ake::HostCredentials;
use oxideav_aacs::{
    build_signed_certificate, host_authenticate, read_verified_volume_id, MockDrive, Point,
    BUS_KEY_LEN, CERT_TYPE_DRIVE, CERT_TYPE_HOST, U160,
};

fn scalar(v: u32) -> U160 {
    U160 {
        limbs: [v, 0, 0, 0, 0],
    }
}

/// Build a fully-wired authenticating MockDrive plus the matching host
/// credentials, all rooted at one synthetic AACS LA key pair.
fn synthetic_pair() -> (MockDrive, HostCredentials, [u8; 20], U160) {
    // --- Synthetic AACS LA root key ---
    let la_priv = scalar(0x0abc_def1);
    let la_pub = Point::generator().mul_scalar(&la_priv);

    // --- Drive identity ---
    let drive_priv = scalar(0x0011_2233);
    let drive_pub = Point::generator().mul_scalar(&drive_priv);
    let drive_cert = build_signed_certificate(
        CERT_TYPE_DRIVE,
        0x00,
        &[0xD0, 0x01, 0x02, 0x03, 0x04, 0x05],
        &drive_pub,
        &la_priv,
    );

    // --- Host identity ---
    let host_priv = scalar(0x0044_5566);
    let host_pub = Point::generator().mul_scalar(&host_priv);
    let host_cert = build_signed_certificate(
        CERT_TYPE_HOST,
        0x00,
        &[0xA0, 0x06, 0x07, 0x08, 0x09, 0x0A],
        &host_pub,
        &la_priv,
    );

    // --- Drive-side AKE state ---
    let dk = scalar(0x0013_5790);
    let mut drive_nonce = [0u8; 20];
    for (i, b) in drive_nonce.iter_mut().enumerate() {
        *b = 0xD0 ^ (i as u8);
    }
    let mut drive = MockDrive::with_test_fixture();
    drive.agid_to_return = 1;
    // Give the mock a recognisable Volume ID so the §4.4 transfer test
    // can assert the recovered value.
    for (i, b) in drive.volume_id.iter_mut().enumerate() {
        *b = 0x10 + i as u8;
    }
    drive.auth = Some(DriveAuthState::new(
        drive_cert,
        drive_priv,
        dk,
        drive_nonce,
        la_pub,
    ));

    // --- Host credentials ---
    let creds = HostCredentials {
        host_cert,
        host_priv,
        aacs_la_pub: la_pub,
    };

    // Host ephemeral secret Hk + nonce Hn.
    let hk = scalar(0x0024_6801);
    let mut host_nonce = [0u8; 20];
    for (i, b) in host_nonce.iter_mut().enumerate() {
        *b = 0x50 ^ (i as u8);
    }
    (drive, creds, host_nonce, hk)
}

#[test]
fn full_ake_handshake_derives_shared_bus_key() {
    let (mut drive, creds, host_nonce, hk) = synthetic_pair();

    let result = host_authenticate(&mut drive, &creds, &host_nonce, &hk)
        .expect("synthetic-cert AKE must authenticate end-to-end");

    // Host derived a 16-byte Bus Key.
    assert_eq!(result.bus_key.len(), BUS_KEY_LEN);

    // The drive (inside the mock) derived its own Bus Key from Dk·Hv;
    // §4.3 steps 28/29 guarantee these match.
    let drive_bk = drive
        .auth
        .as_ref()
        .unwrap()
        .bus_key
        .expect("drive must have derived a Bus Key after verifying Hsig");
    assert_eq!(
        result.bus_key, drive_bk,
        "host and drive Bus Keys must agree (ECDH x-coordinate)"
    );

    // The negotiated AGID + drive nonce surfaced in the result.
    assert_eq!(result.agid, 1);
    assert_ne!(result.bus_key, [0u8; BUS_KEY_LEN]);
}

#[test]
fn volume_id_transfer_verifies_under_bus_key() {
    let (mut drive, creds, host_nonce, hk) = synthetic_pair();
    let result = host_authenticate(&mut drive, &creds, &host_nonce, &hk).unwrap();

    // §4.4: read the Volume ID and verify the drive's CMAC under BK.
    let vid = read_verified_volume_id(&mut drive, &result.bus_key, result.agid)
        .expect("Volume ID CMAC must verify under the shared Bus Key");
    let mut expected = [0u8; 16];
    for (i, b) in expected.iter_mut().enumerate() {
        *b = 0x10 + i as u8;
    }
    assert_eq!(vid, expected);
}

#[test]
fn ake_rejects_drive_cert_signed_by_wrong_la() {
    // Mint the drive cert under a DIFFERENT root than the host trusts;
    // the host's Drive Certificate signature check must fail.
    let trusted_la_priv = scalar(0x0abc_def1);
    let trusted_la_pub = Point::generator().mul_scalar(&trusted_la_priv);
    let rogue_la_priv = scalar(0x0bad_0bad);

    let drive_priv = scalar(0x0011_2233);
    let drive_pub = Point::generator().mul_scalar(&drive_priv);
    let drive_cert = build_signed_certificate(
        CERT_TYPE_DRIVE,
        0,
        &[1, 2, 3, 4, 5, 6],
        &drive_pub,
        &rogue_la_priv, // signed by the rogue root
    );

    let host_priv = scalar(0x0044_5566);
    let host_pub = Point::generator().mul_scalar(&host_priv);
    let host_cert = build_signed_certificate(
        CERT_TYPE_HOST,
        0,
        &[7, 8, 9, 10, 11, 12],
        &host_pub,
        &trusted_la_priv,
    );

    let mut drive = MockDrive::with_test_fixture();
    drive.agid_to_return = 0;
    drive.auth = Some(DriveAuthState::new(
        drive_cert,
        drive_priv,
        scalar(0x0013_5790),
        [0u8; 20],
        trusted_la_pub, // drive trusts the real root for the host cert
    ));

    let creds = HostCredentials {
        host_cert,
        host_priv,
        aacs_la_pub: trusted_la_pub,
    };
    let err = host_authenticate(&mut drive, &creds, &[0x11u8; 20], &scalar(0x99)).unwrap_err();
    assert_eq!(err, oxideav_aacs::AacsError::DriveCertSignatureInvalid);
}

#[test]
fn drive_rejects_host_cert_signed_by_wrong_la() {
    // The host certificate is signed by a rogue root; the drive's
    // step-9 verification (inside accept_host_cert_challenge) fails and
    // surfaces as an error from the SEND_KEY host-cert-challenge.
    let trusted_la_priv = scalar(0x0abc_def1);
    let trusted_la_pub = Point::generator().mul_scalar(&trusted_la_priv);
    let rogue_la_priv = scalar(0x0bad_cafe);

    let drive_priv = scalar(0x0011_2233);
    let drive_pub = Point::generator().mul_scalar(&drive_priv);
    let drive_cert = build_signed_certificate(
        CERT_TYPE_DRIVE,
        0,
        &[1, 2, 3, 4, 5, 6],
        &drive_pub,
        &trusted_la_priv,
    );

    let host_priv = scalar(0x0044_5566);
    let host_pub = Point::generator().mul_scalar(&host_priv);
    let host_cert = build_signed_certificate(
        CERT_TYPE_HOST,
        0,
        &[7, 8, 9, 10, 11, 12],
        &host_pub,
        &rogue_la_priv,
    );

    let mut drive = MockDrive::with_test_fixture();
    drive.auth = Some(DriveAuthState::new(
        drive_cert,
        drive_priv,
        scalar(0x0013_5790),
        [0u8; 20],
        trusted_la_pub,
    ));

    let creds = HostCredentials {
        host_cert,
        host_priv,
        aacs_la_pub: trusted_la_pub,
    };
    let err = host_authenticate(&mut drive, &creds, &[0x22u8; 20], &scalar(0x77)).unwrap_err();
    assert_eq!(err, oxideav_aacs::AacsError::HostCertSignatureInvalid);
}

#[test]
fn tampered_volume_id_mac_is_rejected() {
    let (mut drive, creds, host_nonce, hk) = synthetic_pair();
    let result = host_authenticate(&mut drive, &creds, &host_nonce, &hk).unwrap();

    // Verify under a DIFFERENT (wrong) Bus Key → CMAC mismatch.
    let mut wrong_bk = result.bus_key;
    wrong_bk[0] ^= 0xFF;
    let err = read_verified_volume_id(&mut drive, &wrong_bk, result.agid).unwrap_err();
    assert_eq!(err, oxideav_aacs::AacsError::VolumeIdMacInvalid);
}
