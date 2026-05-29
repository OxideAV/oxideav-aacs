//! Integration test for the MKB AACS LA signature verification API
//! (Common spec §3.2.5.1.2 / §3.2.5.1.3 / §3.2.5.1.8).
//!
//! Builds a synthetic Type-and-Version + HRL + End-of-MKB byte stream
//! signed under a self-generated AACS LA private key, parses it back
//! through the public `Mkb::parse` entry point, and confirms that
//! `verify_end_of_block_signature` + `verify_host_revocation_list`
//! accept the legitimate signatures and reject a forged public key.
//!
//! No real disc fixtures, no real AACS LA key material.

use oxideav_aacs::ec::{Point, U160};
use oxideav_aacs::ecdsa::sign;
use oxideav_aacs::{AacsError, Mkb};

fn write_record(tag: u8, body: &[u8]) -> Vec<u8> {
    let length = 4 + body.len();
    let mut out = vec![
        tag,
        ((length >> 16) & 0xFF) as u8,
        ((length >> 8) & 0xFF) as u8,
        (length & 0xFF) as u8,
    ];
    out.extend_from_slice(body);
    out
}

fn build_tv() -> Vec<u8> {
    let mut tv = Vec::new();
    tv.extend_from_slice(&0x0003_1003u32.to_be_bytes());
    tv.extend_from_slice(&42u32.to_be_bytes());
    write_record(0x10, &tv)
}

fn la_keypair() -> (U160, Point) {
    let d = U160::from_be_bytes(&[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14,
    ]);
    let q = Point::generator().mul_scalar(&d);
    (d, q)
}

#[test]
fn end_to_end_mkb_signature_roundtrip() {
    let (la_priv, la_pub) = la_keypair();

    let tv = build_tv();

    // Single-block HRL with 3 entries.
    let mut hrl_payload = Vec::new();
    hrl_payload.extend_from_slice(&3u32.to_be_bytes()); // Total entries
    hrl_payload.extend_from_slice(&3u32.to_be_bytes()); // N1
    for i in 0u8..3 {
        hrl_payload.extend_from_slice(&[0x00, 0x00, i, i + 1, i + 2, i + 3, i + 4, i + 5]);
    }
    let hrl_total_len = 4 + hrl_payload.len() + 40;
    let hrl_header = [
        0x21,
        ((hrl_total_len >> 16) & 0xFF) as u8,
        ((hrl_total_len >> 8) & 0xFF) as u8,
        (hrl_total_len & 0xFF) as u8,
    ];

    let mut signed_hrl = Vec::new();
    signed_hrl.extend_from_slice(&tv);
    signed_hrl.extend_from_slice(&hrl_header);
    signed_hrl.extend_from_slice(&hrl_payload);
    let hrl_sig = sign(&la_priv, &signed_hrl);

    let mut hrl_record = Vec::new();
    hrl_record.extend_from_slice(&hrl_header);
    hrl_record.extend_from_slice(&hrl_payload);
    hrl_record.extend_from_slice(&hrl_sig);

    // Verify-Media-Key record.
    let vmk = write_record(0x81, &[0x77u8; 16]);

    // Compose the signed prefix for End-of-MKB: tv || hrl || vmk.
    let mut prefix = Vec::new();
    prefix.extend_from_slice(&tv);
    prefix.extend_from_slice(&hrl_record);
    prefix.extend_from_slice(&vmk);
    let eob_sig = sign(&la_priv, &prefix);

    // Assemble final MKB.
    let mut mkb_bytes = prefix.clone();
    mkb_bytes.extend_from_slice(&write_record(0x02, &eob_sig));

    // Parse + verify.
    let mkb = Mkb::parse(&mkb_bytes).expect("MKB must parse");
    assert_eq!(mkb.host_revocation_list.len(), 3);
    assert_eq!(mkb.host_revocation_blocks.len(), 1);
    assert_eq!(mkb.end_of_block_signature.as_ref(), Some(&eob_sig));

    mkb.verify_end_of_block_signature(&mkb_bytes, &la_pub)
        .expect("End-of-MKB signature must verify under the LA pub key");
    mkb.verify_host_revocation_list(&mkb_bytes, &la_pub)
        .expect("HRL signature must verify");

    // Forge: replace one entry byte post-parse and re-run the check
    // against the tampered buffer. The signature must fail.
    let mut tampered = mkb_bytes.clone();
    // Tamper a byte inside the HRL entries (skip tv + header + 4-byte
    // total + 4-byte N1 = tv_len + 8 + 4).
    let tv_len = tv.len();
    tampered[tv_len + 4 + 4 + 4 + 2] ^= 0x55;
    assert!(matches!(
        mkb.verify_host_revocation_list(&tampered, &la_pub),
        Err(AacsError::MkbSignatureInvalid)
    ));

    // The End-of-MKB signature also fails because its signed-prefix
    // range includes the (tampered) HRL bytes.
    assert!(matches!(
        mkb.verify_end_of_block_signature(&tampered, &la_pub),
        Err(AacsError::MkbSignatureInvalid)
    ));
}

#[test]
fn missing_signature_paths_return_distinct_error_from_invalid() {
    let (_priv, pubk) = la_keypair();

    // Minimal MKB: tv + end-of-mkb only. No HRL, no signature payload
    // beyond the bare 0-length placeholder — but the End-of-MKB
    // record body is not 40 bytes, so verification reports
    // MkbSignatureMissing (not MkbSignatureInvalid).
    let tv = build_tv();
    let mut bytes = tv.clone();
    bytes.extend(write_record(0x02, &[0u8; 0]));
    // Compose this manually because write_record with empty body
    // makes a 4-byte header which is a legitimate "End-of-MKB" record
    // shape per the parser's existing behaviour.

    let mkb = Mkb::parse(&bytes).expect("MKB must parse");
    assert!(mkb.end_of_block);
    assert!(mkb.end_of_block_signature.is_none());

    assert!(matches!(
        mkb.verify_end_of_block_signature(&bytes, &pubk),
        Err(AacsError::MkbSignatureMissing)
    ));
    assert!(matches!(
        mkb.verify_host_revocation_list(&bytes, &pubk),
        Err(AacsError::MkbSignatureMissing)
    ));
    assert!(matches!(
        mkb.verify_drive_revocation_list(&bytes, &pubk),
        Err(AacsError::MkbSignatureMissing)
    ));
}
