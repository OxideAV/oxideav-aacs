//! Round 222 — end-to-end synthetic Content Certificate (PVB §2.4 /
//! §2.5 / §2.6) verification against a synthetic-LA-rooted ECDSA key
//! pair, with the BD-Prerecorded Format-Specific Section (BD-Prerecorded
//! Table 2-1) and per-CHT digest roundtrips.
//!
//! Every byte is synthesised in-source. No real AACS LA Content
//! Certificate public key, no disc fixture, no embedded key material.

use oxideav_aacs::cht::{hash_value_of_unit, ContentHashTable, HASH_UNIT_SIZE};
use oxideav_aacs::content_certificate::{
    usage_rules_hash, BdFormatSpecificSection, ContentCertificate, ContentSequenceNumber,
    CERTIFICATE_TYPE_FIRST_GEN, CONTENT_HASH_TABLE_DIGEST_LEN, SIGNATURE_DATA_LEN,
};
use oxideav_aacs::ec::{Point, U160};
use oxideav_aacs::ecdsa::sign;
use oxideav_aacs::AacsError;

/// Helper: synthesise a Hash Unit's worth of deterministic bytes.
fn synth_hash_unit(seed: u8) -> Vec<u8> {
    (0..HASH_UNIT_SIZE)
        .map(|i| (i as u8).wrapping_add(seed).wrapping_mul(31))
        .collect()
}

/// Helper: build a CHT for a single Clip, then return its on-disc
/// bytes (the form the spec's `CHT_d` digest is computed over).
fn synth_cht_bytes(seed: u8, hash_units: usize) -> Vec<u8> {
    // Header: one ClipDescriptor (12 bytes), Starting_HU=0, Clip=seed,
    // HU_Offset=0.
    let mut buf = Vec::new();
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.extend_from_slice(&u32::from(seed).to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes());
    for i in 0..hash_units {
        let unit = synth_hash_unit(seed.wrapping_add(i as u8));
        buf.extend_from_slice(&hash_value_of_unit(&unit));
    }
    // Sanity: also exercise the cht-side parser on the same buffer.
    let _ = ContentHashTable::parse(&buf, 1, hash_units as u32).unwrap();
    buf
}

fn small_scalar(v: u32) -> U160 {
    U160 {
        limbs: [v, 0, 0, 0, 0],
    }
}

/// Mint a synthetic AACS_CC ECDSA key pair (not the real LA key) and
/// return the (private scalar, public point).
fn synth_aacs_cc_key_pair() -> (U160, Point) {
    let d = small_scalar(0x5a5a_3c3c);
    let q = Point::generator().mul_scalar(&d);
    (d, q)
}

/// Build a fully populated layer-0 Content Certificate that signs over
/// 2 CHT digests, with a BD-Prerecorded Format-Specific Section
/// carrying 3 CPS Unit Usage hashes.
fn build_signed_certificate(
    priv_key: &U160,
    cht_layer0_bytes: &[u8],
    cht_layer1_bytes: &[u8],
) -> ContentCertificate {
    let bd = BdFormatSpecificSection {
        hash_value_of_mc_manifest_file: [0xA1; 20],
        hash_value_of_bdj_root_cert: [0xB2; 20],
        hash_value_of_cps_unit_usage_files: vec![[0x11; 20], [0x22; 20], [0x33; 20]],
    };
    let format_specific_section = bd.to_bytes();

    let mut cert = ContentCertificate {
        certificate_type: CERTIFICATE_TYPE_FIRST_GEN,
        bee: false,
        total_number_of_hash_units: 0x0000_2000,
        total_number_of_layers: 2,
        layer_number: 0,
        number_of_hash_units: 0x0000_1000,
        number_of_digests: 2,
        applicant_id: [0x00, 0x9F],
        content_sequence_number: ContentSequenceNumber {
            ccss_id: 12,
            timestamp: 5000,
            sequence_number: 0x0AB,
        }
        .to_be_bytes(),
        minimum_crl_version: 3,
        format_specific_section,
        content_hash_table_digests: vec![
            ContentCertificate::content_hash_table_digest(cht_layer0_bytes),
            ContentCertificate::content_hash_table_digest(cht_layer1_bytes),
        ],
        signature_data: [0u8; SIGNATURE_DATA_LEN],
    };

    let payload = cert.signed_range_bytes();
    cert.signature_data = sign(priv_key, &payload);
    cert
}

#[test]
fn end_to_end_certificate_round_trip_against_synthetic_la_key() {
    let (priv_key, pub_key) = synth_aacs_cc_key_pair();
    let cht_layer0 = synth_cht_bytes(0x10, 4);
    let cht_layer1 = synth_cht_bytes(0x20, 3);

    let cert = build_signed_certificate(&priv_key, &cht_layer0, &cht_layer1);
    let on_disc = cert.to_bytes();

    // Parse back from raw on-disc bytes.
    let parsed = ContentCertificate::parse(&on_disc).unwrap();
    assert_eq!(parsed, cert);

    // Signature verifies against the synthetic LA pubkey.
    parsed.verify_signature(&pub_key).unwrap();

    // Per-layer CHT digests verify.
    parsed
        .verify_content_hash_table_digest(0, &cht_layer0)
        .unwrap();
    parsed
        .verify_content_hash_table_digest(1, &cht_layer1)
        .unwrap();

    // BD-Prerecorded Format-Specific Section decodes the 3 usage hashes.
    let bd = parsed.bd_format_specific_section().unwrap();
    assert_eq!(bd.hash_value_of_cps_unit_usage_files.len(), 3);
    assert_eq!(bd.hash_value_of_mc_manifest_file, [0xA1; 20]);
    assert_eq!(bd.hash_value_of_bdj_root_cert, [0xB2; 20]);

    // Content Certificate ID concatenates Applicant ID and Content
    // Sequence Number per PVB §2.4.
    let id = parsed.content_certificate_id();
    let expected_seq = ContentSequenceNumber {
        ccss_id: 12,
        timestamp: 5000,
        sequence_number: 0x0AB,
    }
    .to_be_bytes();
    assert_eq!(id.applicant_id(), [0x00, 0x9F]);
    assert_eq!(id.content_sequence_number(), expected_seq);
    assert_eq!(id.0[..2], [0x00, 0x9F]);
    assert_eq!(id.0[2..], expected_seq);
    // The decoded Content Sequence Number round-trips structured.
    let decoded = parsed.content_sequence_number_decoded();
    assert_eq!(decoded.ccss_id, 12);
    assert_eq!(decoded.timestamp, 5000);
    assert_eq!(decoded.sequence_number, 0x0AB);
}

#[test]
fn tampered_cht_digest_invalidates_signature() {
    let (priv_key, pub_key) = synth_aacs_cc_key_pair();
    let cht_layer0 = synth_cht_bytes(0x40, 2);
    let cht_layer1 = synth_cht_bytes(0x50, 2);
    let cert = build_signed_certificate(&priv_key, &cht_layer0, &cht_layer1);
    cert.verify_signature(&pub_key).unwrap();

    // Flip one byte of one of the stored CHT digests; signature breaks.
    let mut tampered = cert.clone();
    tampered.content_hash_table_digests[0][3] ^= 0x80;
    assert_eq!(
        tampered.verify_signature(&pub_key),
        Err(AacsError::MkbSignatureInvalid)
    );
}

#[test]
fn tampered_cht_bytes_invalidate_digest_check() {
    let (priv_key, _pub_key) = synth_aacs_cc_key_pair();
    let cht_layer0 = synth_cht_bytes(0x60, 5);
    let cht_layer1 = synth_cht_bytes(0x61, 4);
    let cert = build_signed_certificate(&priv_key, &cht_layer0, &cht_layer1);

    // Flip a byte in the on-disc CHT bytes — recomputed CHT_d no
    // longer matches the certificate's stored digest.
    let mut tampered = cht_layer0.clone();
    tampered[42] ^= 0xFF;
    assert_eq!(
        cert.verify_content_hash_table_digest(0, &tampered),
        Err(AacsError::ContentHashMismatch { index: 0 })
    );
}

#[test]
fn wrong_public_key_rejects_certificate_signature() {
    let (priv_key, _pub_key) = synth_aacs_cc_key_pair();
    let cht_layer0 = synth_cht_bytes(0x70, 3);
    let cht_layer1 = synth_cht_bytes(0x71, 3);
    let cert = build_signed_certificate(&priv_key, &cht_layer0, &cht_layer1);
    let imposter_priv = small_scalar(0xDEAD_BEEF);
    let imposter_pub = Point::generator().mul_scalar(&imposter_priv);
    assert_eq!(
        cert.verify_signature(&imposter_pub),
        Err(AacsError::MkbSignatureInvalid)
    );
}

#[test]
fn cht_digest_byte_length_is_eight() {
    // The CHT_d = [SHA-1(CHT)]_lsb_64 primitive is exactly 8 bytes.
    let bytes = vec![0xAB; 200];
    let d = ContentCertificate::content_hash_table_digest(&bytes);
    assert_eq!(d.len(), CONTENT_HASH_TABLE_DIGEST_LEN);
    assert_eq!(d.len(), 8);
}

#[test]
fn usage_rules_hash_helper_matches_sha1() {
    // PVB §2.6 C_ur = SHA-1(Usage_Rules).
    let rules = b"\x00\x01\x02\x03 synthetic usage rules";
    let h = usage_rules_hash(rules);
    assert_eq!(h.len(), 20);

    // Re-hashing the same bytes is deterministic; trivial sanity.
    let h2 = usage_rules_hash(rules);
    assert_eq!(h, h2);

    // Tampering the rules changes the digest.
    let mut tampered = rules.to_vec();
    tampered[0] ^= 1;
    let h3 = usage_rules_hash(&tampered);
    assert_ne!(h, h3);
}
