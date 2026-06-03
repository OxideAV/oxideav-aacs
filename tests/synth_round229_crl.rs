//! Round 229 — end-to-end synthetic Content Revocation List (PVB §2.7
//! Tables 2-2 / 2-3 / 2-4 / 2-5) verification against a synthetic LA
//! Entity ECDSA key pair, with multi-segment cumulative-prefix
//! signature semantics and the §2.7.2 RMRR applicability rules.
//!
//! Every byte is synthesised in-source. No real AACS LA Entity public
//! key, no disc fixture, no embedded key material.

use oxideav_aacs::content_certificate::ContentCertificateId;
use oxideav_aacs::crl::{
    ContentRevocationList, CrlSegment, ManagedCopyServerCertificateId, RecordableMediaRevocation,
    RecordableMediaType, RevocationRecord, LIST_TYPE_FIRST_GEN, SEGMENT_SIGNATURE_LEN,
};
use oxideav_aacs::ec::{Point, U160};
use oxideav_aacs::ecdsa::sign;
use oxideav_aacs::AacsError;

fn small_scalar(v: u32) -> U160 {
    U160 {
        limbs: [v, 0, 0, 0, 0],
    }
}

/// Mint a synthetic AACS LA Entity key pair (not the real LA key).
fn synth_la_key_pair() -> (U160, Point) {
    let d = small_scalar(0x0BAD_FACE);
    let q = Point::generator().mul_scalar(&d);
    (d, q)
}

fn cc_id(b: u8) -> ContentCertificateId {
    ContentCertificateId([
        b,
        b.wrapping_add(0x11),
        b.wrapping_add(0x22),
        b.wrapping_add(0x33),
        b.wrapping_add(0x44),
        b.wrapping_add(0x55),
    ])
}

/// Build a fully-populated synthetic CRL across THREE segments. The
/// first carries 4 Content Certificate ID revocations (a singleton +
/// a 12-record range), the second adds 2 Managed Copy Server revocation
/// records, and the third adds one Recordable Media Revocation Record
/// (RMRR with ICCID=0).
fn build_three_segment_crl(priv_key: &U160) -> ContentRevocationList {
    let records_a = vec![
        RevocationRecord::ContentCertificateId {
            range: 0,
            id: cc_id(0x10),
        },
        RevocationRecord::ContentCertificateId {
            range: 11, // covers ids 0x20..=0x2B
            id: cc_id(0x20),
        },
        RevocationRecord::ContentCertificateId {
            range: 0,
            id: cc_id(0x30),
        },
        RevocationRecord::ContentCertificateId {
            range: 0,
            id: cc_id(0x40),
        },
    ];
    let records_b = vec![
        RevocationRecord::ManagedCopyServerCertificateId {
            range: 2,
            id: ManagedCopyServerCertificateId([0x10, 0, 0, 0, 0, 0]),
        },
        RevocationRecord::ManagedCopyServerCertificateId {
            range: 0,
            id: ManagedCopyServerCertificateId([0x99, 0x88, 0x77, 0x66, 0x55, 0x44]),
        },
    ];
    let records_c = vec![RevocationRecord::RecordableMedia(
        RecordableMediaRevocation {
            iccid: false,
            media_type: RecordableMediaType::BdRecordable,
            content_certificate_id: cc_id(0x90),
            media_id: [
                0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                0x0A, 0x0B,
            ],
        },
    )];

    fn segment_size(records: &[RevocationRecord]) -> u32 {
        let mut s = 4u32;
        s += SEGMENT_SIGNATURE_LEN as u32;
        for r in records {
            let n = match r {
                RevocationRecord::RecordableMedia(_) => 24,
                _ => 8,
            };
            s += n;
        }
        s
    }

    let mut crl = ContentRevocationList {
        list_type: LIST_TYPE_FIRST_GEN,
        reserved_nibble: 0,
        list_version: 0x0042,
        number_of_segments: 3,
        segments: vec![
            CrlSegment {
                segment_size: segment_size(&records_a),
                records: records_a,
                signature: [0u8; SEGMENT_SIGNATURE_LEN],
            },
            CrlSegment {
                segment_size: segment_size(&records_b),
                records: records_b,
                signature: [0u8; SEGMENT_SIGNATURE_LEN],
            },
            CrlSegment {
                segment_size: segment_size(&records_c),
                records: records_c,
                signature: [0u8; SEGMENT_SIGNATURE_LEN],
            },
        ],
    };
    for k in 0..3 {
        let payload = crl.signed_range_for_segment(k).unwrap();
        crl.segments[k].signature = sign(priv_key, &payload);
    }
    crl
}

#[test]
fn end_to_end_three_segment_crl_signs_verifies_round_trips() {
    let (priv_key, pub_key) = synth_la_key_pair();
    let crl = build_three_segment_crl(&priv_key);

    // Byte-exact round trip.
    let bytes = crl.to_bytes();
    let reparsed = ContentRevocationList::parse(&bytes).unwrap();
    assert_eq!(reparsed, crl);

    // Each segment's Entity Signature verifies independently AND
    // the §2.7-prescribed "last-segment-only" check verifies.
    crl.verify_all_segments(&pub_key).unwrap();
    crl.verify_last_segment_signature(&pub_key).unwrap();

    // Segment N's signed prefix transitively covers segments < N.
    let r0 = crl.signed_range_for_segment(0).unwrap();
    let r1 = crl.signed_range_for_segment(1).unwrap();
    let r2 = crl.signed_range_for_segment(2).unwrap();
    assert!(r1.len() > r0.len() + SEGMENT_SIGNATURE_LEN);
    assert!(r2.len() > r1.len() + SEGMENT_SIGNATURE_LEN);

    // The aggregate records iterator yields every record across the
    // three segments in segment-major order.
    let records: Vec<_> = crl.records().collect();
    assert_eq!(records.len(), 7);
}

#[test]
fn wrong_public_key_rejects_every_segment() {
    let (priv_key, _pub_key) = synth_la_key_pair();
    let crl = build_three_segment_crl(&priv_key);

    let imposter_priv = small_scalar(0xCAFE_BABE);
    let imposter_pub = Point::generator().mul_scalar(&imposter_priv);
    for k in 0..3 {
        assert_eq!(
            crl.verify_segment_signature(k, &imposter_pub),
            Err(AacsError::MkbSignatureInvalid)
        );
    }
    assert_eq!(
        crl.verify_last_segment_signature(&imposter_pub),
        Err(AacsError::MkbSignatureInvalid)
    );
}

#[test]
fn content_certificate_revocation_queries_match_spec_range_semantics() {
    let (priv_key, _pub_key) = synth_la_key_pair();
    let crl = build_three_segment_crl(&priv_key);

    // The singleton record at cc_id(0x10) revokes exactly that ID.
    assert!(crl.is_content_certificate_id_revoked(cc_id(0x10)));
    let near = ContentCertificateId([0x10, 0x21, 0x32, 0x43, 0x54, 0x66]);
    assert!(!crl.is_content_certificate_id_revoked(near));

    // The range=11 record at cc_id(0x20) covers the next 11 IDs (12
    // total). Try a query in the middle of the range.
    let mid_id_byte = cc_id(0x20).0;
    let mut q = mid_id_byte;
    q[5] = mid_id_byte[5].wrapping_add(7); // start + 7
    assert!(crl.is_content_certificate_id_revoked(ContentCertificateId(q)));

    // Outside the range:
    let mut over = mid_id_byte;
    over[5] = mid_id_byte[5].wrapping_add(12); // start + 12 → out of range
    assert!(!crl.is_content_certificate_id_revoked(ContentCertificateId(over)));

    // Layer-three RMRR with ICCID=0 also revokes its Content
    // Certificate ID by the general query path.
    assert!(crl.is_content_certificate_id_revoked(cc_id(0x90)));
}

#[test]
fn rmrr_iccid_set_applies_by_media_id_only() {
    let (priv_key, _pub_key) = synth_la_key_pair();
    // Build a CRL containing one RMRR with ICCID = 1.
    let rmrr = RecordableMediaRevocation {
        iccid: true,
        media_type: RecordableMediaType::DvdRecordable,
        content_certificate_id: cc_id(0xAA),
        media_id: [0x77; 16],
    };
    let records = vec![RevocationRecord::RecordableMedia(rmrr)];
    let segment_size = 4u32 + 24u32 + SEGMENT_SIGNATURE_LEN as u32;
    let mut crl = ContentRevocationList {
        list_type: LIST_TYPE_FIRST_GEN,
        reserved_nibble: 0,
        list_version: 0x000F,
        number_of_segments: 1,
        segments: vec![CrlSegment {
            segment_size,
            records,
            signature: [0u8; SEGMENT_SIGNATURE_LEN],
        }],
    };
    let payload = crl.signed_range_for_segment(0).unwrap();
    crl.segments[0].signature = sign(&priv_key, &payload);

    // ICCID=1: matches the (type, media_id) pair regardless of CCID.
    assert!(crl.recordable_media_revoked(
        RecordableMediaType::DvdRecordable,
        [0x77; 16],
        cc_id(0xAA), // matching CCID
    ));
    assert!(crl.recordable_media_revoked(
        RecordableMediaType::DvdRecordable,
        [0x77; 16],
        cc_id(0xBB), // non-matching CCID, still revoked because ICCID=1
    ));
    // But the wrong media type does NOT match.
    assert!(!crl.recordable_media_revoked(
        RecordableMediaType::BdRecordable,
        [0x77; 16],
        cc_id(0xAA),
    ));
    // And the wrong media ID does NOT match.
    assert!(!crl.recordable_media_revoked(
        RecordableMediaType::DvdRecordable,
        [0x66; 16],
        cc_id(0xAA),
    ));

    // The §2.7 "is_content_certificate_id_revoked" query does NOT
    // surface ICCID=1 RMRRs (they revoke by media, not by CCID).
    assert!(!crl.is_content_certificate_id_revoked(cc_id(0xAA)));
}

#[test]
fn managed_copy_server_revocation_range_semantics() {
    let (priv_key, _pub_key) = synth_la_key_pair();
    let crl = build_three_segment_crl(&priv_key);

    // Records range=2 from id [0x10,0,0,0,0,0]: revokes 3 IDs.
    let start = ManagedCopyServerCertificateId([0x10, 0, 0, 0, 0, 0]);
    let mid = ManagedCopyServerCertificateId([0x10, 0, 0, 0, 0, 1]);
    let end = ManagedCopyServerCertificateId([0x10, 0, 0, 0, 0, 2]);
    let just_after = ManagedCopyServerCertificateId([0x10, 0, 0, 0, 0, 3]);
    assert!(crl.is_managed_copy_server_id_revoked(start));
    assert!(crl.is_managed_copy_server_id_revoked(mid));
    assert!(crl.is_managed_copy_server_id_revoked(end));
    assert!(!crl.is_managed_copy_server_id_revoked(just_after));

    // The second record is a singleton.
    let singleton = ManagedCopyServerCertificateId([0x99, 0x88, 0x77, 0x66, 0x55, 0x44]);
    assert!(crl.is_managed_copy_server_id_revoked(singleton));
}

#[test]
fn tampering_anywhere_in_the_chain_breaks_last_signature() {
    let (priv_key, pub_key) = synth_la_key_pair();
    let mut crl = build_three_segment_crl(&priv_key);
    // Sanity:
    crl.verify_last_segment_signature(&pub_key).unwrap();
    // Tamper with a record in segment 0.
    if let RevocationRecord::ContentCertificateId { id, .. } = &mut crl.segments[0].records[0] {
        id.0[2] ^= 0x01;
    }
    // Both the per-segment verify on segment 0 AND the cumulative
    // last-segment verify must now reject.
    assert_eq!(
        crl.verify_segment_signature(0, &pub_key),
        Err(AacsError::MkbSignatureInvalid)
    );
    assert_eq!(
        crl.verify_last_segment_signature(&pub_key),
        Err(AacsError::MkbSignatureInvalid)
    );
}

#[test]
fn padding_after_last_segment_tolerated() {
    let (priv_key, pub_key) = synth_la_key_pair();
    let crl = build_three_segment_crl(&priv_key);
    let mut bytes = crl.to_bytes();
    // Append spec-permitted 0x00 padding.
    bytes.extend(std::iter::repeat_n(0u8, 65));
    let reparsed = ContentRevocationList::parse(&bytes).unwrap();
    assert_eq!(reparsed, crl);
    reparsed.verify_last_segment_signature(&pub_key).unwrap();
}

#[test]
fn unknown_record_type_in_otherwise_valid_segment_preserved() {
    let (priv_key, pub_key) = synth_la_key_pair();
    // Hand-build a Revocation Record Set: one Unknown-type record
    // (record_type 0xE) followed by a Content Certificate ID record.
    let unknown = RevocationRecord::Unknown {
        record_type: 0xE,
        bytes: [0xE0, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
    };
    let known = RevocationRecord::ContentCertificateId {
        range: 0,
        id: cc_id(0x70),
    };
    let segment_size = 4u32 + 16u32 + SEGMENT_SIGNATURE_LEN as u32;
    let mut crl = ContentRevocationList {
        list_type: LIST_TYPE_FIRST_GEN,
        reserved_nibble: 0,
        list_version: 0x01,
        number_of_segments: 1,
        segments: vec![CrlSegment {
            segment_size,
            records: vec![unknown.clone(), known.clone()],
            signature: [0u8; SEGMENT_SIGNATURE_LEN],
        }],
    };
    let payload = crl.signed_range_for_segment(0).unwrap();
    crl.segments[0].signature = sign(&priv_key, &payload);

    let bytes = crl.to_bytes();
    let reparsed = ContentRevocationList::parse(&bytes).unwrap();
    assert_eq!(reparsed, crl);
    crl.verify_segment_signature(0, &pub_key).unwrap();

    // Unknown records are skipped by the revocation queries; the
    // adjacent CCID record still applies.
    assert!(crl.is_content_certificate_id_revoked(cc_id(0x70)));
}

#[test]
fn parse_rejects_zero_segment_count() {
    // Number_of_Segments == 0 violates the spec ("shall be at least 1")
    // even when the rest of the header is otherwise sane.
    let bytes = [
        0x00, 0x00, 0x01, 0x00, // header: List Type=0, version=1, N=0
    ];
    assert!(matches!(
        ContentRevocationList::parse(&bytes),
        Err(AacsError::InvalidValue { .. })
    ));
}

#[test]
fn parse_rejects_truncated_buffer() {
    // 2 bytes < CRL_HEADER_LEN
    assert!(matches!(
        ContentRevocationList::parse(&[0x00, 0x00]),
        Err(AacsError::Truncated(_))
    ));
}
