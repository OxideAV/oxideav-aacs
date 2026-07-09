//! Round 401 — hostile-input hardening battery for every public
//! byte-slice parser entry point.
//!
//! AACS on-disc structures and SCSI response buffers arrive from an
//! untrusted medium / drive. A malformed record length, an oversized
//! declared count, a truncated tail, or a byte-flipped header must
//! surface as a typed [`AacsError`] — never a panic (out-of-bounds
//! slice, arithmetic overflow, or `unwrap` on `None`).
//!
//! This file feeds each parser three adversarial corpora:
//!   1. Random + all-zero + all-ones buffers across a wide length range.
//!   2. Attacker-controlled internal count/length fields driven to
//!      their extremes (the values a hostile MKB / CHT would carry).
//!   3. Smart mutation of a *valid* fixture: every prefix truncation
//!      plus every 2/3/4-byte window overwritten with 0x00 / 0xFF,
//!      which reaches the length-driven inner loops that random noise
//!      almost never unlocks.
//!
//! Every byte is synthesised in-source; no disc fixture, no key
//! material. A panic in any callee fails the test with the offending
//! input.

use oxideav_aacs::content_certificate::ContentCertificateId;
use oxideav_aacs::crl::{
    ContentRevocationList, CrlSegment, RevocationRecord, LIST_TYPE_FIRST_GEN, SEGMENT_SIGNATURE_LEN,
};
use oxideav_aacs::*;

/// Deterministic xorshift so the corpus is reproducible across runs.
struct XorShift(u64);
impl XorShift {
    fn next_byte(&mut self) -> u8 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 & 0xFF) as u8
    }
    fn buf(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_byte()).collect()
    }
}

/// General-purpose corpus: empty, zero-fill, one-fill, and pseudo-random
/// buffers over a length range that brackets every fixed AACS structure
/// size (16 B ids, 40 B signatures, 72/82/92/112 B AKE payloads, 6144 B
/// aligned unit, 24576/32768 B MKB packs).
fn general_corpus() -> Vec<Vec<u8>> {
    let mut v = Vec::new();
    for len in 0..=520usize {
        v.push(vec![0u8; len]);
    }
    for len in [
        0usize, 1, 2, 4, 8, 15, 16, 17, 40, 41, 52, 72, 82, 92, 112, 128, 256, 512, 1024, 2048,
        6144, 24576, 32768,
    ] {
        v.push(vec![0xFFu8; len]);
    }
    let mut r = XorShift(0x1234_5678_9abc_def0);
    for len in [
        1usize, 2, 3, 4, 5, 8, 16, 17, 20, 24, 32, 36, 40, 41, 48, 52, 64, 72, 80, 82, 92, 96, 112,
        128, 200, 256, 300, 512, 1000, 4096, 6144, 24578, 32770,
    ] {
        for _ in 0..24 {
            v.push(r.buf(len));
        }
    }
    v
}

/// Every 2/3/4-byte window of `seed` overwritten with 0x00 then 0xFF,
/// plus every prefix truncation. This is the mutation that drives the
/// declared-length / declared-count fields of a real structure to
/// hostile values while keeping the surrounding framing intact.
fn smart_mutations(seed: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(seed.len() * 8);
    for n in 0..=seed.len() {
        out.push(seed[..n].to_vec());
    }
    for w in [2usize, 3, 4] {
        if seed.len() < w {
            continue;
        }
        for start in 0..=seed.len() - w {
            for fill in [0x00u8, 0xFF] {
                let mut m = seed.to_vec();
                for b in m.iter_mut().skip(start).take(w) {
                    *b = fill;
                }
                out.push(m);
            }
        }
    }
    out
}

fn mkb_record(tag: u8, body: &[u8]) -> Vec<u8> {
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

/// A structurally-valid Type-3 MKB exercising the Type-and-Version,
/// Host Revocation List (with a signature block), Explicit
/// Subset-Difference, Media Key Data, Verify Media Key, and End-of-MKB
/// record parsers.
fn valid_mkb() -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut tv = Vec::new();
    tv.extend_from_slice(&0x0003_1003u32.to_be_bytes());
    tv.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend(mkb_record(0x10, &tv));

    let mut hr = Vec::new();
    hr.extend_from_slice(&2u32.to_be_bytes()); // total entries
    hr.extend_from_slice(&2u32.to_be_bytes()); // entries in block
    hr.extend_from_slice(&[0u8; 8]);
    hr.extend_from_slice(&[1u8; 8]);
    hr.extend_from_slice(&[0u8; 40]); // signature
    bytes.extend(mkb_record(0x21, &hr));

    bytes.extend(mkb_record(0x04, &[0x00, 1, 2, 3, 4, 0x00, 5, 6, 7, 8]));
    bytes.extend(mkb_record(0x07, &[0, 0, 0, 5, 0, 0, 1, 0, 0, 2])); // subdiff index
    bytes.extend(mkb_record(0x05, &[0x33u8; 48])); // media key data
    bytes.extend(mkb_record(0x0D, &[0x55u8; 24])); // variant number
    bytes.extend(mkb_record(0x81, &[0x42u8; 16])); // verify media key
    bytes.extend(mkb_record(0x02, &[0u8; 40])); // end of MKB
    bytes
}

fn valid_crl_bytes() -> Vec<u8> {
    let recs = vec![
        RevocationRecord::ContentCertificateId {
            range: 3,
            id: ContentCertificateId([1, 2, 3, 4, 5, 6]),
        },
        RevocationRecord::ContentCertificateId {
            range: 0,
            id: ContentCertificateId([9, 8, 7, 6, 5, 4]),
        },
    ];
    let seg_size = 4 + SEGMENT_SIGNATURE_LEN as u32 + recs.len() as u32 * 8;
    ContentRevocationList {
        list_type: LIST_TYPE_FIRST_GEN,
        reserved_nibble: 0,
        list_version: 0x42,
        number_of_segments: 1,
        segments: vec![CrlSegment {
            segment_size: seg_size,
            records: recs,
            signature: [0u8; SEGMENT_SIGNATURE_LEN],
        }],
    }
    .to_bytes()
}

fn valid_unit_key() -> Vec<u8> {
    let kbs: u32 = 0x80;
    let mut out = vec![0u8; kbs as usize];
    out[0..4].copy_from_slice(&kbs.to_be_bytes());
    out[16] = 0x01;
    out[17] = 0x01;
    out[20..22].copy_from_slice(&1u16.to_be_bytes());
    out[22..24].copy_from_slice(&1u16.to_be_bytes());
    out[24..26].copy_from_slice(&0u16.to_be_bytes());
    let n: u16 = 2;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(&[0u8; 14]);
    for _ in 0..n {
        out.extend_from_slice(&[0u8; 16]); // MAC of PMSN
        out.extend_from_slice(&[0u8; 16]); // MAC of DBN
        out.extend_from_slice(&[0x77u8; 16]); // encrypted CPS unit key
    }
    out
}

/// Drive every single-argument byte-slice parser across the general
/// corpus; none may panic.
#[test]
fn general_corpus_never_panics() {
    for b in general_corpus() {
        let _ = Mkb::parse(&b);
        let _ = ContentRevocationList::parse(&b);
        let _ = UnitKeyFile::parse(&b);
        let _ = ContentCertificate::parse(&b);
        let _ = BdFormatSpecificSection::parse(&b);
        let _ = parse_report_key_agid(&b);
        let _ = parse_report_key_drive_cert_chal(&b);
        let _ = parse_report_key_drive_key(&b);
        let _ = parse_report_key_drive_cert(&b);
        let _ = parse_volume_id_response(&b);
        let _ = parse_media_serial_response(&b);
        let _ = parse_media_id_response(&b);
        let _ = parse_report_key_binding_nonce(&b);
        let _ = parse_data_keys_response(&b);
        let _ = parse_bus_encryption_sector_extents_response(&b);
        let _ = parse_mkb_pack_response(&b);
        let _ = parse_cprm_mkb_pack_response(&b);
        let _ = parse_send_key_host_cert_chal(&b);
        let _ = parse_send_key_host_key(&b);
        let _ = parse_send_disc_structure_write_data_key(&b);
        let _ = parse_send_disc_structure_bus_encryption_sector_extents(&b);
        let _ = parse_aacs_feature_descriptor(&b);
        // CPS Unit Usage File / CCI_and_other_info parsers.
        let _ = CpsUnitUsageFile::parse(&b);
        let _ = CciAndOtherInfo::parse(&b);
        let _ = BasicCci::parse_data(&b);
        let _ = EnhancedTitleUsage::parse_data(&b);
        let _ = KeyManagementOnline::parse_data(&b);
        let _ = ContentOwnerAuthorizedOutputs::parse_data(&b);
    }
}

/// The Content Hash Table header counts are attacker-controlled `u32`s
/// (they come from the Content Certificate). A hostile pair must not
/// overflow the `n_digests * CLIP_DESCRIPTOR_SIZE` / `n_hash_units *
/// HASH_VALUE_SIZE` size computations.
#[test]
fn cht_adversarial_counts_never_panic() {
    let corpus = general_corpus();
    let counts = [
        0u32,
        1,
        2,
        3,
        5,
        256,
        0x0001_0000,
        0x00FF_FFFF,
        0x4000_0000,
        0x8000_0000,
        0xFFFF_FFFE,
        0xFFFF_FFFF,
    ];
    for b in corpus.iter().step_by(7) {
        for &nd in &counts {
            for &nh in &counts {
                let _ = ContentHashTable::parse(b, nd, nh);
            }
        }
    }
}

#[test]
fn mkb_smart_mutations_never_panic() {
    for m in smart_mutations(&valid_mkb()) {
        let _ = Mkb::parse(&m);
    }
}

#[test]
fn crl_smart_mutations_never_panic() {
    for m in smart_mutations(&valid_crl_bytes()) {
        let _ = ContentRevocationList::parse(&m);
    }
}

#[test]
fn unit_key_smart_mutations_never_panic() {
    for m in smart_mutations(&valid_unit_key()) {
        let _ = UnitKeyFile::parse(&m);
    }
}

/// A CPS Unit Usage File carrying one block of each defined type; the
/// loop-count and per-block `data_length` fields are the mutation
/// targets that drive the Primary/Secondary area walk.
fn valid_usage_file() -> Vec<u8> {
    CpsUnitUsageFile {
        primary: vec![
            BasicCci {
                epn_unasserted: true,
                cci: Cci::CopyOneGeneration,
                image_constraint_token: false,
                digital_only_token: true,
                apstb: 0b101,
                title_types: vec![TypeOfTitle::Enhanced, TypeOfTitle::Basic],
            }
            .to_block(),
            EnhancedTitleUsage {
                title_id: 7,
                cacheable: Cacheable::Cacheable,
                period: 24,
                after: Some(TitleDate {
                    year: 2026,
                    month: 1,
                    day: 2,
                    hour: 3,
                    minute: 4,
                    timezone: 0,
                }),
                before: None,
            }
            .to_block(),
            KeyManagementOnline {
                unit_key_status: 2,
                binding_type: BindingType::DeviceContent,
            }
            .to_block(),
        ],
        secondary: vec![ContentOwnerAuthorizedOutputs {
            output_control_bits: [0x5A; 16],
        }
        .to_block()],
        has_secondary: true,
    }
    .to_bytes()
}

#[test]
fn usage_file_smart_mutations_never_panic() {
    for m in smart_mutations(&valid_usage_file()) {
        let _ = CpsUnitUsageFile::parse(&m);
    }
}

/// The valid fixtures themselves must still parse cleanly — a guard
/// that the mutation seeds are actually well-formed (otherwise the
/// mutation battery would be exercising an already-broken input).
#[test]
fn valid_fixtures_parse() {
    assert!(Mkb::parse(&valid_mkb()).is_ok());
    assert!(ContentRevocationList::parse(&valid_crl_bytes()).is_ok());
    assert!(UnitKeyFile::parse(&valid_unit_key()).is_ok());
    assert!(CpsUnitUsageFile::parse(&valid_usage_file()).is_ok());
}
