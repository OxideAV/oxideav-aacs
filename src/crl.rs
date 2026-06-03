//! Content Revocation List (CRL) parse, per-segment ECDSA verify, and
//! revocation-record lookup per AACS Pre-recorded Video Book Final
//! 0.953 §2.7 (Tables 2-2 / 2-3 / 2-4 / 2-5).
//!
//! The CRL (`ContentRevocation.lst` stored under the `\AACS\` directory
//! and `\AACS\DUPLICATE\`) is the AACS-LA-signed list of revoked
//! Content Certificate IDs, Managed Copy Server Certificate IDs, and
//! Recordable Media Revocation Records (RMRR) that a Licensed Player
//! consults before honouring a Content Certificate (whose
//! `Minimum_CRL_Version` requirement bounds the acceptable CRL
//! version).
//!
//! ## On-disc layout (Table 2-2)
//!
//! ```text
//! CRL Header
//!   byte 0      : List Type (high 4 bits) || reserved (low 4 bits)
//!                 List Type == 0x0 => first-generation AACS CRL.
//!   bytes 1..=2 : List Version (u16 big-endian).
//!   byte 3      : Number of Segments (N), at least 1.
//! CRL Segment #1
//!   bytes 4..=7         : Segment Size (S1, u32 big-endian).
//!                         Spans from this field through the
//!                         segment's Entity Signature.
//!   bytes 8..=4+S1-41   : Revocation Record Set #1 (variable, may be
//!                         empty).
//!   bytes 4+S1-40..=4+S1-1
//!                       : Entity Signature #1 (40 bytes, AACS_Sign
//!                         under the AACS LA Entity Private Key over
//!                         all bytes preceding this signature including
//!                         the CRL Header and the segment's own
//!                         Segment Size + Revocation Record Set).
//! CRL Segment #2 … #N
//!   identical layout. Each segment's Entity Signature is computed over
//!   the cumulative prefix "CRL Header || segment #1 bytes || segment
//!   #2 bytes || … || (this segment's Segment Size + Revocation Record
//!   Set)".
//! ```
//!
//! Segment Size #1 is capped at `128 KiB - 4` bytes (the spec's "no
//! more than 128K bytes less the CRL Header" rule, since the Header is
//! 4 bytes). Subsequent segments have no such cap.
//!
//! Records inside a Revocation Record Set are a stream of 8-byte
//! records (PVB §2.7 prose: "shall consist of" entries with the
//! Table-2-3 / Table-2-4 / Table-2-5 layouts). The leading 4 bits of
//! the first record byte carry the `Record_Type` tag; the remaining
//! 60 bits + the next 7 bytes carry the type-specific payload.
//!
//! `Record_Type` values defined by the spec are:
//!
//! | Tag  | Meaning                                                 |
//! | ---: | ------------------------------------------------------- |
//! | `0x0`| Revocation Record for Content Certificate ID (Table 2-3)|
//! | `0x1`| Revocation Record for Managed Copy Server Certificate ID (Table 2-4)|
//! | `0x2`| RMRR record 1 of 3 (Table 2-5 first row)                |
//! | `0x3`| RMRR record 2 of 3 (Table 2-5 second row)               |
//! | `0x4`| RMRR record 3 of 3 (Table 2-5 third row)                |
//!
//! Per PVB §2.7 ("If a Licensed Product encounters a Revocation Record
//! with a Record_Type value it does not recognize, the record shall be
//! ignored."), unknown 8-byte records are preserved as
//! [`RevocationRecord::Unknown`] entries rather than aborting the
//! parse. RMRR records 2 and 3 that don't follow an RMRR-1 (corrupt
//! stream) are similarly carried through as `Unknown` so the player
//! can still process the valid records that surround them.
//!
//! ## Verification (PVB §2.7)
//!
//! For each segment #k:
//!
//! ```text
//! AACS_Verify(AACS_LApub, Segsig_k, Seg_k)
//! ```
//!
//! where `Seg_k` is the byte range "from byte 0 of the CRL Header
//! through and including the (Segment Size #k + Revocation Record
//! Set #k) of this segment", i.e. *everything before this segment's
//! 40-byte Entity Signature*. Because each segment's signed prefix
//! transitively covers segments `1..=k-1`, verifying the *last*
//! segment's signature alone validates every preceding segment per the
//! spec note "when reading more than one CRL Segment, only the
//! signature of the last Segment shall be checked".
//!
//! The CRL ships **no** AACS LA Entity public key — AACS LA
//! distributes it only to licensees. The verifier takes a
//! [`crate::ec::Point`] parameter; tests use a self-issued synthetic
//! LA identity.

use crate::content_certificate::ContentCertificateId;
use crate::ec::Point;
use crate::ecdsa::{verify as ecdsa_verify, Signature as EcdsaSignature};
use crate::error::AacsError;

/// First-generation AACS CRL List Type (PVB Table 2-2: "List Type:
/// `0000_2`").
pub const LIST_TYPE_FIRST_GEN: u8 = 0x0;

/// `Record_Type` value `0x0` — Revocation Record for Content
/// Certificate ID (PVB Table 2-3).
pub const RECORD_TYPE_CONTENT_CERTIFICATE_ID: u8 = 0x0;

/// `Record_Type` value `0x1` — Revocation Record for Managed Copy
/// Server Certificate ID (PVB Table 2-4).
pub const RECORD_TYPE_MANAGED_COPY_SERVER_ID: u8 = 0x1;

/// `Record_Type` value `0x2` — RMRR record 1 of 3 (PVB Table 2-5
/// first row).
pub const RECORD_TYPE_RMRR_PART_1: u8 = 0x2;

/// `Record_Type` value `0x3` — RMRR record 2 of 3 (PVB Table 2-5
/// second row).
pub const RECORD_TYPE_RMRR_PART_2: u8 = 0x3;

/// `Record_Type` value `0x4` — RMRR record 3 of 3 (PVB Table 2-5
/// third row).
pub const RECORD_TYPE_RMRR_PART_3: u8 = 0x4;

/// Byte length of one Revocation Record on the wire (PVB Tables 2-3 /
/// 2-4: "8 byte Revocation Record"; Table 2-5 RMRR is three contiguous
/// 8-byte records).
pub const REVOCATION_RECORD_LEN: usize = 8;

/// Byte length of one CRL segment's trailing Entity Signature (PVB
/// Table 2-2: "A 40-byte Signature field").
pub const SEGMENT_SIGNATURE_LEN: usize = 40;

/// Fixed byte length of the CRL Header (PVB Table 2-2: 1-byte
/// List Type + reserved nibble, 2-byte List Version, 1-byte Number of
/// Segments).
pub const CRL_HEADER_LEN: usize = 4;

/// PVB §2.7: "The Segment Size value for the first segment (CRL
/// Segment #1) shall be no more than 128K bytes less the CRL Header."
/// The CRL Header is `CRL_HEADER_LEN` = 4 bytes, so the cap is
/// `128 * 1024 - 4`.
pub const SEGMENT_1_SIZE_MAX: u32 = 128 * 1024 - CRL_HEADER_LEN as u32;

/// 6-byte Managed Copy Server Certificate ID (PVB Table 2-4: "A 6-byte
/// Managed Copy Server Certificate ID value indicating the lowest
/// numbered ID to be revoked.").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ManagedCopyServerCertificateId(pub [u8; 6]);

/// AACS Recordable Media Type field of a Recordable Media Revocation
/// Record (PVB Table 2-5: 3 bits, where `0 = BD-R/RE`, `1 = HD
/// DVD-R/RW/RAM`, `2 = DVD-R/RW/RAM`, `3 = +R/+RW`; values 4..=7 are
/// reserved).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RecordableMediaType {
    /// `0` — BD-R / BD-RE.
    BdRecordable = 0,
    /// `1` — HD DVD-R / HD DVD-RW / HD DVD-RAM.
    HdDvdRecordable = 1,
    /// `2` — DVD-R / DVD-RW / DVD-RAM.
    DvdRecordable = 2,
    /// `3` — `+R` / `+RW`.
    PlusRecordable = 3,
    /// Spec-reserved value `4..=7`, carried through as the raw 3-bit
    /// integer so a player can recognise the record without panicking
    /// on a future-revision value.
    Reserved(u8),
}

impl RecordableMediaType {
    /// Decode the low 3 bits of a stored byte per PVB Table 2-5.
    pub fn from_u3(v: u8) -> Self {
        match v & 0x07 {
            0 => Self::BdRecordable,
            1 => Self::HdDvdRecordable,
            2 => Self::DvdRecordable,
            3 => Self::PlusRecordable,
            other => Self::Reserved(other),
        }
    }

    /// Re-encode to the low 3 bits of a wire byte.
    pub fn to_u3(self) -> u8 {
        match self {
            Self::BdRecordable => 0,
            Self::HdDvdRecordable => 1,
            Self::DvdRecordable => 2,
            Self::PlusRecordable => 3,
            Self::Reserved(v) => v & 0x07,
        }
    }
}

/// Recordable Media Revocation Record (RMRR) — the three-part record
/// defined in PVB Table 2-5, used to revoke AACS Prepared Video Content
/// bound to specific AACS Recordable Media IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordableMediaRevocation {
    /// Ignore-Content-Certificate-ID flag. When set, only the
    /// `media_id` is used for revocation matching per PVB §2.7.2 step 3
    /// of the Prepared Video book: "Is the value of the ICCID flag
    /// stored in the RMRR equal to 1? If it is then this RMRR is
    /// applicable."
    pub iccid: bool,
    /// Recordable Media Type (3 bits, Table 2-5).
    pub media_type: RecordableMediaType,
    /// Content Certificate ID associated with the revoked content,
    /// PVB Table 2-5: "the concatenation of the 2-byte Applicant ID
    /// and the 4-byte Content Sequence Number".
    pub content_certificate_id: ContentCertificateId,
    /// 128-bit AACS Recordable Media identifier. For Media Types with
    /// fewer than 128 bits, the most significant bits are zero per the
    /// spec note.
    pub media_id: [u8; 16],
}

/// One Revocation Record decoded from a CRL Segment's Revocation
/// Record Set (PVB §2.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationRecord {
    /// Revocation Record for Content Certificate ID (PVB Table 2-3,
    /// `Record_Type == 0x0`).
    ContentCertificateId {
        /// 12-bit Range value. `0` means only this ID is revoked;
        /// `r > 0` means the IDs `id, id+1, …, id+r` (a span of `r+1`
        /// IDs) are revoked per the PVB §2.7 prose.
        range: u16,
        /// Lowest-numbered revoked Content Certificate ID (PVB Table
        /// 2-3: "A 6-byte Content Certificate ID value").
        id: ContentCertificateId,
    },
    /// Revocation Record for Managed Copy Server Certificate ID (PVB
    /// Table 2-4, `Record_Type == 0x1`).
    ManagedCopyServerCertificateId {
        /// 12-bit Range value, same semantics as
        /// [`Self::ContentCertificateId`].
        range: u16,
        /// Lowest-numbered revoked Managed Copy Server Certificate ID.
        id: ManagedCopyServerCertificateId,
    },
    /// Recordable Media Revocation Record (PVB Table 2-5, made from
    /// the three contiguous `Record_Type` `0x2 / 0x3 / 0x4` rows). The
    /// parser folds the three on-wire 8-byte records into a single
    /// [`RecordableMediaRevocation`] entry on parse.
    RecordableMedia(RecordableMediaRevocation),
    /// A record whose `Record_Type` value isn't defined by the spec.
    /// Per PVB §2.7 ("If a Licensed Product encounters a Revocation
    /// Record with a Record_Type value it does not recognize, the
    /// record shall be ignored.") this is preserved so the caller can
    /// observe the on-disc bytes, but the higher-level revocation
    /// queries don't apply it. RMRR parts 2 / 3 that don't follow a
    /// part-1 record also land here, so a corrupt stream doesn't
    /// silently drop adjacent valid records.
    Unknown {
        /// Raw 4-bit `Record_Type` tag (`0x0..=0xF`).
        record_type: u8,
        /// 8 bytes of the on-wire record, including the leading byte
        /// whose high 4 bits are `record_type`.
        bytes: [u8; REVOCATION_RECORD_LEN],
    },
}

impl RevocationRecord {
    /// `true` when this record revokes the supplied Content Certificate
    /// ID — applies to both [`Self::ContentCertificateId`] (range
    /// match) and [`Self::RecordableMedia`] with `iccid == false`
    /// (exact match on the embedded Content Certificate ID, per the
    /// Prepared Video Book §2.7.2 step 4).
    ///
    /// `Self::RecordableMedia` records with `iccid == true` revoke by
    /// Media ID only, not by Content Certificate ID; this method
    /// returns `false` for them.
    pub fn revokes_content_certificate_id(&self, query: ContentCertificateId) -> bool {
        match self {
            Self::ContentCertificateId { range, id } => id_in_range(query.0, id.0, *range),
            Self::RecordableMedia(r) if !r.iccid => r.content_certificate_id == query,
            _ => false,
        }
    }

    /// `true` when this record revokes the supplied Managed Copy Server
    /// Certificate ID (only [`Self::ManagedCopyServerCertificateId`]
    /// records match).
    pub fn revokes_managed_copy_server_id(&self, query: ManagedCopyServerCertificateId) -> bool {
        match self {
            Self::ManagedCopyServerCertificateId { range, id } => {
                id_in_range(query.0, id.0, *range)
            }
            _ => false,
        }
    }
}

/// Compare a 6-byte query ID against the `[start, start + range]`
/// inclusive range. PVB §2.7: "A value of zero in the Range field
/// indicates that only one ID is being revoked."
fn id_in_range(query: [u8; 6], start: [u8; 6], range: u16) -> bool {
    let q = u64_from_6(query);
    let s = u64_from_6(start);
    let r = u64::from(range);
    q >= s && q <= s.saturating_add(r)
}

fn u64_from_6(b: [u8; 6]) -> u64 {
    ((b[0] as u64) << 40)
        | ((b[1] as u64) << 32)
        | ((b[2] as u64) << 24)
        | ((b[3] as u64) << 16)
        | ((b[4] as u64) << 8)
        | (b[5] as u64)
}

/// One CRL Segment after parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlSegment {
    /// Segment Size field from the on-disc record. Equals
    /// `4 (own size) + revocation_record_set_bytes + 40 (signature)`.
    pub segment_size: u32,
    /// Decoded Revocation Records (Table 2-3 / 2-4 / 2-5 / Unknown).
    pub records: Vec<RevocationRecord>,
    /// Trailing 40-byte AACS_Sign Entity Signature for this segment
    /// over the cumulative prefix described at the module-level docs.
    pub signature: EcdsaSignature,
}

/// A parsed Content Revocation List (PVB §2.7 / Table 2-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentRevocationList {
    /// CRL Header `List Type` value (PVB Table 2-2: 4-bit field
    /// occupying the high nibble of byte 0; `0x0` for the
    /// first-generation list).
    pub list_type: u8,
    /// 4-bit reserved low nibble of CRL Header byte 0, preserved so the
    /// canonical round-trip is byte-exact for forward-compatibility.
    pub reserved_nibble: u8,
    /// 16-bit `List Version` field (PVB Table 2-2 byte 1..=2),
    /// big-endian.
    pub list_version: u16,
    /// `Number of Segments` field (PVB Table 2-2 byte 3).
    pub number_of_segments: u8,
    /// Decoded CRL Segments in order, length == `number_of_segments`.
    pub segments: Vec<CrlSegment>,
}

impl ContentRevocationList {
    /// Parse a `ContentRevocation.lst` blob per PVB Table 2-2.
    ///
    /// Trailing padding bytes after the last CRL Segment's Entity
    /// Signature are tolerated (PVB §2.2 of the Pre-recorded book:
    /// "CRL data shall be recorded from the first byte of the file, and
    /// the null (0016) padding may be attached after the CRL data in
    /// the file for authoring and mastering purposes.").
    pub fn parse(bytes: &[u8]) -> Result<Self, AacsError> {
        if bytes.len() < CRL_HEADER_LEN {
            return Err(AacsError::Truncated("CRL Header"));
        }

        let header_byte = bytes[0];
        let list_type = (header_byte >> 4) & 0x0F;
        let reserved_nibble = header_byte & 0x0F;
        let list_version = u16::from_be_bytes([bytes[1], bytes[2]]);
        let number_of_segments = bytes[3];

        if number_of_segments == 0 {
            return Err(AacsError::InvalidValue {
                what: "CRL Number of Segments (must be ≥ 1)",
                value: 0,
            });
        }

        let mut cursor = CRL_HEADER_LEN;
        let mut segments = Vec::with_capacity(usize::from(number_of_segments));

        for segment_index in 0..usize::from(number_of_segments) {
            if cursor.saturating_add(4) > bytes.len() {
                return Err(AacsError::Truncated("CRL Segment Size"));
            }
            let segment_size = u32::from_be_bytes([
                bytes[cursor],
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
            ]);

            // First-segment 128 KiB cap per PVB §2.7.
            if segment_index == 0 && segment_size > SEGMENT_1_SIZE_MAX {
                return Err(AacsError::InvalidValue {
                    what: "CRL Segment #1 Segment Size (must be ≤ 128 KiB − CRL Header)",
                    value: u64::from(segment_size),
                });
            }

            let segment_size_usize = segment_size as usize;
            // Segment Size spans from the Segment Size field through
            // the 40-byte Entity Signature; the Revocation Record Set
            // therefore occupies `segment_size − 4 (size field) − 40
            // (signature)` bytes.
            let min_segment_len = 4usize
                .checked_add(SEGMENT_SIGNATURE_LEN)
                .ok_or(AacsError::Truncated("CRL Segment minimum length"))?;
            if segment_size_usize < min_segment_len {
                return Err(AacsError::InvalidValue {
                    what:
                        "CRL Segment Size (must accommodate 4-byte size field + 40-byte signature)",
                    value: u64::from(segment_size),
                });
            }

            let segment_end = cursor
                .checked_add(segment_size_usize)
                .ok_or(AacsError::Truncated("CRL Segment end offset"))?;
            if segment_end > bytes.len() {
                return Err(AacsError::OversizedRecord {
                    what: "CRL Segment",
                    declared: segment_end,
                    available: bytes.len(),
                });
            }

            let record_set_start = cursor + 4;
            let record_set_end = segment_end - SEGMENT_SIGNATURE_LEN;
            let record_set_bytes = &bytes[record_set_start..record_set_end];

            let records = parse_revocation_record_set(record_set_bytes)?;

            let mut signature = [0u8; SEGMENT_SIGNATURE_LEN];
            signature.copy_from_slice(&bytes[record_set_end..segment_end]);

            segments.push(CrlSegment {
                segment_size,
                records,
                signature,
            });

            cursor = segment_end;
        }

        // PVB §2.2 padding tolerance: trailing 0x00 bytes after the
        // final segment are allowed and silently dropped on parse.
        for (i, b) in bytes[cursor..].iter().enumerate() {
            if *b != 0 {
                return Err(AacsError::InvalidValue {
                    what: "CRL trailing byte (only 0x00 padding permitted)",
                    value: u64::from(*b) | (i as u64) << 8,
                });
            }
        }

        Ok(Self {
            list_type,
            reserved_nibble,
            list_version,
            number_of_segments,
            segments,
        })
    }

    /// Reconstruct the canonical on-disc byte form of the CRL (the
    /// `to_bytes` ↔ `parse` round-trip is byte-exact for any value
    /// that parses with no trailing padding).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push((self.list_type << 4) | (self.reserved_nibble & 0x0F));
        out.extend_from_slice(&self.list_version.to_be_bytes());
        out.push(self.number_of_segments);
        for seg in &self.segments {
            out.extend_from_slice(&seg.segment_size.to_be_bytes());
            for r in &seg.records {
                out.extend_from_slice(&encode_revocation_record(r));
            }
            out.extend_from_slice(&seg.signature);
        }
        out
    }

    /// Cumulative-prefix signed range for segment `k` (0-based) per PVB
    /// §2.7: "from the CRL Header through and including this segment's
    /// Revocation Record Set", exclusive of this segment's Entity
    /// Signature.
    ///
    /// Returns `None` if `k >= self.segments.len()`.
    pub fn signed_range_for_segment(&self, k: usize) -> Option<Vec<u8>> {
        if k >= self.segments.len() {
            return None;
        }
        let mut out = Vec::new();
        out.push((self.list_type << 4) | (self.reserved_nibble & 0x0F));
        out.extend_from_slice(&self.list_version.to_be_bytes());
        out.push(self.number_of_segments);
        for (i, seg) in self.segments.iter().enumerate() {
            out.extend_from_slice(&seg.segment_size.to_be_bytes());
            for r in &seg.records {
                out.extend_from_slice(&encode_revocation_record(r));
            }
            if i == k {
                // Stop *before* this segment's signature.
                break;
            }
            out.extend_from_slice(&seg.signature);
        }
        Some(out)
    }

    /// Verify the Entity Signature on segment `k` (0-based) against
    /// the AACS LA Entity public key.
    ///
    /// Returns:
    /// * `Ok(())` on success;
    /// * `AacsError::InvalidValue` if `k` is out of range;
    /// * `AacsError::MkbSignatureInvalid` on a verify mismatch
    ///   (variant reused so the consumer can fold all `AACS_Verify`
    ///   failures through one branch — the same convention
    ///   [`crate::content_certificate::ContentCertificate::verify_signature`]
    ///   uses).
    pub fn verify_segment_signature(&self, k: usize, aacs_la_pub: &Point) -> Result<(), AacsError> {
        let payload = self
            .signed_range_for_segment(k)
            .ok_or(AacsError::InvalidValue {
                what: "CRL segment index",
                value: k as u64,
            })?;
        let sig = &self.segments[k].signature;
        if ecdsa_verify(aacs_la_pub, sig, &payload) {
            Ok(())
        } else {
            Err(AacsError::MkbSignatureInvalid)
        }
    }

    /// PVB §2.7 spec note: "when reading more than one CRL Segment,
    /// only the signature of the last Segment shall be checked since
    /// that signature includes all previous fields including previous
    /// Segments and the CRL Header." This helper runs that one check
    /// when the CRL has at least one segment.
    pub fn verify_last_segment_signature(&self, aacs_la_pub: &Point) -> Result<(), AacsError> {
        if self.segments.is_empty() {
            return Err(AacsError::InvalidValue {
                what: "CRL Number of Segments (must be ≥ 1)",
                value: 0,
            });
        }
        self.verify_segment_signature(self.segments.len() - 1, aacs_la_pub)
    }

    /// Verify every segment's Entity Signature in order. Useful for
    /// authoring-side validation; per the spec a player only needs to
    /// verify the last segment it reads.
    pub fn verify_all_segments(&self, aacs_la_pub: &Point) -> Result<(), AacsError> {
        for k in 0..self.segments.len() {
            self.verify_segment_signature(k, aacs_la_pub)?;
        }
        Ok(())
    }

    /// Iterator over every parsed Revocation Record across all
    /// segments, in segment-major / record order.
    pub fn records(&self) -> impl Iterator<Item = &RevocationRecord> + '_ {
        self.segments.iter().flat_map(|s| s.records.iter())
    }

    /// `true` when at least one record revokes the supplied Content
    /// Certificate ID. Walks both
    /// [`RevocationRecord::ContentCertificateId`] (range match) and
    /// [`RevocationRecord::RecordableMedia`] with `iccid == false`
    /// (exact match), per PVB Tables 2-3 and 2-5.
    pub fn is_content_certificate_id_revoked(&self, query: ContentCertificateId) -> bool {
        self.records()
            .any(|r| r.revokes_content_certificate_id(query))
    }

    /// `true` when at least one record revokes the supplied Managed
    /// Copy Server Certificate ID.
    pub fn is_managed_copy_server_id_revoked(&self, query: ManagedCopyServerCertificateId) -> bool {
        self.records()
            .any(|r| r.revokes_managed_copy_server_id(query))
    }

    /// PVB §2.7.2 (Prepared Video book) applicability check for a
    /// specific (media type, media ID, content certificate ID) triple.
    /// Returns `true` when at least one Recordable Media Revocation
    /// Record renders the AACS Content un-playable per the §2.7.2 four
    /// steps:
    ///
    /// 1. Recordable Media Type of the RMRR matches the queried type.
    /// 2. Media ID stored in the RMRR equals the queried Media ID.
    /// 3. If the RMRR's ICCID flag is `1`, the RMRR is applicable.
    /// 4. Otherwise, the RMRR is applicable iff its Content Certificate
    ///    ID matches the queried Content Certificate ID.
    pub fn recordable_media_revoked(
        &self,
        media_type: RecordableMediaType,
        media_id: [u8; 16],
        content_certificate_id: ContentCertificateId,
    ) -> bool {
        self.records().any(|r| {
            if let RevocationRecord::RecordableMedia(rmrr) = r {
                if rmrr.media_type != media_type {
                    return false;
                }
                if rmrr.media_id != media_id {
                    return false;
                }
                if rmrr.iccid {
                    true
                } else {
                    rmrr.content_certificate_id == content_certificate_id
                }
            } else {
                false
            }
        })
    }
}

/// Parse a Revocation Record Set — the byte range between a segment's
/// Segment Size field and its 40-byte Entity Signature. The byte
/// length must be a multiple of [`REVOCATION_RECORD_LEN`].
fn parse_revocation_record_set(bytes: &[u8]) -> Result<Vec<RevocationRecord>, AacsError> {
    if bytes.len() % REVOCATION_RECORD_LEN != 0 {
        return Err(AacsError::InvalidValue {
            what: "CRL Revocation Record Set length (must be a multiple of 8)",
            value: bytes.len() as u64,
        });
    }
    let mut records = Vec::with_capacity(bytes.len() / REVOCATION_RECORD_LEN);
    let mut i = 0;
    while i < bytes.len() {
        let slot: [u8; REVOCATION_RECORD_LEN] = bytes[i..i + REVOCATION_RECORD_LEN]
            .try_into()
            .map_err(|_| AacsError::Truncated("CRL Revocation Record"))?;
        let record_type = (slot[0] >> 4) & 0x0F;
        match record_type {
            RECORD_TYPE_CONTENT_CERTIFICATE_ID => {
                let (range, id_bytes) = decode_range_and_id(&slot);
                records.push(RevocationRecord::ContentCertificateId {
                    range,
                    id: ContentCertificateId(id_bytes),
                });
                i += REVOCATION_RECORD_LEN;
            }
            RECORD_TYPE_MANAGED_COPY_SERVER_ID => {
                let (range, id_bytes) = decode_range_and_id(&slot);
                records.push(RevocationRecord::ManagedCopyServerCertificateId {
                    range,
                    id: ManagedCopyServerCertificateId(id_bytes),
                });
                i += REVOCATION_RECORD_LEN;
            }
            RECORD_TYPE_RMRR_PART_1 => {
                // Three contiguous 8-byte records. Per PVB Table 2-5
                // they "shall not cross a CRL Segment boundary" so all
                // three must be in this byte range.
                let have_3 = i + 3 * REVOCATION_RECORD_LEN <= bytes.len();
                let part2_ok = have_3
                    && (bytes[i + REVOCATION_RECORD_LEN] >> 4) & 0x0F == RECORD_TYPE_RMRR_PART_2;
                let part3_ok = have_3
                    && (bytes[i + 2 * REVOCATION_RECORD_LEN] >> 4) & 0x0F
                        == RECORD_TYPE_RMRR_PART_3;
                if have_3 && part2_ok && part3_ok {
                    let rec1 = &bytes[i..i + REVOCATION_RECORD_LEN];
                    let rec2 = &bytes[i + REVOCATION_RECORD_LEN..i + 2 * REVOCATION_RECORD_LEN];
                    let rec3 = &bytes[i + 2 * REVOCATION_RECORD_LEN..i + 3 * REVOCATION_RECORD_LEN];
                    let rmrr = decode_rmrr(rec1, rec2, rec3);
                    records.push(RevocationRecord::RecordableMedia(rmrr));
                    i += 3 * REVOCATION_RECORD_LEN;
                } else {
                    // Malformed RMRR — preserve as Unknown so adjacent
                    // valid records aren't silently dropped.
                    records.push(RevocationRecord::Unknown {
                        record_type,
                        bytes: slot,
                    });
                    i += REVOCATION_RECORD_LEN;
                }
            }
            _ => {
                records.push(RevocationRecord::Unknown {
                    record_type,
                    bytes: slot,
                });
                i += REVOCATION_RECORD_LEN;
            }
        }
    }
    Ok(records)
}

/// PVB Tables 2-3 / 2-4 share the same shape: 4-bit Record_Type at the
/// top of byte 0, then a 12-bit Range value crossing bytes 0..=1, then
/// a 6-byte ID in bytes 2..=7.
fn decode_range_and_id(slot: &[u8; REVOCATION_RECORD_LEN]) -> (u16, [u8; 6]) {
    let range_hi = u16::from(slot[0] & 0x0F);
    let range = (range_hi << 8) | u16::from(slot[1]);
    let mut id = [0u8; 6];
    id.copy_from_slice(&slot[2..8]);
    (range, id)
}

/// PVB Table 2-5 RMRR decoder. The 3-record / 24-byte layout per
/// Table 2-5 prose:
///
/// * Record 1 (`rec1`, leading nibble `0x2`):
///   * bits 7..=4 of byte 0: `Record_Type` (`0x2`).
///   * bit 3 of byte 0: `ICCID` flag (PVB §2.7: "A 1 bit Ignore
///     Content Certificate ID flag").
///   * bits 2..=0 of byte 0: Recordable Media Type (PVB §2.7: "A 3 bit
///     Recordable Media Type field").
///   * bytes 1..=6: Content Certificate ID (6 bytes).
///   * byte 7: Media ID bits 127..=120 (MSByte).
/// * Record 2 (`rec2`, leading nibble `0x3`):
///   * bits 3..=0 of byte 0: Media ID bits 119..=116 (high nibble of
///     byte 1 of the 16-byte Media ID).
///   * bytes 1..=7: Media ID bits 111..=56.
/// * Record 3 (`rec3`, leading nibble `0x4`):
///   * bits 3..=0 of byte 0: Media ID bits 115..=112 (low nibble).
///   * bytes 1..=7: Media ID bits 55..=0.
///
/// The on-wire byte 1 of the 16-byte Media ID is reconstructed by
/// concatenating `rec2[0] & 0x0F` (high nibble) with `rec3[0] & 0x0F`
/// (low nibble) per the Table 2-5 bit layout. Bytes 2..=14 then come
/// from `rec2[1..=7]` (Media ID bits 111..=56, 7 bytes) followed by
/// `rec3[1..=7]` (Media ID bits 55..=0, 7 bytes).
fn decode_rmrr(rec1: &[u8], rec2: &[u8], rec3: &[u8]) -> RecordableMediaRevocation {
    let iccid = (rec1[0] & 0x08) != 0;
    let media_type = RecordableMediaType::from_u3(rec1[0] & 0x07);
    let mut ccid = [0u8; 6];
    ccid.copy_from_slice(&rec1[1..=6]);
    let mut media_id = [0u8; 16];
    // byte 0 of Media ID is rec1[7] (bits 127..=120).
    media_id[0] = rec1[7];
    // byte 1 of Media ID: high nibble = rec2[0]&0x0F, low nibble =
    // rec3[0]&0x0F, per Table 2-5 bit map.
    media_id[1] = ((rec2[0] & 0x0F) << 4) | (rec3[0] & 0x0F);
    // bytes 2..=8 of Media ID: rec2[1..=7] (7 bytes, Media ID bits
    // 111..=56).
    media_id[2..=8].copy_from_slice(&rec2[1..=7]);
    // bytes 9..=15 of Media ID: rec3[1..=7] (7 bytes, Media ID bits
    // 55..=0).
    media_id[9..=15].copy_from_slice(&rec3[1..=7]);
    RecordableMediaRevocation {
        iccid,
        media_type,
        content_certificate_id: ContentCertificateId(ccid),
        media_id,
    }
}

/// Re-encode an `RecordableMediaRevocation` into its 3-record on-wire
/// form (24 bytes total). Inverse of [`decode_rmrr`].
fn encode_rmrr(rmrr: &RecordableMediaRevocation) -> [u8; 3 * REVOCATION_RECORD_LEN] {
    let mut out = [0u8; 3 * REVOCATION_RECORD_LEN];
    // Record 1.
    out[0] = (RECORD_TYPE_RMRR_PART_1 << 4)
        | (if rmrr.iccid { 0x08 } else { 0x00 })
        | (rmrr.media_type.to_u3() & 0x07);
    out[1..=6].copy_from_slice(&rmrr.content_certificate_id.0);
    out[7] = rmrr.media_id[0];
    // Record 2.
    out[REVOCATION_RECORD_LEN] = (RECORD_TYPE_RMRR_PART_2 << 4) | ((rmrr.media_id[1] >> 4) & 0x0F);
    out[REVOCATION_RECORD_LEN + 1..=REVOCATION_RECORD_LEN + 7]
        .copy_from_slice(&rmrr.media_id[2..=8]);
    // Record 3.
    out[2 * REVOCATION_RECORD_LEN] = (RECORD_TYPE_RMRR_PART_3 << 4) | (rmrr.media_id[1] & 0x0F);
    out[2 * REVOCATION_RECORD_LEN + 1..=2 * REVOCATION_RECORD_LEN + 7]
        .copy_from_slice(&rmrr.media_id[9..=15]);
    out
}

/// Encode one [`RevocationRecord`] back to its on-wire form. RMRR
/// records expand to 24 bytes; everything else is exactly 8 bytes.
fn encode_revocation_record(r: &RevocationRecord) -> Vec<u8> {
    match r {
        RevocationRecord::ContentCertificateId { range, id } => {
            let mut out = vec![0u8; REVOCATION_RECORD_LEN];
            out[0] = (RECORD_TYPE_CONTENT_CERTIFICATE_ID << 4) | ((*range >> 8) as u8 & 0x0F);
            out[1] = (*range & 0xFF) as u8;
            out[2..=7].copy_from_slice(&id.0);
            out
        }
        RevocationRecord::ManagedCopyServerCertificateId { range, id } => {
            let mut out = vec![0u8; REVOCATION_RECORD_LEN];
            out[0] = (RECORD_TYPE_MANAGED_COPY_SERVER_ID << 4) | ((*range >> 8) as u8 & 0x0F);
            out[1] = (*range & 0xFF) as u8;
            out[2..=7].copy_from_slice(&id.0);
            out
        }
        RevocationRecord::RecordableMedia(rmrr) => encode_rmrr(rmrr).to_vec(),
        RevocationRecord::Unknown { bytes, .. } => bytes.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content_certificate::ContentCertificateId;
    use crate::ec::{Point, U160};
    use crate::ecdsa::sign;

    fn small_scalar(v: u32) -> U160 {
        U160 {
            limbs: [v, 0, 0, 0, 0],
        }
    }

    fn synth_la_keys() -> (U160, Point) {
        let d = small_scalar(0x1234_abcd);
        let q = Point::generator().mul_scalar(&d);
        (d, q)
    }

    fn cc_id(b: u8) -> ContentCertificateId {
        ContentCertificateId([
            b,
            b.wrapping_add(1),
            b.wrapping_add(2),
            b.wrapping_add(3),
            b.wrapping_add(4),
            b.wrapping_add(5),
        ])
    }

    fn build_signed_one_segment(
        priv_key: &U160,
        records: Vec<RevocationRecord>,
    ) -> ContentRevocationList {
        let mut record_set_bytes = Vec::new();
        for r in &records {
            record_set_bytes.extend_from_slice(&encode_revocation_record(r));
        }
        let segment_size = 4u32 + record_set_bytes.len() as u32 + SEGMENT_SIGNATURE_LEN as u32;
        let mut crl = ContentRevocationList {
            list_type: LIST_TYPE_FIRST_GEN,
            reserved_nibble: 0,
            list_version: 0x0017,
            number_of_segments: 1,
            segments: vec![CrlSegment {
                segment_size,
                records,
                signature: [0u8; SEGMENT_SIGNATURE_LEN],
            }],
        };
        let payload = crl.signed_range_for_segment(0).unwrap();
        crl.segments[0].signature = sign(priv_key, &payload);
        crl
    }

    #[test]
    fn round_trip_empty_crl_one_segment_no_records() {
        let (priv_key, pub_key) = synth_la_keys();
        let crl = build_signed_one_segment(&priv_key, vec![]);
        let bytes = crl.to_bytes();
        let reparsed = ContentRevocationList::parse(&bytes).unwrap();
        assert_eq!(reparsed, crl);
        crl.verify_segment_signature(0, &pub_key).unwrap();
        crl.verify_last_segment_signature(&pub_key).unwrap();
    }

    #[test]
    fn round_trip_content_certificate_id_records() {
        let (priv_key, pub_key) = synth_la_keys();
        let rec_a = RevocationRecord::ContentCertificateId {
            range: 0,
            id: cc_id(0x10),
        };
        let rec_b = RevocationRecord::ContentCertificateId {
            range: 5,
            id: cc_id(0x20),
        };
        let crl = build_signed_one_segment(&priv_key, vec![rec_a.clone(), rec_b.clone()]);
        let bytes = crl.to_bytes();
        let reparsed = ContentRevocationList::parse(&bytes).unwrap();
        assert_eq!(reparsed, crl);
        crl.verify_all_segments(&pub_key).unwrap();
        // exact match on a singleton-range record:
        assert!(crl.is_content_certificate_id_revoked(cc_id(0x10)));
        assert!(!crl.is_content_certificate_id_revoked(cc_id(0x11)));
        // range == 5 should cover ids 0x20..0x25 (inclusive endpoints).
        let base = cc_id(0x20).0;
        let start = u64_from_6(base);
        // Some id three above start, still in range.
        let mut mid = [0u8; 6];
        let val = start + 3;
        mid[0] = (val >> 40) as u8;
        mid[1] = (val >> 32) as u8;
        mid[2] = (val >> 24) as u8;
        mid[3] = (val >> 16) as u8;
        mid[4] = (val >> 8) as u8;
        mid[5] = val as u8;
        assert!(crl.is_content_certificate_id_revoked(ContentCertificateId(mid)));
        // Six above start: out of range.
        let mut over = [0u8; 6];
        let val = start + 6;
        over[0] = (val >> 40) as u8;
        over[1] = (val >> 32) as u8;
        over[2] = (val >> 24) as u8;
        over[3] = (val >> 16) as u8;
        over[4] = (val >> 8) as u8;
        over[5] = val as u8;
        assert!(!crl.is_content_certificate_id_revoked(ContentCertificateId(over)));
    }

    #[test]
    fn round_trip_managed_copy_server_records() {
        let (priv_key, pub_key) = synth_la_keys();
        let rec = RevocationRecord::ManagedCopyServerCertificateId {
            range: 1,
            id: ManagedCopyServerCertificateId([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
        };
        let crl = build_signed_one_segment(&priv_key, vec![rec.clone()]);
        let bytes = crl.to_bytes();
        let reparsed = ContentRevocationList::parse(&bytes).unwrap();
        assert_eq!(reparsed, crl);
        crl.verify_segment_signature(0, &pub_key).unwrap();
        assert!(
            crl.is_managed_copy_server_id_revoked(ManagedCopyServerCertificateId([
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06
            ]))
        );
        // range == 1 covers the next ID too.
        assert!(
            crl.is_managed_copy_server_id_revoked(ManagedCopyServerCertificateId([
                0x01, 0x02, 0x03, 0x04, 0x05, 0x07
            ]))
        );
        // ...but not two-above-start.
        assert!(
            !crl.is_managed_copy_server_id_revoked(ManagedCopyServerCertificateId([
                0x01, 0x02, 0x03, 0x04, 0x05, 0x08
            ]))
        );
        // Wrong record type shouldn't match content-certificate query.
        assert!(
            !crl.is_content_certificate_id_revoked(ContentCertificateId([
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06
            ]))
        );
    }

    #[test]
    fn round_trip_recordable_media_revocation() {
        let (priv_key, pub_key) = synth_la_keys();
        let media_id = [
            0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22,
            0x33, 0x44,
        ];
        let rmrr_iccid_off = RecordableMediaRevocation {
            iccid: false,
            media_type: RecordableMediaType::BdRecordable,
            content_certificate_id: cc_id(0x40),
            media_id,
        };
        let rmrr_iccid_on = RecordableMediaRevocation {
            iccid: true,
            media_type: RecordableMediaType::DvdRecordable,
            content_certificate_id: cc_id(0x50),
            media_id: [0x55; 16],
        };
        let crl = build_signed_one_segment(
            &priv_key,
            vec![
                RevocationRecord::RecordableMedia(rmrr_iccid_off),
                RevocationRecord::RecordableMedia(rmrr_iccid_on),
            ],
        );
        let bytes = crl.to_bytes();
        let reparsed = ContentRevocationList::parse(&bytes).unwrap();
        assert_eq!(reparsed, crl);
        crl.verify_all_segments(&pub_key).unwrap();

        // ICCID=0: matches only when CCID matches too.
        assert!(crl.recordable_media_revoked(
            RecordableMediaType::BdRecordable,
            media_id,
            cc_id(0x40),
        ));
        // Wrong CCID with ICCID=0 → not revoked.
        assert!(!crl.recordable_media_revoked(
            RecordableMediaType::BdRecordable,
            media_id,
            cc_id(0x41),
        ));
        // ICCID=1: matches regardless of CCID.
        assert!(crl.recordable_media_revoked(
            RecordableMediaType::DvdRecordable,
            [0x55; 16],
            cc_id(0x99),
        ));
        // Wrong media type → not revoked even when MediaID + CCID match.
        assert!(!crl.recordable_media_revoked(
            RecordableMediaType::HdDvdRecordable,
            media_id,
            cc_id(0x40),
        ));

        // The ICCID=0 RMRR also revokes by Content Certificate ID via
        // the general revokes_content_certificate_id query.
        assert!(crl.is_content_certificate_id_revoked(cc_id(0x40)));
        // The ICCID=1 RMRR does NOT revoke by CCID alone.
        assert!(!crl.is_content_certificate_id_revoked(cc_id(0x50)));
    }

    #[test]
    fn unknown_record_type_preserved_and_ignored_by_queries() {
        let (priv_key, _pub_key) = synth_la_keys();
        let unknown = RevocationRecord::Unknown {
            record_type: 0xF,
            bytes: [0xFA, 0xBC, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        };
        let crl = build_signed_one_segment(&priv_key, vec![unknown.clone()]);
        let bytes = crl.to_bytes();
        let reparsed = ContentRevocationList::parse(&bytes).unwrap();
        assert_eq!(reparsed, crl);
        // Unknown records don't revoke anything.
        let any_cc = ContentCertificateId([0xFA, 0xBC, 0x11, 0x22, 0x33, 0x44]);
        assert!(!crl.is_content_certificate_id_revoked(any_cc));
    }

    #[test]
    fn malformed_rmrr_part1_without_parts_2_3_preserved_as_unknown() {
        let (priv_key, _pub_key) = synth_la_keys();
        // Build a Revocation Record Set by hand: one RMRR part-1 record
        // followed by a 0x0 Content Certificate ID record (not a valid
        // RMRR-2 continuation).
        let mut record_set = Vec::new();
        record_set.push(RECORD_TYPE_RMRR_PART_1 << 4);
        record_set.extend_from_slice(&[0; 7]);
        record_set.push(RECORD_TYPE_CONTENT_CERTIFICATE_ID << 4);
        record_set.extend_from_slice(&[0; 7]);

        let segment_size = 4u32 + record_set.len() as u32 + SEGMENT_SIGNATURE_LEN as u32;
        let mut crl = ContentRevocationList {
            list_type: LIST_TYPE_FIRST_GEN,
            reserved_nibble: 0,
            list_version: 1,
            number_of_segments: 1,
            segments: vec![CrlSegment {
                segment_size,
                records: parse_revocation_record_set(&record_set).unwrap(),
                signature: [0u8; SEGMENT_SIGNATURE_LEN],
            }],
        };
        let payload = crl.signed_range_for_segment(0).unwrap();
        crl.segments[0].signature = sign(&priv_key, &payload);

        // Should round-trip: orphan RMRR-part-1 surfaces as Unknown, the
        // adjacent CCID record is preserved as a structured CCID.
        let bytes = crl.to_bytes();
        let reparsed = ContentRevocationList::parse(&bytes).unwrap();
        assert_eq!(reparsed, crl);
        assert!(matches!(
            crl.segments[0].records[0],
            RevocationRecord::Unknown {
                record_type: RECORD_TYPE_RMRR_PART_1,
                ..
            }
        ));
        assert!(matches!(
            crl.segments[0].records[1],
            RevocationRecord::ContentCertificateId { .. }
        ));
    }

    #[test]
    fn multi_segment_signatures_use_cumulative_prefix() {
        let (priv_key, pub_key) = synth_la_keys();
        // Two segments. Each has one CCID revocation. Both signatures
        // should verify; the second covers the first's bytes too.
        let records_a = vec![RevocationRecord::ContentCertificateId {
            range: 0,
            id: cc_id(0xA0),
        }];
        let records_b = vec![RevocationRecord::ContentCertificateId {
            range: 0,
            id: cc_id(0xB0),
        }];
        let seg_a_size = 4u32
            + (encode_revocation_record(&records_a[0]).len()) as u32
            + SEGMENT_SIGNATURE_LEN as u32;
        let seg_b_size = 4u32
            + (encode_revocation_record(&records_b[0]).len()) as u32
            + SEGMENT_SIGNATURE_LEN as u32;
        let mut crl = ContentRevocationList {
            list_type: LIST_TYPE_FIRST_GEN,
            reserved_nibble: 0,
            list_version: 0x0023,
            number_of_segments: 2,
            segments: vec![
                CrlSegment {
                    segment_size: seg_a_size,
                    records: records_a,
                    signature: [0u8; SEGMENT_SIGNATURE_LEN],
                },
                CrlSegment {
                    segment_size: seg_b_size,
                    records: records_b,
                    signature: [0u8; SEGMENT_SIGNATURE_LEN],
                },
            ],
        };
        let payload_a = crl.signed_range_for_segment(0).unwrap();
        crl.segments[0].signature = sign(&priv_key, &payload_a);
        let payload_b = crl.signed_range_for_segment(1).unwrap();
        crl.segments[1].signature = sign(&priv_key, &payload_b);

        // Second-segment signed range covers the first segment's bytes
        // including its signature.
        assert!(payload_b.len() > payload_a.len() + SEGMENT_SIGNATURE_LEN);

        let bytes = crl.to_bytes();
        let reparsed = ContentRevocationList::parse(&bytes).unwrap();
        assert_eq!(reparsed, crl);

        crl.verify_all_segments(&pub_key).unwrap();
        crl.verify_last_segment_signature(&pub_key).unwrap();

        // Both records visible to the global query iterator.
        assert!(crl.is_content_certificate_id_revoked(cc_id(0xA0)));
        assert!(crl.is_content_certificate_id_revoked(cc_id(0xB0)));
    }

    #[test]
    fn wrong_public_key_rejects_segment_signature() {
        let (priv_key, _pub_key) = synth_la_keys();
        let imposter = Point::generator().mul_scalar(&small_scalar(0xCAFE_F00D));
        let crl = build_signed_one_segment(
            &priv_key,
            vec![RevocationRecord::ContentCertificateId {
                range: 0,
                id: cc_id(0x77),
            }],
        );
        assert_eq!(
            crl.verify_segment_signature(0, &imposter),
            Err(AacsError::MkbSignatureInvalid)
        );
    }

    #[test]
    fn tampering_a_record_invalidates_segment_signature() {
        let (priv_key, pub_key) = synth_la_keys();
        let mut crl = build_signed_one_segment(
            &priv_key,
            vec![RevocationRecord::ContentCertificateId {
                range: 0,
                id: cc_id(0x88),
            }],
        );
        crl.verify_segment_signature(0, &pub_key).unwrap();
        // Flip one bit of the stored ID — signature now fails.
        if let RevocationRecord::ContentCertificateId { id, .. } = &mut crl.segments[0].records[0] {
            id.0[3] ^= 0x80;
        }
        assert_eq!(
            crl.verify_segment_signature(0, &pub_key),
            Err(AacsError::MkbSignatureInvalid)
        );
    }

    #[test]
    fn invalid_list_type_rejected_via_header_round_trip() {
        // The parser tolerates unknown List Type values (preserved
        // verbatim for forward-compatibility) but verifying anything
        // else still requires Number of Segments ≥ 1.
        let bytes = [
            0x10, 0x00, 0x01, 0x00, // List Type=1, Version=1, Segments=0
        ];
        assert!(matches!(
            ContentRevocationList::parse(&bytes),
            Err(AacsError::InvalidValue { .. })
        ));
    }

    #[test]
    fn segment_size_too_small_rejected() {
        // Header valid, but Segment Size advertises a 4-byte run — not
        // enough for the trailing 40-byte signature.
        let bytes = [
            0x00, 0x00, 0x01, 0x01, // header
            0x00, 0x00, 0x00, 0x04, // Segment Size = 4
        ];
        assert!(matches!(
            ContentRevocationList::parse(&bytes),
            Err(AacsError::InvalidValue { .. })
        ));
    }

    #[test]
    fn first_segment_oversized_rejected() {
        // Build a buffer that declares Segment Size #1 = 128 KiB
        // exactly (above the cap of 128 KiB − 4).
        let mut bytes = Vec::new();
        bytes.push(0x00); // List Type = 0
        bytes.extend_from_slice(&1u16.to_be_bytes()); // List Version
        bytes.push(1); // Number of Segments = 1
        let oversized = 128u32 * 1024;
        bytes.extend_from_slice(&oversized.to_be_bytes());
        // Don't bother padding to that length — the size validation
        // runs before the bounds check.
        assert!(matches!(
            ContentRevocationList::parse(&bytes),
            Err(AacsError::InvalidValue { .. })
        ));
    }

    #[test]
    fn trailing_zero_padding_is_tolerated() {
        let (priv_key, _pub_key) = synth_la_keys();
        let crl = build_signed_one_segment(
            &priv_key,
            vec![RevocationRecord::ContentCertificateId {
                range: 0,
                id: cc_id(0x55),
            }],
        );
        let mut padded = crl.to_bytes();
        padded.extend_from_slice(&[0u8; 17]); // arbitrary 0x00 tail
        let reparsed = ContentRevocationList::parse(&padded).unwrap();
        assert_eq!(reparsed, crl);
    }

    #[test]
    fn trailing_non_zero_garbage_rejected() {
        let (priv_key, _pub_key) = synth_la_keys();
        let crl = build_signed_one_segment(
            &priv_key,
            vec![RevocationRecord::ContentCertificateId {
                range: 0,
                id: cc_id(0x56),
            }],
        );
        let mut padded = crl.to_bytes();
        padded.extend_from_slice(&[0xFF, 0x00, 0x00]);
        assert!(matches!(
            ContentRevocationList::parse(&padded),
            Err(AacsError::InvalidValue { .. })
        ));
    }

    #[test]
    fn rmrr_iccid_bit_round_trip() {
        for iccid in [false, true] {
            let rmrr = RecordableMediaRevocation {
                iccid,
                media_type: RecordableMediaType::HdDvdRecordable,
                content_certificate_id: cc_id(0xCC),
                media_id: [0; 16],
            };
            let bytes = encode_rmrr(&rmrr);
            let decoded = decode_rmrr(
                &bytes[..REVOCATION_RECORD_LEN],
                &bytes[REVOCATION_RECORD_LEN..2 * REVOCATION_RECORD_LEN],
                &bytes[2 * REVOCATION_RECORD_LEN..],
            );
            assert_eq!(decoded.iccid, iccid);
            assert_eq!(decoded, rmrr);
        }
    }

    #[test]
    fn recordable_media_type_round_trip_including_reserved() {
        for v in 0u8..=7 {
            let mt = RecordableMediaType::from_u3(v);
            assert_eq!(mt.to_u3(), v);
        }
    }

    #[test]
    fn signed_range_for_out_of_range_segment_returns_none() {
        let (priv_key, _pub_key) = synth_la_keys();
        let crl = build_signed_one_segment(&priv_key, vec![]);
        assert!(crl.signed_range_for_segment(1).is_none());
        assert!(matches!(
            crl.verify_segment_signature(1, &Point::generator()),
            Err(AacsError::InvalidValue { .. })
        ));
    }

    #[test]
    fn rmrr_media_id_byte_layout_round_trip_full_pattern() {
        let media_id = [
            0x80, 0xAB, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
            0x0D, 0x0E,
        ];
        let rmrr = RecordableMediaRevocation {
            iccid: false,
            media_type: RecordableMediaType::PlusRecordable,
            content_certificate_id: cc_id(0x71),
            media_id,
        };
        let bytes = encode_rmrr(&rmrr);
        let decoded = decode_rmrr(
            &bytes[..REVOCATION_RECORD_LEN],
            &bytes[REVOCATION_RECORD_LEN..2 * REVOCATION_RECORD_LEN],
            &bytes[2 * REVOCATION_RECORD_LEN..],
        );
        assert_eq!(decoded.media_id, media_id);
        assert_eq!(decoded, rmrr);
    }
}
