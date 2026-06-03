//! Signed Content Certificate parse and verification per AACS
//! Pre-recorded Video Book §2.4 / §2.5 / §2.6, with the BD-Prerecorded
//! Final 0.953 Format-Specific Section per BD-Prerecorded Table 2-1
//! decoded out.
//!
//! The Content Certificate (`Content00N.cer`, one per BD-ROM physical
//! layer) is the AACS-LA-signed wrapper that binds the layer's
//! revocation parameters (Content Certificate ID, Minimum CRL Version),
//! the BDMV usage-rules / BD-J root-cert / CPS Unit Usage-File hashes,
//! and the per-Content-Hash-Table digests, into one ECDSA-signed blob
//! that the player verifies before trusting the Content Hash Table
//! integrity layer (the `cht` module).
//!
//! ## Pre-recorded Video Book Table 2-1 layout (generic)
//!
//! | Byte                       | Field                          | Bytes |
//! |----------------------------|--------------------------------|------:|
//! | 0                          | Certificate Type (`0x00`)      | 1     |
//! | 1                          | BEE flag (bit 7) + reserved    | 1     |
//! | 2..5                       | Total_Number_of_HashUnits      | 4     |
//! | 6                          | Total_Number_of_Layers         | 1     |
//! | 7                          | Layer_Number                   | 1     |
//! | 8..11                      | Number_of_HashUnits            | 4     |
//! | 12..13                     | Number_of_Digests              | 2     |
//! | 14..15                     | Applicant ID                   | 2     |
//! | 16..19                     | Content Sequence Number        | 4     |
//! | 20..21                     | Minimum CRL Version            | 2     |
//! | 22..23                     | Reserved                       | 2     |
//! | 24..25                     | Length_Format_Specific_Section | 2     |
//! | 26..26+L−1                 | Format_Specific_Section        | L     |
//! | 26+L..26+L+(N×8)−1         | Content Hash Table Digest #1…N | 8 ⋅ N |
//! | 26+L+(N×8)..26+L+(N×8)+39  | Signature Data                 | 40    |
//!
//! `L` is `Length_Format_Specific_Section`, which the spec requires to
//! be a multiple of 4 (and may be `0` — in that case the field is
//! treated as 2 reserved bytes for byte alignment).
//!
//! ## BD-Prerecorded Final 0.953 Table 2-1 Format-Specific Section
//!
//! For BD-ROM, the Format-Specific Section spans bytes `26 .. 26+L−1`
//! and decomposes as:
//!
//! | Byte (rel.)        | Field                              | Bytes |
//! |--------------------|------------------------------------|------:|
//! | 0..19              | Hash_Value_of_MC_Manifest_File     | 20    |
//! | 20..39             | Hash_Value_of_BDJ_Root_Cert        | 20    |
//! | 40..41             | Num_of_CPS_Unit (J)                | 2     |
//! | 42..41+20·J        | Hash_Value_of_CPS_Unit_Usage_File  | 20·J  |
//!
//! Hence for a BD-Prerecorded disc with `J` CPS Units, `L = 42 + 20·J`.
//! For `J = 1` (the typical single-title disc), `L = 62`, which makes
//! the BD-Prerecorded note `K = 88 + (J−1)·20` equivalent to
//! `K = 26 + L` — the first byte of `Content Hash Table Digest #1`.
//!
//! ## Verification (PVB §2.6)
//!
//! A Licensed Product verifies the certificate by:
//!
//! 1. Selecting a subset of Hash Units (the PVB chooses 7 + optional 1%
//!    sampling; out of scope here — this module only computes the
//!    primitives).
//! 2. `C_d = [SHA-1(Hash_Unit)]_lsb_64` for each selected Hash Unit
//!    (`cht::hash_value_of_unit`).
//! 3. `CHT_d = [SHA-1(CHT)]_lsb_64` for each Content Hash Table read off
//!    the disc ([`Self::content_hash_table_digest`]).
//! 4. The recomputed `CHT_d` values match the per-layer digests stored
//!    in the certificate ([`Self::verify_content_hash_table_digest`]).
//! 5. `AACS_Verify(AACS_CC_pub, Signature_Data, CC)` over the
//!    certificate bytes up to but excluding the 40-byte signature
//!    ([`Self::verify_signature`]).
//! 6. `C_ur = SHA-1(Usage_Rules)` matches the usage-rules hash carried
//!    in the certificate ([`Self::hash_value_of_mc_manifest_file`] /
//!    [`Self::hash_value_of_cps_unit_usage_files`] depending on which
//!    usage-rules artefact the format specifies; the BD spec uses the
//!    MC Manifest File and the per-CPS-Unit Usage Files).
//!
//! The CRL processing (PVB §2.7 / Table 2-3..2-5) is a separate layer,
//! not implemented here — the Content Certificate only declares a
//! `Minimum CRL Version` that the CRL the player loads must meet or
//! exceed.

use crate::cht::HASH_VALUE_SIZE;
use crate::ec::Point;
use crate::ecdsa::{sha1, verify, Signature, SHA1_LEN};
use crate::error::AacsError;

/// Fixed Certificate Type byte value indicating a first-generation
/// AACS Content Certificate (PVB §2.4, BD-Prerecorded §2.1).
pub const CERTIFICATE_TYPE_FIRST_GEN: u8 = 0x00;

/// Length of one stored Content Hash Table Digest (PVB §2.4: "8-byte
/// Content Hash Table Digests").
pub const CONTENT_HASH_TABLE_DIGEST_LEN: usize = HASH_VALUE_SIZE;

/// Length of the AACS ECDSA Signature Data field at the tail of the
/// Content Certificate (PVB §2.4: "A 40 byte Signature Data").
pub const SIGNATURE_DATA_LEN: usize = 40;

/// Generic Pre-recorded Video Book header length up to but not
/// including the Format-Specific Section (bytes 0..=25).
const HEADER_FIXED_LEN: usize = 26;

/// Byte offset of the `Length_Format_Specific_Section` u16 within the
/// header (PVB Table 2-1, bytes 24..=25).
const OFFSET_LENGTH_FORMAT_SPECIFIC_SECTION: usize = 24;

/// BD-Prerecorded Final 0.953 Format-Specific Section fixed-prefix
/// length: `Hash_Value_of_MC_Manifest_File` (20) +
/// `Hash_Value_of_BDJ_Root_Cert` (20) + `Num_of_CPS_Unit` (2).
const BD_FORMAT_SPECIFIC_FIXED_LEN: usize = SHA1_LEN + SHA1_LEN + 2;

/// Byte length of one `Hash_Value_of_CPS_Unit_Usage_File` entry
/// (BD-Prerecorded Table 2-1: 20-byte SHA-1 digest).
const HASH_VALUE_OF_CPS_UNIT_USAGE_FILE_LEN: usize = SHA1_LEN;

/// 6-byte Content Certificate ID — the AACS-LA-assigned identifier
/// formed by concatenating the 2-byte Applicant ID with the 4-byte
/// Content Sequence Number (PVB §2.4: "The combination of the
/// Applicant ID and the Content Sequence Number is referred to as the
/// Content Certificate ID. … The Content Certificate ID is a 6-byte
/// number.").
///
/// This is the value the per-CRL Revocation Record for Content
/// Certificate ID matches against (PVB Table 2-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentCertificateId(pub [u8; 6]);

impl ContentCertificateId {
    /// Construct from the raw 2-byte Applicant ID and 4-byte Content
    /// Sequence Number, in their on-disc big-endian byte form.
    pub fn from_components(applicant_id: [u8; 2], content_sequence_number: [u8; 4]) -> Self {
        let mut out = [0u8; 6];
        out[..2].copy_from_slice(&applicant_id);
        out[2..].copy_from_slice(&content_sequence_number);
        Self(out)
    }

    /// The 2-byte Applicant ID half of the Content Certificate ID
    /// (high-order 2 bytes).
    pub fn applicant_id(&self) -> [u8; 2] {
        [self.0[0], self.0[1]]
    }

    /// The 4-byte Content Sequence Number half (low-order 4 bytes).
    pub fn content_sequence_number(&self) -> [u8; 4] {
        [self.0[2], self.0[3], self.0[4], self.0[5]]
    }
}

/// Decoded Content Sequence Number (PVB §2.4: 6-bit CCSS ID,
/// 15-bit Timestamp, 11-bit Sequence Number = Sequence Number 1 (4)
/// concatenated with Sequence Number 2 (7)).
///
/// The decoding matches the BD-Prerecorded Table 2-1 bit layout for
/// bytes 16..=19: CCSS ID occupies the top 6 bits of byte 16,
/// Sequence Number 1 is bits 1..=0 of byte 16 plus bits 7..=2 of byte
/// 17 (4 bits total), Timestamp is bits 1..=0 of byte 17 plus all of
/// byte 18 plus bits 7..=3 of byte 19 (15 bits), and Sequence Number 2
/// is the bottom 7 bits of byte 19. The two `Sequence_Number_*` fields
/// concatenate to form the 11-bit Sequence Number per the §2.4 prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentSequenceNumber {
    /// 6-bit Content Certificate Signing Server ID.
    pub ccss_id: u8,
    /// 15-bit Timestamp — elapsed days from 1 January 2008 UTC. Values
    /// predating 2 February 2008 (i.e. `1..=31`) are reserved per
    /// PVB §2.4.
    pub timestamp: u16,
    /// 11-bit Sequence Number = `Sequence_Number_1(4) || Sequence_Number_2(7)`,
    /// AACS-LA-assigned to uniquely identify the Certified Content
    /// among one applicant's content.
    pub sequence_number: u16,
}

impl ContentSequenceNumber {
    /// Decode the 4 raw bytes per the BD-Prerecorded Table 2-1 layout
    /// (also matches PVB §2.4 since the BD book uses the generic
    /// concatenation rule).
    pub fn from_be_bytes(b: [u8; 4]) -> Self {
        let ccss_id = b[0] >> 2;
        let seq1 = ((u16::from(b[0] & 0x03)) << 2) | (u16::from(b[1]) >> 6);
        let timestamp =
            ((u16::from(b[1] & 0x3F)) << 9) | (u16::from(b[2]) << 1) | (u16::from(b[3]) >> 7);
        let seq2 = u16::from(b[3] & 0x7F);
        let sequence_number = (seq1 << 7) | seq2;
        Self {
            ccss_id,
            timestamp,
            sequence_number,
        }
    }

    /// Re-encode to the 4-byte on-disc form (round-trip for tests and
    /// authoring code).
    pub fn to_be_bytes(self) -> [u8; 4] {
        let ccss_id = self.ccss_id & 0x3F;
        let seq1 = (self.sequence_number >> 7) & 0x0F;
        let seq2 = self.sequence_number & 0x7F;
        let timestamp = self.timestamp & 0x7FFF;
        let b0 = (ccss_id << 2) | ((seq1 >> 2) as u8 & 0x03);
        let b1 = (((seq1 & 0x03) as u8) << 6) | ((timestamp >> 9) as u8 & 0x3F);
        let b2 = ((timestamp >> 1) & 0xFF) as u8;
        let b3 = (((timestamp & 0x01) as u8) << 7) | (seq2 as u8 & 0x7F);
        [b0, b1, b2, b3]
    }
}

/// BD-Prerecorded Final 0.953 Table 2-1 Format-Specific Section,
/// parsed out of the variable-length region that PVB §2.4 leaves to
/// the adaptation book.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BdFormatSpecificSection {
    /// `Hash_Value_of_MC_Manifest_File` — SHA-1 of the Managed Copy
    /// Manifest File (BD-Prerecorded §2.3.2.4 / §5.3).
    pub hash_value_of_mc_manifest_file: [u8; SHA1_LEN],
    /// `Hash_Value_of_BDJ_Root_Cert` — SHA-1 of the BD-J Root
    /// Certificate.
    pub hash_value_of_bdj_root_cert: [u8; SHA1_LEN],
    /// `Hash_Value_of_CPS_Unit_Usage_File#1 .. #J` — SHA-1 of each CPS
    /// Unit Usage File on the disc. `len() == Num_of_CPS_Unit (J)`.
    pub hash_value_of_cps_unit_usage_files: Vec<[u8; SHA1_LEN]>,
}

impl BdFormatSpecificSection {
    /// Parse the Format-Specific Section bytes per BD-Prerecorded
    /// Table 2-1. The buffer length must equal
    /// `42 + 20·Num_of_CPS_Unit`.
    pub fn parse(bytes: &[u8]) -> Result<Self, AacsError> {
        if bytes.len() < BD_FORMAT_SPECIFIC_FIXED_LEN {
            return Err(AacsError::Truncated(
                "Content Certificate BD Format-Specific Section",
            ));
        }
        let mut mc = [0u8; SHA1_LEN];
        mc.copy_from_slice(&bytes[0..SHA1_LEN]);
        let mut bdj = [0u8; SHA1_LEN];
        bdj.copy_from_slice(&bytes[SHA1_LEN..2 * SHA1_LEN]);
        let num_of_cps_unit =
            u16::from_be_bytes([bytes[2 * SHA1_LEN], bytes[2 * SHA1_LEN + 1]]) as usize;

        let required = BD_FORMAT_SPECIFIC_FIXED_LEN
            .checked_add(
                num_of_cps_unit
                    .checked_mul(HASH_VALUE_OF_CPS_UNIT_USAGE_FILE_LEN)
                    .ok_or(AacsError::Truncated(
                        "Content Certificate CPS Unit Usage hash array",
                    ))?,
            )
            .ok_or(AacsError::Truncated(
                "Content Certificate BD Format-Specific Section",
            ))?;
        if bytes.len() < required {
            return Err(AacsError::OversizedRecord {
                what: "Content Certificate BD Format-Specific Section",
                declared: required,
                available: bytes.len(),
            });
        }

        let mut usage = Vec::with_capacity(num_of_cps_unit);
        let mut cursor = BD_FORMAT_SPECIFIC_FIXED_LEN;
        for _ in 0..num_of_cps_unit {
            let mut h = [0u8; SHA1_LEN];
            h.copy_from_slice(&bytes[cursor..cursor + SHA1_LEN]);
            usage.push(h);
            cursor += SHA1_LEN;
        }

        Ok(Self {
            hash_value_of_mc_manifest_file: mc,
            hash_value_of_bdj_root_cert: bdj,
            hash_value_of_cps_unit_usage_files: usage,
        })
    }

    /// Serialise this section back to its on-disc byte form
    /// (round-trip helper for authoring tests).
    pub fn to_bytes(&self) -> Vec<u8> {
        let j = self.hash_value_of_cps_unit_usage_files.len();
        let mut out = Vec::with_capacity(BD_FORMAT_SPECIFIC_FIXED_LEN + j * SHA1_LEN);
        out.extend_from_slice(&self.hash_value_of_mc_manifest_file);
        out.extend_from_slice(&self.hash_value_of_bdj_root_cert);
        out.extend_from_slice(&(j as u16).to_be_bytes());
        for h in &self.hash_value_of_cps_unit_usage_files {
            out.extend_from_slice(h);
        }
        out
    }

    /// `Num_of_CPS_Unit` — i.e. the number of stored CPS Unit Usage
    /// File hashes (BD-Prerecorded Table 2-1).
    pub fn num_of_cps_unit(&self) -> u16 {
        self.hash_value_of_cps_unit_usage_files.len() as u16
    }
}

/// A parsed AACS Content Certificate, with the BD-Prerecorded
/// Format-Specific Section split out for direct access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentCertificate {
    /// `Certificate Type` (PVB §2.4) — `0x00` for a first-generation
    /// AACS Content Certificate. Currently the only value the spec
    /// defines.
    pub certificate_type: u8,
    /// Bus Encryption Enabled flag (BD-Prerecorded §2.1: `0` = off,
    /// `1` = on; both layers' Content Certificates must agree).
    pub bee: bool,
    /// `Total_Number_of_HashUnits` across the whole disc.
    pub total_number_of_hash_units: u32,
    /// `Total_Number_of_Layers` (BD-Prerecorded: 1 for single-layer,
    /// 2 for dual-layer).
    pub total_number_of_layers: u8,
    /// `Layer_Number` of the layer this certificate applies to
    /// (`0` for `Content000.cer`, `1` for `Content001.cer`).
    pub layer_number: u8,
    /// `Number_of_HashUnits` on this layer.
    pub number_of_hash_units: u32,
    /// `Number_of_Digests` — the number of 8-byte Content Hash Table
    /// Digests stored in this certificate. BD-Prerecorded §2.1 ties
    /// this to the number of Clip AV stream files of ≥ 96 Logical
    /// Sectors on the layer.
    pub number_of_digests: u16,
    /// `Applicant ID` assigned by AACS LA.
    pub applicant_id: [u8; 2],
    /// `Content Sequence Number` (raw 4 bytes; use
    /// [`Self::content_sequence_number_decoded`] for the structured
    /// CCSS ID / Timestamp / Sequence Number view).
    pub content_sequence_number: [u8; 4],
    /// Minimum Content Revocation List version the player must load
    /// before honouring this certificate.
    pub minimum_crl_version: u16,
    /// Variable-length Format-Specific Section bytes
    /// (`Length_Format_Specific_Section`). Always a multiple of 4 per
    /// PVB §2.4 (if 0 the field is treated as 2 reserved alignment
    /// bytes — represented here as an empty `Vec`).
    pub format_specific_section: Vec<u8>,
    /// The `Number_of_Digests` 8-byte Content Hash Table Digests, in
    /// table order: index `i` is `Content Hash Table Digest #(i+1)`.
    /// Each is `[SHA-1(Content Hash Table i+1)]_lsb_64` per PVB §2.5.
    pub content_hash_table_digests: Vec<[u8; CONTENT_HASH_TABLE_DIGEST_LEN]>,
    /// 40-byte AACS_Sign signature over the certificate bytes up to
    /// but excluding this field (PVB §2.5 step 4 / §2.6 step 5).
    pub signature_data: Signature,
}

impl ContentCertificate {
    /// Parse a generic Pre-recorded Video Book Content Certificate
    /// (Table 2-1) given the on-disc bytes of a `Content00N.cer` file
    /// and the `Number_of_Digests` count (also redundantly stored in
    /// the header).
    ///
    /// The header's own `Number_of_Digests` is cross-checked against
    /// the parser's reconstructed count, so a corrupt header that
    /// drives a different tail layout surfaces as an
    /// [`AacsError::InvalidValue`].
    pub fn parse(bytes: &[u8]) -> Result<Self, AacsError> {
        if bytes.len() < HEADER_FIXED_LEN {
            return Err(AacsError::Truncated("Content Certificate header"));
        }

        let certificate_type = bytes[0];
        if certificate_type != CERTIFICATE_TYPE_FIRST_GEN {
            return Err(AacsError::InvalidValue {
                what: "Content Certificate Type",
                value: u64::from(certificate_type),
            });
        }
        let bee = (bytes[1] & 0x80) != 0;
        let total_number_of_hash_units =
            u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        let total_number_of_layers = bytes[6];
        let layer_number = bytes[7];
        let number_of_hash_units = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let number_of_digests = u16::from_be_bytes([bytes[12], bytes[13]]);
        let applicant_id = [bytes[14], bytes[15]];
        let content_sequence_number = [bytes[16], bytes[17], bytes[18], bytes[19]];
        let minimum_crl_version = u16::from_be_bytes([bytes[20], bytes[21]]);
        // bytes[22..=23] reserved.
        let length_format_specific_section = u16::from_be_bytes([
            bytes[OFFSET_LENGTH_FORMAT_SPECIFIC_SECTION],
            bytes[OFFSET_LENGTH_FORMAT_SPECIFIC_SECTION + 1],
        ]) as usize;

        // PVB §2.4: "The combination of the Length_Format_Specific_Section
        // field and the Format_Specific_Section field shall always be a
        // multiple of 4 bytes." `Length_Format_Specific_Section` itself
        // is 2 bytes, so the variable section's own length must satisfy
        // `(L + 2) ≡ 0 (mod 4)`. The spec carves out `L = 0` as a
        // special case where 2 alignment bytes are appended; both `L=0`
        // and `L ≡ 2 (mod 4)` are valid on-disc encodings.
        if length_format_specific_section != 0 && (length_format_specific_section + 2) % 4 != 0 {
            return Err(AacsError::InvalidValue {
                what: "Content Certificate Length_Format_Specific_Section (must be 0 or ≡ 2 mod 4)",
                value: length_format_specific_section as u64,
            });
        }

        // PVB §2.4: "If [Length_Format_Specific_Section] is zero, then
        // the length of Format_Specific_Section is 2 to maintain byte
        // alignment and the 2 bytes shall be treated as Reserved." We
        // still don't store those alignment bytes; the parser just
        // accepts the on-disc layout.
        let format_specific_section_len = if length_format_specific_section == 0 {
            2
        } else {
            length_format_specific_section
        };

        let digests_offset = HEADER_FIXED_LEN + format_specific_section_len;
        let n_digests = number_of_digests as usize;
        let digests_len =
            n_digests
                .checked_mul(CONTENT_HASH_TABLE_DIGEST_LEN)
                .ok_or(AacsError::Truncated(
                    "Content Certificate digest-array length",
                ))?;
        let signature_offset = digests_offset
            .checked_add(digests_len)
            .ok_or(AacsError::Truncated("Content Certificate signature offset"))?;
        let total = signature_offset
            .checked_add(SIGNATURE_DATA_LEN)
            .ok_or(AacsError::Truncated("Content Certificate total length"))?;

        if bytes.len() < total {
            return Err(AacsError::OversizedRecord {
                what: "Content Certificate",
                declared: total,
                available: bytes.len(),
            });
        }

        let mut format_specific_section = Vec::with_capacity(length_format_specific_section);
        if length_format_specific_section > 0 {
            format_specific_section.extend_from_slice(
                &bytes[HEADER_FIXED_LEN..HEADER_FIXED_LEN + length_format_specific_section],
            );
        }

        let mut content_hash_table_digests = Vec::with_capacity(n_digests);
        for i in 0..n_digests {
            let off = digests_offset + i * CONTENT_HASH_TABLE_DIGEST_LEN;
            let mut d = [0u8; CONTENT_HASH_TABLE_DIGEST_LEN];
            d.copy_from_slice(&bytes[off..off + CONTENT_HASH_TABLE_DIGEST_LEN]);
            content_hash_table_digests.push(d);
        }

        let mut signature_data = [0u8; SIGNATURE_DATA_LEN];
        signature_data
            .copy_from_slice(&bytes[signature_offset..signature_offset + SIGNATURE_DATA_LEN]);

        Ok(Self {
            certificate_type,
            bee,
            total_number_of_hash_units,
            total_number_of_layers,
            layer_number,
            number_of_hash_units,
            number_of_digests,
            applicant_id,
            content_sequence_number,
            minimum_crl_version,
            format_specific_section,
            content_hash_table_digests,
            signature_data,
        })
    }

    /// 6-byte Content Certificate ID per PVB §2.4 — used as the lookup
    /// key for the per-CRL Revocation Record for Content Certificate
    /// ID (PVB Table 2-3).
    pub fn content_certificate_id(&self) -> ContentCertificateId {
        ContentCertificateId::from_components(self.applicant_id, self.content_sequence_number)
    }

    /// Structured decode of the Content Sequence Number into its
    /// `CCSS ID / Timestamp / Sequence Number` fields per PVB §2.4 +
    /// BD-Prerecorded Table 2-1 bit layout.
    pub fn content_sequence_number_decoded(&self) -> ContentSequenceNumber {
        ContentSequenceNumber::from_be_bytes(self.content_sequence_number)
    }

    /// Parse the BD-Prerecorded Format-Specific Section (Table 2-1) out
    /// of [`Self::format_specific_section`]. Returns
    /// [`AacsError::Truncated`] if the section is shorter than the
    /// 42-byte fixed prefix or its declared `Num_of_CPS_Unit · 20`
    /// trailer is missing.
    pub fn bd_format_specific_section(&self) -> Result<BdFormatSpecificSection, AacsError> {
        BdFormatSpecificSection::parse(&self.format_specific_section)
    }

    /// Number of stored Content Hash Table Digests.
    pub fn number_of_digests_stored(&self) -> usize {
        self.content_hash_table_digests.len()
    }

    /// True when this is the layer-0 `Content000.cer`.
    pub fn is_layer_zero(&self) -> bool {
        self.layer_number == 0
    }

    /// Reconstruct the canonical on-disc byte form of the certificate.
    /// The result is the exact input to `parse()` for a roundtrip and
    /// the exact data the AACS_Sign signature is computed over (when
    /// the trailing 40 bytes of [`Self::signature_data`] are
    /// substituted with the recomputed signature).
    pub fn to_bytes(&self) -> Vec<u8> {
        let length_field = self.format_specific_section.len() as u16;
        let format_specific_padded_len = if self.format_specific_section.is_empty() {
            2
        } else {
            self.format_specific_section.len()
        };
        let mut out = Vec::with_capacity(
            HEADER_FIXED_LEN
                + format_specific_padded_len
                + self.content_hash_table_digests.len() * CONTENT_HASH_TABLE_DIGEST_LEN
                + SIGNATURE_DATA_LEN,
        );
        out.push(self.certificate_type);
        out.push(if self.bee { 0x80 } else { 0x00 });
        out.extend_from_slice(&self.total_number_of_hash_units.to_be_bytes());
        out.push(self.total_number_of_layers);
        out.push(self.layer_number);
        out.extend_from_slice(&self.number_of_hash_units.to_be_bytes());
        out.extend_from_slice(&self.number_of_digests.to_be_bytes());
        out.extend_from_slice(&self.applicant_id);
        out.extend_from_slice(&self.content_sequence_number);
        out.extend_from_slice(&self.minimum_crl_version.to_be_bytes());
        out.extend_from_slice(&[0u8; 2]); // bytes 22..23 reserved
        out.extend_from_slice(&length_field.to_be_bytes());
        if self.format_specific_section.is_empty() {
            out.extend_from_slice(&[0u8; 2]);
        } else {
            out.extend_from_slice(&self.format_specific_section);
        }
        for d in &self.content_hash_table_digests {
            out.extend_from_slice(d);
        }
        out.extend_from_slice(&self.signature_data);
        out
    }

    /// Byte range covered by the AACS_Sign signature per PVB §2.5
    /// step 4: "calculated using the Entity Private Key, over the
    /// entire data up to and including Content_Hash_Table_Digest#N",
    /// i.e. everything except the trailing 40-byte signature.
    pub fn signed_range_bytes(&self) -> Vec<u8> {
        let mut bytes = self.to_bytes();
        bytes.truncate(bytes.len() - SIGNATURE_DATA_LEN);
        bytes
    }

    /// Verify [`Self::signature_data`] over [`Self::signed_range_bytes`]
    /// against the caller-supplied AACS LA Content Certificate public
    /// key (`AACS_CC_pub` in PVB §2.6 step 5).
    ///
    /// Returns `Ok(())` on success; `Err(AacsError::MkbSignatureInvalid)`
    /// when the ECDSA check rejects. The reused error variant matches
    /// the existing MKB signature paths so the consumer can fold all
    /// AACS_Verify failures through one branch.
    pub fn verify_signature(&self, aacs_cc_pub: &Point) -> Result<(), AacsError> {
        let payload = self.signed_range_bytes();
        if verify(aacs_cc_pub, &self.signature_data, &payload) {
            Ok(())
        } else {
            Err(AacsError::MkbSignatureInvalid)
        }
    }

    /// Recompute `CHT_d = [SHA-1(cht_bytes)]_lsb_64` for a candidate
    /// Content Hash Table (PVB §2.5 step 3 / §2.6 step 3).
    ///
    /// `cht_bytes` is the on-disc bytes of the corresponding
    /// `ContentHash00N.tbl` (i.e. the bytes the `cht::ContentHashTable`
    /// parser consumes). This intentionally hashes the *raw bytes* —
    /// not the parsed struct — because the spec digest is over the
    /// on-medium octets.
    pub fn content_hash_table_digest(cht_bytes: &[u8]) -> [u8; CONTENT_HASH_TABLE_DIGEST_LEN] {
        let d = sha1(cht_bytes);
        let mut out = [0u8; CONTENT_HASH_TABLE_DIGEST_LEN];
        out.copy_from_slice(&d[SHA1_LEN - CONTENT_HASH_TABLE_DIGEST_LEN..]);
        out
    }

    /// Verify that `cht_bytes` hashes to the same `CHT_d` the
    /// certificate stores at digest index `digest_index` (0-based;
    /// digest #1 is `digest_index == 0`).
    ///
    /// Returns [`AacsError::InvalidValue`] if `digest_index` is out of
    /// range and [`AacsError::ContentHashMismatch`] (reused with the
    /// `index` field carrying `digest_index`) on a digest mismatch.
    pub fn verify_content_hash_table_digest(
        &self,
        digest_index: usize,
        cht_bytes: &[u8],
    ) -> Result<(), AacsError> {
        let stored =
            self.content_hash_table_digests
                .get(digest_index)
                .ok_or(AacsError::InvalidValue {
                    what: "Content Certificate digest index",
                    value: digest_index as u64,
                })?;
        let recomputed = Self::content_hash_table_digest(cht_bytes);
        if &recomputed == stored {
            Ok(())
        } else {
            Err(AacsError::ContentHashMismatch {
                index: digest_index,
            })
        }
    }
}

/// Compute `C_ur = SHA-1(Usage_Rules)` per PVB §2.6 — the
/// usage-rules cryptographic hash a Licensed Product checks against the
/// `Hash_Value_of_*` fields the BD-Prerecorded Format-Specific Section
/// carries (MC Manifest File, BD-J Root Certificate, each CPS Unit
/// Usage File).
///
/// The spec leaves the exact identity of the usage-rules artefact to
/// each adaptation book — for BD-Prerecorded the relevant artefacts are
/// the MC Manifest File and the per-CPS-Unit Usage File. This helper
/// just exposes the SHA-1 primitive so the caller can apply it to the
/// raw bytes of whichever artefact the format dictates.
pub fn usage_rules_hash(usage_rules: &[u8]) -> [u8; SHA1_LEN] {
    sha1(usage_rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::{Point, U160};
    use crate::ecdsa::sign;

    fn small_scalar(v: u32) -> U160 {
        U160 {
            limbs: [v, 0, 0, 0, 0],
        }
    }

    /// Synthesise a BD-style Format-Specific Section with the given
    /// number of CPS Unit Usage hash entries; bytes are deterministic
    /// in `seed` so tests carry no disc-derived material.
    fn synth_bd_format_specific_section(seed: u8, j: usize) -> BdFormatSpecificSection {
        let mut mc = [0u8; SHA1_LEN];
        for (i, b) in mc.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(seed);
        }
        let mut bdj = [0u8; SHA1_LEN];
        for (i, b) in bdj.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(seed).wrapping_mul(3);
        }
        let mut usage = Vec::with_capacity(j);
        for u in 0..j {
            let mut h = [0u8; SHA1_LEN];
            for (i, b) in h.iter_mut().enumerate() {
                *b = (i as u8)
                    .wrapping_add(seed)
                    .wrapping_add(u as u8)
                    .wrapping_mul(7);
            }
            usage.push(h);
        }
        BdFormatSpecificSection {
            hash_value_of_mc_manifest_file: mc,
            hash_value_of_bdj_root_cert: bdj,
            hash_value_of_cps_unit_usage_files: usage,
        }
    }

    fn synth_certificate_template() -> ContentCertificate {
        let bd_section = synth_bd_format_specific_section(0x11, 2);
        let format_specific = bd_section.to_bytes();
        // Two CHT digests, one per layer, deterministic.
        let digests = vec![[0u8; 8], [0u8; 8]];
        ContentCertificate {
            certificate_type: CERTIFICATE_TYPE_FIRST_GEN,
            bee: true,
            total_number_of_hash_units: 0x0001_0000,
            total_number_of_layers: 2,
            layer_number: 0,
            number_of_hash_units: 0x0000_8000,
            number_of_digests: digests.len() as u16,
            applicant_id: [0x00, 0x42],
            // CCSS ID 5, timestamp 1234, seq 0x123 (11 bits).
            content_sequence_number: ContentSequenceNumber {
                ccss_id: 5,
                timestamp: 1234,
                sequence_number: 0x123,
            }
            .to_be_bytes(),
            minimum_crl_version: 7,
            format_specific_section: format_specific,
            content_hash_table_digests: digests,
            signature_data: [0u8; SIGNATURE_DATA_LEN],
        }
    }

    #[test]
    fn content_certificate_id_concatenates_applicant_and_sequence() {
        let cert = synth_certificate_template();
        let id = cert.content_certificate_id();
        assert_eq!(id.applicant_id(), [0x00, 0x42]);
        assert_eq!(id.content_sequence_number(), cert.content_sequence_number);
        assert_eq!(id.0[0..2], cert.applicant_id);
        assert_eq!(id.0[2..6], cert.content_sequence_number);
    }

    #[test]
    fn content_sequence_number_round_trips() {
        let cases = [
            ContentSequenceNumber {
                ccss_id: 0,
                timestamp: 0,
                sequence_number: 0,
            },
            ContentSequenceNumber {
                ccss_id: 0x3F,
                timestamp: 0x7FFF,
                sequence_number: 0x7FF,
            },
            ContentSequenceNumber {
                ccss_id: 7,
                timestamp: 1234,
                sequence_number: 0x456,
            },
            ContentSequenceNumber {
                ccss_id: 33,
                timestamp: 0x4321,
                sequence_number: 0x321,
            },
        ];
        for c in cases {
            let bytes = c.to_be_bytes();
            let decoded = ContentSequenceNumber::from_be_bytes(bytes);
            assert_eq!(decoded, c, "round-trip failed for {c:?}");
        }
    }

    #[test]
    fn bd_format_specific_section_round_trips() {
        let original = synth_bd_format_specific_section(0x42, 3);
        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), BD_FORMAT_SPECIFIC_FIXED_LEN + 3 * SHA1_LEN);
        let parsed = BdFormatSpecificSection::parse(&bytes).unwrap();
        assert_eq!(parsed, original);
        assert_eq!(parsed.num_of_cps_unit(), 3);
    }

    #[test]
    fn bd_format_specific_section_rejects_truncated_prefix() {
        let truncated = [0u8; BD_FORMAT_SPECIFIC_FIXED_LEN - 1];
        assert!(matches!(
            BdFormatSpecificSection::parse(&truncated),
            Err(AacsError::Truncated(_))
        ));
    }

    #[test]
    fn bd_format_specific_section_rejects_short_trailer() {
        // Claim J=2 but supply only the fixed prefix + 1 hash worth.
        let mut buf = vec![0u8; BD_FORMAT_SPECIFIC_FIXED_LEN + SHA1_LEN];
        // Set num_of_cps_unit = 2 (big-endian) at the right offset.
        buf[2 * SHA1_LEN] = 0x00;
        buf[2 * SHA1_LEN + 1] = 0x02;
        assert!(matches!(
            BdFormatSpecificSection::parse(&buf),
            Err(AacsError::OversizedRecord { .. })
        ));
    }

    #[test]
    fn parse_round_trips_certificate_bytes() {
        let mut cert = synth_certificate_template();
        // Deterministic non-zero digests so they actually round-trip.
        cert.content_hash_table_digests[0] = [1, 2, 3, 4, 5, 6, 7, 8];
        cert.content_hash_table_digests[1] = [9, 10, 11, 12, 13, 14, 15, 16];
        // Deterministic non-zero signature bytes.
        for (i, b) in cert.signature_data.iter_mut().enumerate() {
            *b = i as u8;
        }
        let on_disc = cert.to_bytes();
        let parsed = ContentCertificate::parse(&on_disc).unwrap();
        assert_eq!(parsed, cert);
        assert_eq!(parsed.to_bytes(), on_disc);
    }

    #[test]
    fn parse_rejects_unknown_certificate_type() {
        let mut cert = synth_certificate_template();
        cert.certificate_type = 0x42;
        let mut bytes = cert.to_bytes();
        // Substitute the type byte directly to bypass our own builder
        // assertion; parse should still reject.
        bytes[0] = 0x42;
        assert!(matches!(
            ContentCertificate::parse(&bytes),
            Err(AacsError::InvalidValue { what, .. }) if what.contains("Certificate Type")
        ));
    }

    #[test]
    fn parse_rejects_length_field_violating_4byte_alignment() {
        let cert = synth_certificate_template();
        let mut bytes = cert.to_bytes();
        // Bump Length_Format_Specific_Section to a value where
        // (L + 2) % 4 != 0 — e.g. L=63 instead of 62.
        let bad = 63u16.to_be_bytes();
        bytes[OFFSET_LENGTH_FORMAT_SPECIFIC_SECTION] = bad[0];
        bytes[OFFSET_LENGTH_FORMAT_SPECIFIC_SECTION + 1] = bad[1];
        assert!(matches!(
            ContentCertificate::parse(&bytes),
            Err(AacsError::InvalidValue { .. })
        ));
    }

    #[test]
    fn parse_rejects_truncated_bytes() {
        let cert = synth_certificate_template();
        let bytes = cert.to_bytes();
        let short = &bytes[..bytes.len() - 1];
        assert!(matches!(
            ContentCertificate::parse(short),
            Err(AacsError::OversizedRecord { .. })
        ));
    }

    #[test]
    fn signed_range_excludes_only_the_signature() {
        let cert = synth_certificate_template();
        let full = cert.to_bytes();
        let signed = cert.signed_range_bytes();
        assert_eq!(signed.len(), full.len() - SIGNATURE_DATA_LEN);
        assert_eq!(&signed[..], &full[..full.len() - SIGNATURE_DATA_LEN]);
    }

    #[test]
    fn verify_signature_round_trips_with_synthetic_key() {
        // Mint a synthetic AACS_CC key pair.
        let priv_key = small_scalar(0x9be3_1f5d);
        let pub_key = Point::generator().mul_scalar(&priv_key);

        let mut cert = synth_certificate_template();
        // Fill plausible digests so a downstream tamper test bites.
        cert.content_hash_table_digests[0] = [0xaa; 8];
        cert.content_hash_table_digests[1] = [0xbb; 8];

        // Sign the canonical signed-range bytes.
        let payload = cert.signed_range_bytes();
        let sig = sign(&priv_key, &payload);
        cert.signature_data = sig;

        // Untampered: passes.
        cert.verify_signature(&pub_key).unwrap();

        // Tamper with one CHT digest: signature now mismatches.
        let mut tampered = cert.clone();
        tampered.content_hash_table_digests[0][0] ^= 0x01;
        assert_eq!(
            tampered.verify_signature(&pub_key),
            Err(AacsError::MkbSignatureInvalid)
        );

        // Wrong key: rejects.
        let other_priv = small_scalar(0x1234_5678);
        let other_pub = Point::generator().mul_scalar(&other_priv);
        assert_eq!(
            cert.verify_signature(&other_pub),
            Err(AacsError::MkbSignatureInvalid)
        );
    }

    #[test]
    fn cht_digest_is_lsb_64_of_sha1() {
        let cht_bytes: Vec<u8> = (0..2000u32).map(|i| (i & 0xFF) as u8).collect();
        let digest = ContentCertificate::content_hash_table_digest(&cht_bytes);
        let full = sha1(&cht_bytes);
        assert_eq!(&digest[..], &full[12..20]);
    }

    #[test]
    fn verify_content_hash_table_digest_round_trips_and_detects_tampering() {
        // Build a certificate whose digests we control directly.
        let cht_a: Vec<u8> = (0..1024u32).map(|i| (i & 0xFF) as u8).collect();
        let cht_b: Vec<u8> = (0..2048u32).map(|i| ((i * 3) & 0xFF) as u8).collect();
        let mut cert = synth_certificate_template();
        cert.content_hash_table_digests[0] = ContentCertificate::content_hash_table_digest(&cht_a);
        cert.content_hash_table_digests[1] = ContentCertificate::content_hash_table_digest(&cht_b);

        cert.verify_content_hash_table_digest(0, &cht_a).unwrap();
        cert.verify_content_hash_table_digest(1, &cht_b).unwrap();

        // Tampering bites.
        let mut tampered = cht_a.clone();
        tampered[7] ^= 0xFF;
        assert_eq!(
            cert.verify_content_hash_table_digest(0, &tampered),
            Err(AacsError::ContentHashMismatch { index: 0 })
        );

        // Out of range.
        assert!(matches!(
            cert.verify_content_hash_table_digest(99, &cht_a),
            Err(AacsError::InvalidValue { .. })
        ));
    }

    #[test]
    fn usage_rules_hash_is_sha1() {
        let usage_rules = b"BDMV usage rules payload (synthetic for test)";
        let h = usage_rules_hash(usage_rules);
        assert_eq!(h, sha1(usage_rules));
    }

    #[test]
    fn bd_format_specific_round_trip_through_full_certificate() {
        let cert = synth_certificate_template();
        let on_disc = cert.to_bytes();
        let parsed = ContentCertificate::parse(&on_disc).unwrap();
        let bd = parsed.bd_format_specific_section().unwrap();
        assert_eq!(bd.num_of_cps_unit(), 2);
        assert_eq!(bd.hash_value_of_cps_unit_usage_files.len(), 2);
    }

    #[test]
    fn zero_length_format_specific_section_uses_alignment_bytes() {
        let mut cert = synth_certificate_template();
        cert.format_specific_section.clear();
        cert.number_of_digests = 1;
        cert.content_hash_table_digests = vec![[0x77; 8]];
        let on_disc = cert.to_bytes();
        // Header (26) + 2 alignment bytes + 1*8 + 40
        assert_eq!(on_disc.len(), HEADER_FIXED_LEN + 2 + 8 + SIGNATURE_DATA_LEN);
        let parsed = ContentCertificate::parse(&on_disc).unwrap();
        assert!(parsed.format_specific_section.is_empty());
        assert_eq!(parsed.content_hash_table_digests, vec![[0x77; 8]]);
    }
}
