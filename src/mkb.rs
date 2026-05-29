//! Media Key Block parser per Common spec §3.2.5.
//!
//! An MKB is a contiguous stream of records. Each record begins with
//! a 1-byte type tag and a 3-byte big-endian length field (which
//! *includes* the 4 bytes of header). The whole MKB is always a
//! multiple of 4 bytes per spec §3.2.5.
//!
//! ```text
//! +-----+-------------+--------------------+
//! | tag | length (BE) | record payload ... |
//! | 1B  | 3B          | (length - 4) bytes |
//! +-----+-------------+--------------------+
//! ```
//!
//! Per the spec ("if a device encounters a Record with a Record Type
//! field value it does not recognize, that is not an error; it shall
//! ignore that Record and skip to the next"), this parser silently
//! preserves unknown records in a side-vector so a caller can still
//! observe the entire byte-stream.

use crate::aes::aes_128_ecb_decrypt;
use crate::ec::Point;
use crate::ecdsa::{verify as ecdsa_verify, Signature as EcdsaSignature};
use crate::error::AacsError;

/// MKB Type tag per Common spec §3.2.5.1.1 Table 3-2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MkbType {
    /// `00031003` — Type 3, a normal AACS Recordable Media MKB.
    /// Used to directly calculate the Media Key.
    Type3,
    /// `00041003` — Type 4, a Pre-recorded Media MKB that uses Key
    /// Conversion Data.
    Type4,
    /// `000A1003` — Type 10, a Class II / Unified MKB.
    Type10,
    /// Some other unrecognised type tag — carried through as the raw
    /// 32-bit value for diagnostics.
    Other(u32),
}

impl MkbType {
    fn from_u32(v: u32) -> Self {
        match v {
            0x0003_1003 => Self::Type3,
            0x0004_1003 => Self::Type4,
            0x000A_1003 => Self::Type10,
            other => Self::Other(other),
        }
    }

    /// Raw 32-bit `MKBType` value as it appears on the wire (Common
    /// spec §3.2.5.1.1, Table 3-2).
    pub fn as_u32(self) -> u32 {
        match self {
            Self::Type3 => 0x0003_1003,
            Self::Type4 => 0x0004_1003,
            Self::Type10 => 0x000A_1003,
            Self::Other(v) => v,
        }
    }

    /// `true` for the Type-4 MKB whose subset-difference walk yields
    /// a Media Key *Precursor* `K_mp` rather than the final Media Key
    /// `K_m`. Devices that are required to use Key Conversion Data
    /// must then apply [`crate::subdiff::apply_key_conversion_data`]
    /// to recover `K_m`. Common spec §3.2.5.1.1 + §3.2.5.1.4.
    pub fn requires_kcd(self) -> bool {
        matches!(self, Self::Type4)
    }
}

/// One entry in a Host or Drive Revocation List (Common spec
/// §3.2.5.1.2 Table 3-4): 2-byte range + 6-byte ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationEntry {
    /// Number of additional IDs that follow `id` in the revoked range.
    /// `range == 0` means only `id` is revoked.
    pub range: u16,
    /// First (or only) revoked Host or Drive ID.
    pub id: [u8; 6],
}

/// One signature block of a Host or Drive Revocation List Record per
/// Common spec §3.2.5.1.2 / §3.2.5.1.3.
///
/// Each block stores the entries that contribute to its signature plus
/// the raw 40-byte ECDSA signature itself. The signed range, per
/// §3.2.5.1.2, is "the entire Type and Version Record, and also the
/// data in the [HRL/DRL] Record beginning with the Record Type byte and
/// ending with the byte immediately preceding the signature" —
/// cumulatively for each block, so block N covers blocks 1..=N.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationSignatureBlock {
    /// Number of entries in this signature block as declared by the
    /// `Number of Entries in this Signature Block` field (Common spec
    /// §3.2.5.1.2 Table 3-3 / §3.2.5.1.3 Table 3-5).
    pub entries_in_block: u32,
    /// Entries that contribute to this signature block (newly added in
    /// this block, not cumulative).
    pub entries: Vec<RevocationEntry>,
    /// 40-byte ECDSA signature on the cumulative signed-data prefix
    /// (Type-and-Version record bytes || HRL/DRL record bytes up to the
    /// byte immediately preceding this signature). `None` if the record
    /// was truncated before the signature field. Spec §3.2.5.1.2 final
    /// paragraph notes a host is not required to keep the signature
    /// itself for blocks beyond the first; a `None` entry here records
    /// that condition without making it a parse error.
    pub signature: Option<EcdsaSignature>,
}

/// One entry in the Explicit Subset-Difference Record (Common spec
/// §3.2.5.1.5 Table 3-7): 1-byte u-mask + 4-byte uv.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubsetDifferenceEntry {
    /// Number of low-order zero bits in `m_u`.
    pub u_mask_zero_bits: u8,
    /// The 32-bit `uv` number (big-endian on the wire).
    pub uv: u32,
}

/// A parsed Media Key Block.
#[derive(Debug, Clone, Default)]
pub struct Mkb {
    /// Type tag from the mandatory leading Type-and-Version Record
    /// (record type `0x10`).
    pub mkb_type: Option<MkbType>,
    /// Monotonically-increasing MKB version, from the same record.
    pub version: u32,
    /// Parsed Host Revocation List entries (record type `0x21`).
    /// Empty if no HRL is present. Cumulative across all signature
    /// blocks; per-block detail (including signatures) is in
    /// [`host_revocation_blocks`].
    pub host_revocation_list: Vec<RevocationEntry>,
    /// Parsed Host Revocation List signature blocks per Common spec
    /// §3.2.5.1.2 Table 3-3 — one entry per signature block, each
    /// carrying the entries added in that block plus the 40-byte
    /// ECDSA signature over the cumulative signed-data prefix.
    pub host_revocation_blocks: Vec<RevocationSignatureBlock>,
    /// Parsed Drive Revocation List entries (record type `0x20`).
    pub drive_revocation_list: Vec<RevocationEntry>,
    /// Parsed Drive Revocation List signature blocks per Common spec
    /// §3.2.5.1.3 Table 3-5 — same shape as
    /// [`host_revocation_blocks`].
    pub drive_revocation_blocks: Vec<RevocationSignatureBlock>,
    /// The 16-byte ciphertext `V_d` from the Verify Media Key Record
    /// (record type `0x81`), if present.
    pub verify_media_key: Option<[u8; 16]>,
    /// Explicit Subset-Difference Record entries (type `0x04`).
    pub explicit_subdiff: Vec<SubsetDifferenceEntry>,
    /// Subset-Difference Index Record `span` and 3-byte offsets
    /// (type `0x07`), if present.
    pub subdiff_index: Option<SubsetDiffIndex>,
    /// Media Key Data Record entries (type `0x05`), 16 bytes each,
    /// one-for-one with [`explicit_subdiff`].
    pub media_key_data: Vec<[u8; 16]>,
    /// Media Key Variant Data Record entries (type `0x0C`), 16 bytes
    /// each — only present in Type-10 MKBs.
    pub media_key_variant_data: Vec<[u8; 16]>,
    /// Variant Number Record (type `0x0D`) raw payload — Class II
    /// MKB only.
    pub variant_number_record: Option<VariantNumberRecord>,
    /// `true` if the End-of-MKB Record (type `0x02`) was encountered.
    pub end_of_block: bool,
    /// Raw payload of the End-of-MKB Record (type `0x02`) per Common
    /// spec §3.2.5.1.8: the AACS LA ECDSA signature over the MKB
    /// bytes up to but not including this record. `None` when no
    /// End-of-MKB record was present, or when the payload was not the
    /// expected 40 bytes (in which case the record was still treated
    /// as End-of-MKB for backwards-compatible parsing).
    pub end_of_block_signature: Option<EcdsaSignature>,
    /// Raw bytes of the Type-and-Version Record (type `0x10`), header
    /// included, captured during parsing. Needed by
    /// [`Self::verify_host_revocation_list`] /
    /// [`Self::verify_drive_revocation_list`] because those signatures
    /// cover the Type-and-Version record verbatim per §3.2.5.1.2
    /// "The signature for each signature block covers the entire Type
    /// and Version Record, and also the data in the [HRL/DRL] Record".
    pub type_and_version_raw: Vec<u8>,
    /// Any records the parser didn't recognise, recorded as
    /// `(type, full_record_bytes)` for diagnostics.
    pub unknown_records: Vec<(u8, Vec<u8>)>,
}

/// Subset-Difference Index Record (Common spec §3.2.5.1.6 Table 3-8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubsetDiffIndex {
    /// "span" field: number of devices per index offset.
    pub span: u32,
    /// 3-byte offsets (big-endian on the wire); each is a byte offset
    /// into the Explicit Subset-Difference Record.
    pub offsets: Vec<u32>,
}

/// Variant Number Record (Common spec §3.2.5.2.2 Table 3-12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariantNumberRecord {
    /// 16-byte nonce.
    pub nonce: [u8; 16],
    /// Tightly-packed 10-bit variant-number entries (raw bytes,
    /// caller decodes per spec).
    pub variant_number_data: Vec<u8>,
}

impl Mkb {
    /// Parse an MKB byte stream per Common spec §3.2.5. Records are
    /// processed in order; unknown record types are preserved in
    /// [`unknown_records`].
    pub fn parse(bytes: &[u8]) -> Result<Self, AacsError> {
        let mut out = Mkb::default();
        let mut saw_type_record_first = false;
        let mut first_record = true;
        let mut cursor = 0usize;

        while cursor < bytes.len() {
            let remaining = &bytes[cursor..];
            if remaining.len() < 4 {
                // Trailing 1-3 bytes after the last record — treat as
                // sector-padding zero-fill, not a parse error.
                break;
            }
            let tag = remaining[0];
            let length =
                (u32::from_be_bytes([0, remaining[1], remaining[2], remaining[3]])) as usize;
            if length < 4 {
                // A zero-length record header is how real MKB files
                // signal end-of-stream when the MKB itself is shorter
                // than the on-disc file (sector-aligned tail padding).
                // If we've already seen the End-of-MKB record (tag
                // 0x02) just stop quietly. Otherwise also stop, but
                // only as long as the rest of the buffer is all-zero
                // padding — anything else is malformed.
                if out.end_of_block || remaining.iter().all(|&b| b == 0) {
                    break;
                }
                return Err(AacsError::InvalidValue {
                    what: "MKB record length",
                    value: length as u64,
                });
            }
            if length > remaining.len() {
                return Err(AacsError::OversizedRecord {
                    what: "MKB",
                    declared: length,
                    available: remaining.len(),
                });
            }
            let payload = &remaining[4..length];
            let advance = length;

            if first_record {
                if tag == 0x10 {
                    saw_type_record_first = true;
                }
                first_record = false;
            }

            match tag {
                0x10 => {
                    parse_type_and_version(payload, &mut out)?;
                    out.type_and_version_raw.clear();
                    out.type_and_version_raw
                        .extend_from_slice(&remaining[..length]);
                }
                0x21 => {
                    let (entries, blocks) = parse_revocation_list_with_blocks(payload)?;
                    out.host_revocation_list = entries;
                    out.host_revocation_blocks = blocks;
                }
                0x20 => {
                    let (entries, blocks) = parse_revocation_list_with_blocks(payload)?;
                    out.drive_revocation_list = entries;
                    out.drive_revocation_blocks = blocks;
                }
                0x81 => out.verify_media_key = Some(parse_verify_media_key(payload)?),
                0x04 => out.explicit_subdiff = parse_explicit_subdiff(payload)?,
                0x07 => out.subdiff_index = Some(parse_subdiff_index(payload)?),
                0x05 => out.media_key_data = parse_media_key_data(payload)?,
                0x0C => out.media_key_variant_data = parse_media_key_data(payload)?,
                0x0D => out.variant_number_record = Some(parse_variant_number(payload)?),
                0x02 => {
                    // End of Media Key Block Record — payload is the
                    // AACS LA's ECDSA signature over the MKB bytes up
                    // to but not including this record (Common spec
                    // §3.2.5.1.8). We preserve the raw 40-byte
                    // signature so a caller with the AACS LA public
                    // key can run `verify_end_of_block_signature`.
                    out.end_of_block = true;
                    if payload.len() == 40 {
                        let mut sig = [0u8; 40];
                        sig.copy_from_slice(&payload[..40]);
                        out.end_of_block_signature = Some(sig);
                    } else {
                        // Spec mandates a 40-byte ECDSA signature, but
                        // older / partial MKBs (and some fixture
                        // tooling) emit a placeholder of a different
                        // length. We accept the record so the parser
                        // stays backwards-compatible; signature
                        // verification will then return a
                        // "missing-signature" error rather than a
                        // crypto-failure.
                        out.end_of_block_signature = None;
                    }
                }
                other => {
                    let mut blob = Vec::with_capacity(length);
                    blob.extend_from_slice(&remaining[..length]);
                    out.unknown_records.push((other, blob));
                }
            }

            cursor += advance;
        }

        if !saw_type_record_first {
            return Err(AacsError::MissingTypeAndVersionRecord);
        }
        Ok(out)
    }

    /// Verify a candidate Media Key against the MKB's Verify Media Key
    /// Record per Common spec §3.2.5.1.4:
    ///
    /// `[AES-128D(K_m, V_d)]_msb_64 == 0x0123_4567_89AB_CDEF`.
    pub fn verify_media_key(&self, km: &[u8; 16]) -> Result<(), AacsError> {
        let vd = self
            .verify_media_key
            .ok_or(AacsError::MissingVerifyMediaKeyRecord)?;
        let plaintext = aes_128_ecb_decrypt(km, &vd);
        if plaintext[..8] == VERIFY_MEDIA_KEY_SENTINEL {
            Ok(())
        } else {
            Err(AacsError::MediaKeyVerificationFailed)
        }
    }

    /// Boolean variant of [`Self::verify_media_key`]: returns `true`
    /// when the candidate `km` passes the Verify Media Key Record
    /// check, `false` when it doesn't, and `false` when the record is
    /// absent. Use this rather than [`Self::verify_media_key`] when
    /// the caller is expected to consult the result and branch (e.g.
    /// the Type-4 "verify-precursor-or-apply-KCD" path described in
    /// Common spec §3.2.5.1.4 final paragraph), since the latter
    /// surfaces `MissingVerifyMediaKeyRecord` for an MKB without a
    /// `0x81` record — which a Type-4 decision path would need to
    /// treat differently from a wrong-key match-failure.
    pub fn is_verified_media_key(&self, km: &[u8; 16]) -> bool {
        let Some(vd) = self.verify_media_key else {
            return false;
        };
        let plaintext = aes_128_ecb_decrypt(km, &vd);
        plaintext[..8] == VERIFY_MEDIA_KEY_SENTINEL
    }

    /// Verify the End-of-Media-Key-Block Record signature per Common
    /// spec §3.2.5.1.8.
    ///
    /// The spec defines this as
    /// `AACS_Verify(AACS_LApub, Signature Data, MKB)` where `MKB` is
    /// the byte range "up to, but not including" the End-of-MKB
    /// record. Callers must therefore pass the original byte buffer
    /// the [`Mkb`] was parsed from (so the verifier can locate the
    /// signed prefix); `original_bytes` must be the exact slice
    /// originally given to [`Self::parse`].
    ///
    /// Returns `Err(AacsError::MkbSignatureMissing)` when no
    /// End-of-MKB record was present or its payload was not a 40-byte
    /// ECDSA signature; `Err(AacsError::MkbSignatureInvalid)` when
    /// the signature does not verify against `aacs_la_pub`. AACS LA
    /// distributes `AACS_LApub` to licensees only — the caller is
    /// responsible for supplying it; this crate ships no embedded
    /// public key.
    pub fn verify_end_of_block_signature(
        &self,
        original_bytes: &[u8],
        aacs_la_pub: &Point,
    ) -> Result<(), AacsError> {
        let signature = self
            .end_of_block_signature
            .as_ref()
            .ok_or(AacsError::MkbSignatureMissing)?;
        let signed_len = find_end_of_block_signed_prefix_len(original_bytes)?;
        let signed_data = &original_bytes[..signed_len];
        if ecdsa_verify(aacs_la_pub, signature, signed_data) {
            Ok(())
        } else {
            Err(AacsError::MkbSignatureInvalid)
        }
    }

    /// Verify the AACS LA signatures on the Host Revocation List
    /// Record per Common spec §3.2.5.1.2.
    ///
    /// The spec defines this as
    /// `AACS_Verify(AACS_LApub, Signature Data,
    ///   Type and Version || Host Revocation List)` per signature
    /// block, where each block's signature covers
    /// `Type-and-Version-Record || HRL-Record-bytes` up to the byte
    /// immediately preceding the signature. The cumulative shape
    /// follows the Table 3-3 layout: block N covers the bytes that
    /// blocks `1..=N` contribute together with their preceding
    /// `Number of Entries` fields.
    ///
    /// Verifies every signature block whose `signature` is present
    /// and returns success iff each verifies. A revocation record
    /// with no signature blocks ([`Self::host_revocation_blocks`]
    /// empty) returns `Err(AacsError::MkbSignatureMissing)`.
    pub fn verify_host_revocation_list(
        &self,
        original_bytes: &[u8],
        aacs_la_pub: &Point,
    ) -> Result<(), AacsError> {
        self.verify_revocation_list_signatures(
            original_bytes,
            aacs_la_pub,
            0x21,
            &self.host_revocation_blocks,
        )
    }

    /// Verify the AACS LA signatures on the Drive Revocation List
    /// Record per Common spec §3.2.5.1.3.
    ///
    /// Same shape and rules as
    /// [`Self::verify_host_revocation_list`], applied to the Drive
    /// Revocation List Record (tag `0x20`).
    pub fn verify_drive_revocation_list(
        &self,
        original_bytes: &[u8],
        aacs_la_pub: &Point,
    ) -> Result<(), AacsError> {
        self.verify_revocation_list_signatures(
            original_bytes,
            aacs_la_pub,
            0x20,
            &self.drive_revocation_blocks,
        )
    }

    fn verify_revocation_list_signatures(
        &self,
        original_bytes: &[u8],
        aacs_la_pub: &Point,
        record_tag: u8,
        blocks: &[RevocationSignatureBlock],
    ) -> Result<(), AacsError> {
        if blocks.is_empty() {
            return Err(AacsError::MkbSignatureMissing);
        }
        if self.type_and_version_raw.is_empty() {
            // The parser should always have populated this — keep the
            // defensive branch so a hand-constructed `Mkb` doesn't
            // panic.
            return Err(AacsError::MkbSignatureMissing);
        }

        let (rl_record_start, rl_record_len) =
            find_record_extent(original_bytes, record_tag).ok_or(AacsError::MkbSignatureMissing)?;
        let rl_record = &original_bytes[rl_record_start..rl_record_start + rl_record_len];
        let mut verified_any = false;

        // Locate each signature inside the RL record. Each block layout
        // (Common spec §3.2.5.1.2 Table 3-3) is:
        //   [4-byte Number of Entries in this Signature Block]
        //   [N * 8-byte entries]
        //   [40-byte Signature]
        // Block N's signature covers everything from the start of the
        // Type-and-Version Record through the byte immediately
        // preceding that block's signature (i.e. cumulative).
        //
        // The first block additionally has a 4-byte Total-Number-of-
        // Entries header at offset 4 of the record payload; that
        // header is part of the signed data per the table.
        let payload = &rl_record[4..]; // skip record header (tag + length)
        if payload.len() < 4 {
            return Err(AacsError::Truncated("Revocation List signed payload"));
        }
        let mut cursor = 4usize; // skip the Total-Number-of-Entries field
        for block in blocks {
            // Each block has its own Number-of-Entries-in-this-Block
            // 4-byte header followed by entries + signature.
            if cursor + 4 > payload.len() {
                return Err(AacsError::Truncated(
                    "Revocation List per-block entry count",
                ));
            }
            cursor += 4;
            let n = block.entries_in_block as usize;
            let entries_bytes = n.checked_mul(8).ok_or(AacsError::InvalidValue {
                what: "Revocation List block entry count",
                value: block.entries_in_block as u64,
            })?;
            if cursor + entries_bytes > payload.len() {
                return Err(AacsError::Truncated("Revocation List block entries"));
            }
            cursor += entries_bytes;
            let signed_prefix_end_in_record = 4 + cursor; // includes record header
            if let Some(sig) = block.signature.as_ref() {
                // Signed data = Type-and-Version Record || HRL/DRL
                // record bytes up to but not including the signature.
                let mut signed_data = Vec::with_capacity(
                    self.type_and_version_raw.len() + signed_prefix_end_in_record,
                );
                signed_data.extend_from_slice(&self.type_and_version_raw);
                signed_data.extend_from_slice(&rl_record[..signed_prefix_end_in_record]);
                if !ecdsa_verify(aacs_la_pub, sig, &signed_data) {
                    return Err(AacsError::MkbSignatureInvalid);
                }
                verified_any = true;
            }
            // Whether or not the block carried a signature, advance
            // past the 40-byte signature slot for the next block.
            if cursor + 40 > payload.len() {
                // Spec §3.2.5.1.2 final paragraph: hosts may store
                // only the data being signed for the first block. A
                // truncated trailing signature is therefore not a hard
                // parse error — stop the cursor walk.
                break;
            }
            cursor += 40;
        }
        if verified_any {
            Ok(())
        } else {
            Err(AacsError::MkbSignatureMissing)
        }
    }
}

/// Find the byte length of the prefix the End-of-MKB signature covers
/// per Common spec §3.2.5.1.8 — "the data in the Media Key Block up
/// to, but not including, this record". Returns the offset of the
/// End-of-MKB record's first byte; equivalently, the signed-prefix
/// length.
fn find_end_of_block_signed_prefix_len(original_bytes: &[u8]) -> Result<usize, AacsError> {
    let mut cursor = 0usize;
    while cursor + 4 <= original_bytes.len() {
        let tag = original_bytes[cursor];
        let length = (u32::from_be_bytes([
            0,
            original_bytes[cursor + 1],
            original_bytes[cursor + 2],
            original_bytes[cursor + 3],
        ])) as usize;
        if length < 4 || cursor + length > original_bytes.len() {
            break;
        }
        if tag == 0x02 {
            return Ok(cursor);
        }
        cursor += length;
    }
    Err(AacsError::MkbSignatureMissing)
}

/// Find the `[start, length)` extent of the first record carrying the
/// given tag in the original MKB byte buffer. Used by the per-block
/// revocation-list signature verifier to recover the on-wire bytes
/// (which include the record header) that participate in the signed
/// data.
fn find_record_extent(original_bytes: &[u8], tag: u8) -> Option<(usize, usize)> {
    let mut cursor = 0usize;
    while cursor + 4 <= original_bytes.len() {
        let cur_tag = original_bytes[cursor];
        let length = (u32::from_be_bytes([
            0,
            original_bytes[cursor + 1],
            original_bytes[cursor + 2],
            original_bytes[cursor + 3],
        ])) as usize;
        if length < 4 || cursor + length > original_bytes.len() {
            return None;
        }
        if cur_tag == tag {
            return Some((cursor, length));
        }
        cursor += length;
    }
    None
}

/// Common spec §3.2.5.1.4 Verify Media Key sentinel — the high-order
/// 64 bits of `AES-128D(K_m, V_d)` must equal this constant for the
/// device to accept `K_m` as the correct Media Key.
const VERIFY_MEDIA_KEY_SENTINEL: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];

fn parse_type_and_version(payload: &[u8], out: &mut Mkb) -> Result<(), AacsError> {
    // Payload (record length - 4 bytes header):
    //   MKBType   (4 bytes BE)
    //   Version   (4 bytes BE)
    if payload.len() < 8 {
        return Err(AacsError::Truncated("Type-and-Version Record"));
    }
    let mkb_type = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let version = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    out.mkb_type = Some(MkbType::from_u32(mkb_type));
    out.version = version;
    Ok(())
}

fn parse_revocation_list_with_blocks(
    payload: &[u8],
) -> Result<(Vec<RevocationEntry>, Vec<RevocationSignatureBlock>), AacsError> {
    // Payload (record length - 4 bytes header) layout per Common spec
    // §3.2.5.1.2 / §3.2.5.1.3:
    //   Total Number of Entries          (4 bytes BE)
    //   for each signature block:
    //     Number of Entries in Block (N) (4 bytes BE)
    //     N * 8-byte Revocation Entry    (Range 2B + ID 6B)
    //     40-byte Signature
    //
    // We collect both the flat entry list (for backwards compatibility
    // with callers using [`Mkb::host_revocation_list`] /
    // [`Mkb::drive_revocation_list`]) and the per-block view (with the
    // signature bytes preserved for AACS_Verify).
    if payload.len() < 4 {
        return Err(AacsError::Truncated("Revocation List header"));
    }
    let _total = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let mut cursor = 4;
    let mut entries = Vec::new();
    let mut blocks: Vec<RevocationSignatureBlock> = Vec::new();
    while cursor < payload.len() {
        if cursor + 4 > payload.len() {
            return Err(AacsError::Truncated("Revocation List block header"));
        }
        let n_u32 = u32::from_be_bytes([
            payload[cursor],
            payload[cursor + 1],
            payload[cursor + 2],
            payload[cursor + 3],
        ]);
        let n = n_u32 as usize;
        cursor += 4;
        if cursor + n * 8 > payload.len() {
            return Err(AacsError::Truncated("Revocation List entries"));
        }
        let mut block_entries = Vec::with_capacity(n);
        for _ in 0..n {
            let range = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]);
            let mut id = [0u8; 6];
            id.copy_from_slice(&payload[cursor + 2..cursor + 8]);
            let entry = RevocationEntry { range, id };
            entries.push(entry);
            block_entries.push(entry);
            cursor += 8;
        }
        // Signature is 40 bytes per spec §3.2.5.1.2 (`AACS_Verify`
        // ECDSA over the P-160-equivalent curve from §2.3 → 40-byte
        // signature). Tolerate truncation since some MKBs may store
        // only the data being signed and not the signature itself per
        // spec (last paragraph of §3.2.5.1.2).
        let signature = if cursor + 40 <= payload.len() {
            let mut sig = [0u8; 40];
            sig.copy_from_slice(&payload[cursor..cursor + 40]);
            cursor += 40;
            Some(sig)
        } else {
            cursor = payload.len();
            None
        };
        blocks.push(RevocationSignatureBlock {
            entries_in_block: n_u32,
            entries: block_entries,
            signature,
        });
    }
    Ok((entries, blocks))
}

fn parse_verify_media_key(payload: &[u8]) -> Result<[u8; 16], AacsError> {
    if payload.len() < 16 {
        return Err(AacsError::Truncated("Verify Media Key Record"));
    }
    let mut vd = [0u8; 16];
    vd.copy_from_slice(&payload[..16]);
    Ok(vd)
}

fn parse_explicit_subdiff(payload: &[u8]) -> Result<Vec<SubsetDifferenceEntry>, AacsError> {
    // 5 bytes per entry: 1-byte u-mask + 4-byte uv (big-endian). The
    // record length is always a multiple of 4 bytes, so there may be
    // trailing padding the parser stops on by detecting a u-mask byte
    // with the spec's "00xx xxxx" form check OR simply by running out
    // of 5-byte slots before the length boundary.
    let mut entries = Vec::with_capacity(payload.len() / 5);
    let mut i = 0;
    while i + 5 <= payload.len() {
        // Spec §3.2.5.1.5: "If a device encounters a u mask value
        // whose high-order two bits are non-zero, without finding an
        // applicable subset, it may conclude it is revoked." We
        // interpret high-order-two-bits-non-zero as the end-of-list
        // sentinel for padding purposes, so 0x00..0x3F are valid u_mask
        // counts and >= 0x40 marks the end.
        if (payload[i] & 0xC0) != 0 {
            break;
        }
        let u_mask = payload[i];
        let uv = u32::from_be_bytes([
            payload[i + 1],
            payload[i + 2],
            payload[i + 3],
            payload[i + 4],
        ]);
        entries.push(SubsetDifferenceEntry {
            u_mask_zero_bits: u_mask,
            uv,
        });
        i += 5;
    }
    Ok(entries)
}

fn parse_subdiff_index(payload: &[u8]) -> Result<SubsetDiffIndex, AacsError> {
    // 4-byte span + 3-byte offsets (Common spec §3.2.5.1.6 Table 3-8).
    if payload.len() < 4 {
        return Err(AacsError::Truncated("Subset-Difference Index Record"));
    }
    let span = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let mut offsets = Vec::with_capacity((payload.len() - 4) / 3);
    let mut i = 4;
    while i + 3 <= payload.len() {
        let off = u32::from_be_bytes([0, payload[i], payload[i + 1], payload[i + 2]]);
        offsets.push(off);
        i += 3;
    }
    Ok(SubsetDiffIndex { span, offsets })
}

fn parse_media_key_data(payload: &[u8]) -> Result<Vec<[u8; 16]>, AacsError> {
    let mut entries = Vec::with_capacity(payload.len() / 16);
    let mut i = 0;
    while i + 16 <= payload.len() {
        let mut e = [0u8; 16];
        e.copy_from_slice(&payload[i..i + 16]);
        entries.push(e);
        i += 16;
    }
    Ok(entries)
}

fn parse_variant_number(payload: &[u8]) -> Result<VariantNumberRecord, AacsError> {
    if payload.len() < 16 {
        return Err(AacsError::Truncated("Variant Number Record"));
    }
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&payload[..16]);
    let mut variant_number_data = Vec::with_capacity(payload.len() - 16);
    variant_number_data.extend_from_slice(&payload[16..]);
    Ok(VariantNumberRecord {
        nonce,
        variant_number_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_record(tag: u8, body: &[u8]) -> Vec<u8> {
        let length = 4 + body.len();
        assert!(length <= 0xFF_FFFF);
        let mut out = vec![
            tag,
            ((length >> 16) & 0xFF) as u8,
            ((length >> 8) & 0xFF) as u8,
            (length & 0xFF) as u8,
        ];
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn parses_minimal_type3_mkb() {
        // Type-3 MKB: Type/Version + Verify Media Key + End-of-MKB.
        let mut bytes = Vec::new();
        // Type-and-Version: MKBType=0x00031003, Version=1
        let mut tv = Vec::new();
        tv.extend_from_slice(&0x0003_1003u32.to_be_bytes());
        tv.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend(write_record(0x10, &tv));
        // Verify Media Key: 16 bytes of dummy V_d
        bytes.extend(write_record(0x81, &[0x42u8; 16]));
        // End of MKB: 40 bytes of dummy signature
        bytes.extend(write_record(0x02, &[0u8; 40]));

        let mkb = Mkb::parse(&bytes).unwrap();
        assert_eq!(mkb.mkb_type, Some(MkbType::Type3));
        assert_eq!(mkb.version, 1);
        assert!(mkb.verify_media_key.is_some());
        assert!(mkb.end_of_block);
    }

    #[test]
    fn rejects_missing_type_record() {
        // Start with a Verify Media Key record, no Type-and-Version
        // first.
        let bytes = write_record(0x81, &[0u8; 16]);
        assert!(matches!(
            Mkb::parse(&bytes),
            Err(AacsError::MissingTypeAndVersionRecord)
        ));
    }

    #[test]
    fn truncated_header_silently_stops_then_missing_type_record_fires() {
        // 3 bytes; not enough for a header. Per the "tolerate
        // sector-aligned tail padding" rule, the parser stops
        // quietly and surfaces the (more useful) missing-type-record
        // error on the way out.
        let bytes = vec![0x10, 0x00, 0x00];
        assert!(matches!(
            Mkb::parse(&bytes),
            Err(AacsError::MissingTypeAndVersionRecord)
        ));
    }

    /// Real-world MKB files are sector-padded with trailing zeros
    /// after the End-of-MKB record (tag 0x02). The parser must
    /// accept that padding rather than rejecting it as a record
    /// with length=0.
    #[test]
    fn accepts_zero_padding_after_end_of_block() {
        let mut bytes = Vec::new();
        // Type+Version record (tag=0x10, minimal payload).
        bytes.extend_from_slice(&[0x10, 0x00, 0x00, 0x0C]); // length 12 = header + 8-byte payload
        bytes.extend_from_slice(&[0; 8]); // padding payload (mkb_type, version_number)
                                          // End-of-MKB record (tag=0x02, length 4 = header only).
        bytes.extend_from_slice(&[0x02, 0x00, 0x00, 0x04]);
        // Sector-aligned trailing zeros.
        bytes.extend_from_slice(&[0; 32]);
        let mkb = Mkb::parse(&bytes).expect("zero-padding tail must be accepted");
        assert!(mkb.end_of_block);
    }

    #[test]
    fn rejects_oversized_length() {
        let bytes = vec![0x10, 0x00, 0xFF, 0x00, 0x00]; // declares 0xFF00 bytes
        assert!(matches!(
            Mkb::parse(&bytes),
            Err(AacsError::OversizedRecord { .. })
        ));
    }

    /// Type-3 MKBs do NOT require KCD; Type-4 does. Pinning this so a
    /// refactor of the `requires_kcd` predicate can't drift silently.
    #[test]
    fn mkb_type_requires_kcd_only_for_type4() {
        assert!(!MkbType::Type3.requires_kcd());
        assert!(MkbType::Type4.requires_kcd());
        assert!(!MkbType::Type10.requires_kcd());
        assert!(!MkbType::Other(0x0099_1003).requires_kcd());
    }

    /// `MkbType::as_u32` is the inverse of the parser's `from_u32`.
    #[test]
    fn mkb_type_roundtrips_as_u32() {
        for t in [
            MkbType::Type3,
            MkbType::Type4,
            MkbType::Type10,
            MkbType::Other(0x0099_1003),
        ] {
            assert_eq!(MkbType::from_u32(t.as_u32()), t);
        }
    }

    /// `is_verified_media_key` mirrors `verify_media_key` but returns
    /// `false` instead of `MissingVerifyMediaKeyRecord` when there's
    /// no `0x81` record, so a Type-4 decision path can branch on it
    /// without erroring.
    #[test]
    fn is_verified_media_key_false_when_no_record() {
        let mkb = Mkb::default();
        assert!(!mkb.is_verified_media_key(&[0u8; 16]));
    }

    #[test]
    fn is_verified_media_key_true_for_matching_key() {
        // Build a synthetic Vd = AES-128E(km, sentinel || trailing) and
        // pin that is_verified_media_key(&km) is true and
        // is_verified_media_key(&wrong) is false.
        use crate::aes::aes_128_ecb_encrypt;
        let km = [0x42u8; 16];
        let mut plaintext = [0u8; 16];
        plaintext[..8].copy_from_slice(&VERIFY_MEDIA_KEY_SENTINEL);
        let vd = aes_128_ecb_encrypt(&km, &plaintext);

        let mkb = Mkb {
            verify_media_key: Some(vd),
            ..Mkb::default()
        };
        assert!(mkb.is_verified_media_key(&km));

        let mut wrong = km;
        wrong[0] ^= 0x01;
        assert!(!mkb.is_verified_media_key(&wrong));
    }

    // -----------------------------------------------------------------
    // §3.2.5.1.8 End-of-MKB signature + §3.2.5.1.2/3 RL block signatures
    // -----------------------------------------------------------------

    use crate::ec::{Point, U160};
    use crate::ecdsa::sign;

    /// A small deterministic AACS-LA-style key pair for signature
    /// roundtrip tests. We synthesise a 160-bit scalar, derive the
    /// corresponding public point, and sign / verify under both keys.
    fn synth_la_keypair() -> (U160, Point) {
        let mut bytes = [0u8; 20];
        // Non-trivial deterministic scalar; the exact value doesn't
        // matter as long as it's in [1, n-1].
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = 0x10u8.wrapping_add(i as u8);
        }
        let d = U160::from_be_bytes(&bytes);
        let q = Point::generator().mul_scalar(&d);
        (d, q)
    }

    fn build_type_and_version_record() -> Vec<u8> {
        let mut tv = Vec::new();
        tv.extend_from_slice(&0x0003_1003u32.to_be_bytes());
        tv.extend_from_slice(&7u32.to_be_bytes());
        write_record(0x10, &tv)
    }

    #[test]
    fn end_of_mkb_signature_verifies_under_correct_la_pub() {
        let (la_priv, la_pub) = synth_la_keypair();

        // Build the signed-prefix portion of the MKB.
        let mut prefix = Vec::new();
        prefix.extend_from_slice(&build_type_and_version_record());
        prefix.extend(write_record(0x81, &[0x42u8; 16]));

        // Sign the prefix per §3.2.5.1.8.
        let sig = sign(&la_priv, &prefix);

        let mut bytes = prefix.clone();
        bytes.extend(write_record(0x02, &sig));

        let mkb = Mkb::parse(&bytes).unwrap();
        assert!(mkb.end_of_block);
        assert_eq!(mkb.end_of_block_signature.as_ref(), Some(&sig));

        mkb.verify_end_of_block_signature(&bytes, &la_pub)
            .expect("End-of-MKB signature must verify under the AACS LA pub key");
    }

    #[test]
    fn end_of_mkb_signature_rejected_under_wrong_la_pub() {
        let (la_priv, _la_pub) = synth_la_keypair();

        let mut prefix = Vec::new();
        prefix.extend_from_slice(&build_type_and_version_record());
        prefix.extend(write_record(0x81, &[0x42u8; 16]));
        let sig = sign(&la_priv, &prefix);
        let mut bytes = prefix.clone();
        bytes.extend(write_record(0x02, &sig));

        let mkb = Mkb::parse(&bytes).unwrap();

        // Use a different LA key — verification must fail.
        let other_priv = U160::from_be_bytes(&[0x99u8; 20]);
        let other_pub = Point::generator().mul_scalar(&other_priv);
        assert!(matches!(
            mkb.verify_end_of_block_signature(&bytes, &other_pub),
            Err(AacsError::MkbSignatureInvalid)
        ));
    }

    #[test]
    fn end_of_mkb_signature_missing_when_no_record() {
        // MKB body has no End-of-MKB record at all.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&build_type_and_version_record());
        let mkb = Mkb::parse(&bytes).unwrap();
        assert!(!mkb.end_of_block);
        let (_priv, pubk) = synth_la_keypair();
        assert!(matches!(
            mkb.verify_end_of_block_signature(&bytes, &pubk),
            Err(AacsError::MkbSignatureMissing)
        ));
    }

    #[test]
    fn end_of_mkb_signature_missing_when_payload_is_not_40_bytes() {
        // The historical fixture had a 40-byte all-zero End-of-MKB
        // signature; an MKB constructor that ships a placeholder of a
        // different length should still parse but be rejected as
        // missing-signature rather than signature-invalid.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&build_type_and_version_record());
        // 16-byte placeholder instead of 40 bytes.
        bytes.extend(write_record(0x02, &[0u8; 16]));
        let mkb = Mkb::parse(&bytes).unwrap();
        assert!(mkb.end_of_block);
        assert!(mkb.end_of_block_signature.is_none());

        let (_priv, pubk) = synth_la_keypair();
        assert!(matches!(
            mkb.verify_end_of_block_signature(&bytes, &pubk),
            Err(AacsError::MkbSignatureMissing)
        ));
    }

    #[test]
    fn host_revocation_list_single_block_signature_verifies() {
        let (la_priv, la_pub) = synth_la_keypair();

        let tv = build_type_and_version_record();

        // Build a single-block HRL payload: total_entries=2 || N=2 ||
        // 2 entries || 40-byte sig over (tv || record_header ||
        // payload-up-to-sig).
        let mut hrl_payload = Vec::new();
        hrl_payload.extend_from_slice(&2u32.to_be_bytes()); // Total entries
        hrl_payload.extend_from_slice(&2u32.to_be_bytes()); // N1
                                                            // Two entries: range || id (8 bytes each).
        hrl_payload.extend_from_slice(&[0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        hrl_payload.extend_from_slice(&[0x00, 0x01, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15]);

        // Build the record header so we know the signed-data prefix.
        let total_len_with_sig = 4 + hrl_payload.len() + 40;
        let mut record_so_far = vec![
            0x21,
            ((total_len_with_sig >> 16) & 0xFF) as u8,
            ((total_len_with_sig >> 8) & 0xFF) as u8,
            (total_len_with_sig & 0xFF) as u8,
        ];
        record_so_far.extend_from_slice(&hrl_payload);

        // Sign tv || record_so_far per §3.2.5.1.2 "the entire Type and
        // Version Record, and also the data in the HRL Record … up to
        // … the byte immediately preceding the signature".
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&tv);
        signed_data.extend_from_slice(&record_so_far);
        let sig = sign(&la_priv, &signed_data);

        // Append the signature to form the final HRL record on the
        // wire.
        let mut full_record = record_so_far.clone();
        full_record.extend_from_slice(&sig);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&tv);
        bytes.extend_from_slice(&full_record);

        let mkb = Mkb::parse(&bytes).unwrap();
        assert_eq!(mkb.host_revocation_blocks.len(), 1);
        assert_eq!(mkb.host_revocation_blocks[0].entries_in_block, 2);
        assert_eq!(mkb.host_revocation_blocks[0].signature.as_ref(), Some(&sig));
        assert_eq!(mkb.host_revocation_list.len(), 2);

        mkb.verify_host_revocation_list(&bytes, &la_pub)
            .expect("HRL signature must verify");
    }

    #[test]
    fn drive_revocation_list_signature_verification_rejects_wrong_key() {
        let (la_priv, _la_pub) = synth_la_keypair();
        let tv = build_type_and_version_record();

        let mut drl_payload = Vec::new();
        drl_payload.extend_from_slice(&1u32.to_be_bytes()); // Total entries
        drl_payload.extend_from_slice(&1u32.to_be_bytes()); // N1
        drl_payload.extend_from_slice(&[0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        let total_len_with_sig = 4 + drl_payload.len() + 40;
        let mut record_so_far = vec![
            0x20,
            ((total_len_with_sig >> 16) & 0xFF) as u8,
            ((total_len_with_sig >> 8) & 0xFF) as u8,
            (total_len_with_sig & 0xFF) as u8,
        ];
        record_so_far.extend_from_slice(&drl_payload);

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&tv);
        signed_data.extend_from_slice(&record_so_far);
        let sig = sign(&la_priv, &signed_data);

        let mut full_record = record_so_far.clone();
        full_record.extend_from_slice(&sig);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&tv);
        bytes.extend_from_slice(&full_record);

        let mkb = Mkb::parse(&bytes).unwrap();
        assert_eq!(mkb.drive_revocation_blocks.len(), 1);

        let other_priv = U160::from_be_bytes(&[0x77u8; 20]);
        let other_pub = Point::generator().mul_scalar(&other_priv);
        assert!(matches!(
            mkb.verify_drive_revocation_list(&bytes, &other_pub),
            Err(AacsError::MkbSignatureInvalid)
        ));
    }

    #[test]
    fn revocation_list_signature_missing_when_block_has_no_signature() {
        // Hand-craft an HRL record whose payload is truncated before
        // the signature field. Per spec §3.2.5.1.2 final paragraph
        // this is allowed ("hosts are required to store only the data
        // being signed for the first signature block, but not required
        // to store the signature itself"). The verifier should return
        // MkbSignatureMissing rather than panicking.
        let tv = build_type_and_version_record();
        let mut hrl_payload = Vec::new();
        hrl_payload.extend_from_slice(&1u32.to_be_bytes()); // Total entries
        hrl_payload.extend_from_slice(&1u32.to_be_bytes()); // N1
        hrl_payload.extend_from_slice(&[0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let hrl_record = write_record(0x21, &hrl_payload);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&tv);
        bytes.extend_from_slice(&hrl_record);

        let mkb = Mkb::parse(&bytes).unwrap();
        assert_eq!(mkb.host_revocation_blocks.len(), 1);
        assert!(mkb.host_revocation_blocks[0].signature.is_none());

        let (_priv, pubk) = synth_la_keypair();
        assert!(matches!(
            mkb.verify_host_revocation_list(&bytes, &pubk),
            Err(AacsError::MkbSignatureMissing)
        ));
    }

    #[test]
    fn revocation_list_signature_missing_when_record_absent() {
        // Type-and-Version + End-of-MKB only, no HRL / DRL record.
        let tv = build_type_and_version_record();
        let mut bytes = tv.clone();
        bytes.extend(write_record(0x02, &[0u8; 40]));
        let mkb = Mkb::parse(&bytes).unwrap();
        assert!(mkb.host_revocation_blocks.is_empty());

        let (_priv, pubk) = synth_la_keypair();
        assert!(matches!(
            mkb.verify_host_revocation_list(&bytes, &pubk),
            Err(AacsError::MkbSignatureMissing)
        ));
        assert!(matches!(
            mkb.verify_drive_revocation_list(&bytes, &pubk),
            Err(AacsError::MkbSignatureMissing)
        ));
    }

    /// A two-block HRL exercises the cumulative-prefix rule: block 2's
    /// signature covers blocks 1 + 2 together (Type-and-Version ||
    /// HRL record bytes up to but not including block 2's signature).
    #[test]
    fn host_revocation_list_two_block_cumulative_signature_verifies() {
        let (la_priv, la_pub) = synth_la_keypair();
        let tv = build_type_and_version_record();

        // Block layout:
        //   total_entries(4) || N1(4) || E1 entries(8*N1) || sig1(40)
        //                   || N2(4) || E2 entries(8*N2) || sig2(40)
        let n1 = 1u32;
        let n2 = 1u32;
        let total_entries = n1 + n2;

        let mut payload_with_sigs = Vec::new();
        payload_with_sigs.extend_from_slice(&total_entries.to_be_bytes());
        // Block 1
        payload_with_sigs.extend_from_slice(&n1.to_be_bytes());
        payload_with_sigs.extend_from_slice(&[0x00, 0x00, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5]);

        // We need the final record length before we can build the
        // record header (which is part of the signed data). The final
        // record length = 4 (header) + 4 (total) + 4 (N1) + 8 (E1) +
        // 40 (sig1) + 4 (N2) + 8 (E2) + 40 (sig2) = 112.
        let record_len = 4 + 4 + 4 + 8 + 40 + 4 + 8 + 40;
        let header = [
            0x21,
            ((record_len >> 16) & 0xFF) as u8,
            ((record_len >> 8) & 0xFF) as u8,
            (record_len & 0xFF) as u8,
        ];

        // Compute sig1 over (tv || header || total || N1 || E1).
        let mut signed1 = Vec::new();
        signed1.extend_from_slice(&tv);
        signed1.extend_from_slice(&header);
        signed1.extend_from_slice(&payload_with_sigs); // total || N1 || E1
        let sig1 = sign(&la_priv, &signed1);
        payload_with_sigs.extend_from_slice(&sig1);

        // Block 2
        payload_with_sigs.extend_from_slice(&n2.to_be_bytes());
        payload_with_sigs.extend_from_slice(&[0x00, 0x00, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5]);
        let mut signed2 = Vec::new();
        signed2.extend_from_slice(&tv);
        signed2.extend_from_slice(&header);
        signed2.extend_from_slice(&payload_with_sigs); // total || N1 || E1 || sig1 || N2 || E2
        let sig2 = sign(&la_priv, &signed2);
        payload_with_sigs.extend_from_slice(&sig2);

        // Assemble the final record + MKB.
        let mut full_record = Vec::new();
        full_record.extend_from_slice(&header);
        full_record.extend_from_slice(&payload_with_sigs);
        assert_eq!(full_record.len(), record_len as usize);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&tv);
        bytes.extend_from_slice(&full_record);

        let mkb = Mkb::parse(&bytes).unwrap();
        assert_eq!(mkb.host_revocation_blocks.len(), 2);
        assert_eq!(
            mkb.host_revocation_blocks[0].signature.as_ref(),
            Some(&sig1)
        );
        assert_eq!(
            mkb.host_revocation_blocks[1].signature.as_ref(),
            Some(&sig2)
        );
        assert_eq!(mkb.host_revocation_list.len(), 2);

        mkb.verify_host_revocation_list(&bytes, &la_pub)
            .expect("Two-block HRL signature chain must verify cumulatively");
    }

    /// Tampering with any byte of the signed prefix breaks the
    /// End-of-MKB signature — the verifier must catch it.
    #[test]
    fn end_of_mkb_signature_rejected_when_prefix_tampered() {
        let (la_priv, la_pub) = synth_la_keypair();
        let mut prefix = Vec::new();
        prefix.extend_from_slice(&build_type_and_version_record());
        prefix.extend(write_record(0x81, &[0x42u8; 16]));
        let sig = sign(&la_priv, &prefix);
        let mut bytes = prefix.clone();
        bytes.extend(write_record(0x02, &sig));

        // Flip a Verify-Media-Key byte after parsing succeeded.
        let mkb = Mkb::parse(&bytes).unwrap();
        let mut tampered = bytes.clone();
        // The 0x81 record body starts at tv_len + 4; flip its first
        // payload byte.
        let tv_len = build_type_and_version_record().len();
        tampered[tv_len + 4] ^= 0x01;

        assert!(matches!(
            mkb.verify_end_of_block_signature(&tampered, &la_pub),
            Err(AacsError::MkbSignatureInvalid)
        ));
    }
}
