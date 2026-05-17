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
    /// Empty if no HRL is present.
    pub host_revocation_list: Vec<RevocationEntry>,
    /// Parsed Drive Revocation List entries (record type `0x20`).
    pub drive_revocation_list: Vec<RevocationEntry>,
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
    pub fn parse(mut bytes: &[u8]) -> Result<Self, AacsError> {
        let mut out = Mkb::default();
        let mut saw_type_record_first = false;
        let mut first_record = true;

        while !bytes.is_empty() {
            if bytes.len() < 4 {
                return Err(AacsError::Truncated("MKB record header"));
            }
            let tag = bytes[0];
            let length = (u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]])) as usize;
            if length < 4 {
                return Err(AacsError::InvalidValue {
                    what: "MKB record length",
                    value: length as u64,
                });
            }
            if length > bytes.len() {
                return Err(AacsError::OversizedRecord {
                    what: "MKB",
                    declared: length,
                    available: bytes.len(),
                });
            }
            let payload = &bytes[4..length];
            let advance = length;

            if first_record {
                if tag == 0x10 {
                    saw_type_record_first = true;
                }
                first_record = false;
            }

            match tag {
                0x10 => parse_type_and_version(payload, &mut out)?,
                0x21 => out.host_revocation_list = parse_revocation_list(payload)?,
                0x20 => out.drive_revocation_list = parse_revocation_list(payload)?,
                0x81 => out.verify_media_key = Some(parse_verify_media_key(payload)?),
                0x04 => out.explicit_subdiff = parse_explicit_subdiff(payload)?,
                0x07 => out.subdiff_index = Some(parse_subdiff_index(payload)?),
                0x05 => out.media_key_data = parse_media_key_data(payload)?,
                0x0C => out.media_key_variant_data = parse_media_key_data(payload)?,
                0x0D => out.variant_number_record = Some(parse_variant_number(payload)?),
                0x02 => {
                    // End of Media Key Block Record — payload is the
                    // signature, which we record only by setting the
                    // flag. Verification is out of scope.
                    out.end_of_block = true;
                }
                other => {
                    let mut blob = Vec::with_capacity(length);
                    blob.extend_from_slice(&bytes[..length]);
                    out.unknown_records.push((other, blob));
                }
            }

            bytes = &bytes[advance..];
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
        const SENTINEL: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        if plaintext[..8] == SENTINEL {
            Ok(())
        } else {
            Err(AacsError::MediaKeyVerificationFailed)
        }
    }
}

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

fn parse_revocation_list(payload: &[u8]) -> Result<Vec<RevocationEntry>, AacsError> {
    // Payload (record length - 4 bytes header) layout:
    //   Total Number of Entries        (4 bytes BE)
    //   for each signature block:
    //     Number of Entries in Block (N) (4 bytes BE)
    //     N * 8-byte Revocation Entry (Range 2B + ID 6B)
    //     40-byte Signature
    //
    // We don't verify signatures; we just collect all the entries
    // across every signature block.
    if payload.len() < 4 {
        return Err(AacsError::Truncated("Revocation List header"));
    }
    let _total = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let mut cursor = 4;
    let mut entries = Vec::new();
    while cursor < payload.len() {
        if cursor + 4 > payload.len() {
            return Err(AacsError::Truncated("Revocation List block header"));
        }
        let n = u32::from_be_bytes([
            payload[cursor],
            payload[cursor + 1],
            payload[cursor + 2],
            payload[cursor + 3],
        ]) as usize;
        cursor += 4;
        if cursor + n * 8 > payload.len() {
            return Err(AacsError::Truncated("Revocation List entries"));
        }
        for _ in 0..n {
            let range = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]);
            let mut id = [0u8; 6];
            id.copy_from_slice(&payload[cursor + 2..cursor + 8]);
            entries.push(RevocationEntry { range, id });
            cursor += 8;
        }
        // Signature is 40 bytes per spec §3.2.5.1.2 (`AACS_Verify`
        // ECDSA over the P-160-equivalent curve from §2.3 → 40-byte
        // signature). Skip if present; tolerate truncation since some
        // MKBs may store only the data being signed and not the
        // signature itself per spec (last paragraph of §3.2.5.1.2).
        let sig_len = 40usize.min(payload.len().saturating_sub(cursor));
        cursor += sig_len;
    }
    Ok(entries)
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
    fn rejects_truncated_header() {
        let bytes = vec![0x10, 0x00, 0x00]; // 3 bytes; not enough for a header
        assert!(matches!(
            Mkb::parse(&bytes),
            Err(AacsError::Truncated("MKB record header"))
        ));
    }

    #[test]
    fn rejects_oversized_length() {
        let bytes = vec![0x10, 0x00, 0xFF, 0x00, 0x00]; // declares 0xFF00 bytes
        assert!(matches!(
            Mkb::parse(&bytes),
            Err(AacsError::OversizedRecord { .. })
        ));
    }
}
