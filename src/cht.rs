//! Content Hash Table (CHT) parsing and per-Hash-Unit integrity
//! verification per BD-Prerecorded Final 0.953 §2.3.
//!
//! For each physical layer of a BD-ROM, the Content Hash Table is
//! stored as `ContentHash000.tbl` (Layer 0) and, on a dual-layer
//! disc, `ContentHash001.tbl` (Layer 1), in the `\AACS` directory and
//! its `\AACS\DUPLICATE` mirror (§2.3.1).
//!
//! The table carries an 8-byte Hash Value for every *Hash Unit* of
//! the Clip AV stream files under `\BDMV\STREAM` in the corresponding
//! layer, where a Hash Unit is a run of **96 Logical Sectors** =
//! 96 × 2048 = [`HASH_UNIT_SIZE`] bytes. The tail portion of a Clip
//! AV stream file shorter than one Hash Unit is omitted, so only
//! files of at least 96 Logical Sectors contribute (§2.3.1).
//!
//! The on-disc table is a header of `Number_of_Digests` 12-byte clip
//! descriptors followed by `Number_of_HashUnits` 8-byte Hash Values
//! (Table 2-2):
//!
//! ```text
//! Content Hash Table {
//!     for(I=0 ; I < Number_of_Digests ; I++) {
//!         Starting_HU_Num#I      32  uimsbf
//!         Clip_Num#I             32  uimsbf
//!         HU_Offset_in_Clip#I    32  uimsbf
//!     }
//!     for(I=0 ; I < Number_of_HashUnits ; I++) {
//!         Hash_Value#I           64  bslbf
//!     }
//! }
//! ```
//!
//! The two count fields are *not* stored in the table itself; they
//! come from the per-layer Content Certificate (`Content00N.cer`,
//! Table 2-1: `Number_of_Digests`, `Number_of_HashUnits`). The
//! parser therefore takes both counts as arguments.
//!
//! Verification (§2.3.2.1): a Hash Value is the least-significant 64
//! bits of the SHA-1 digest of the (possibly still-encrypted) Hash
//! Unit bytes —
//!
//! `Hash_Value = [SHA-1(Hash_Unit)]_lsb_64`
//!
//! Because the *encrypted* bytes are hashed, a Licensed Player can
//! verify integrity without first decrypting the stream.

use crate::ecdsa::sha1;
use crate::error::AacsError;

/// Size of a Logical Sector on a BD-Prerecorded Disc, in bytes
/// (BD-Prerecorded §2 "Definitions": all Logical Sectors share the
/// same 2048-byte size).
pub const LOGICAL_SECTOR_SIZE: usize = 2048;

/// Number of Logical Sectors in one Hash Unit (BD-Prerecorded §2.3.1:
/// "the size of each hash unit is 96 Logical Sectors").
pub const LOGICAL_SECTORS_PER_HASH_UNIT: usize = 96;

/// Size of a single Hash Unit in bytes:
/// `96 × 2048 = 196608` (= 192 KiB).
///
/// This also fixes the spec's "1344 KB" minimum: seven Hash Units is
/// `7 × 196608 = 1_376_256` bytes = exactly 1344 KiB.
pub const HASH_UNIT_SIZE: usize = LOGICAL_SECTORS_PER_HASH_UNIT * LOGICAL_SECTOR_SIZE;

/// One per-Clip descriptor from the header portion of the Content
/// Hash Table (Table 2-2, the `Number_of_Digests` loop). Describes
/// where a Clip AV stream file's Hash Values begin within this
/// layer's Hash Value list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClipDescriptor {
    /// `Starting_HU_Num#I` — index, into this table's Hash Value
    /// array, of the first Hash Value belonging to this Clip. Starts
    /// from zero. (On a dual-layer disc, `Starting_HU_Num#0` in
    /// `ContentHash001.tbl` equals Layer 0's `Number_of_HashUnits` —
    /// §2.3.1 note.)
    pub starting_hu_num: u32,
    /// `Clip_Num#I` — the 5-digit number embedded in the Clip AV
    /// stream file name (`<Clip_Num>.m2ts`), stored in ascending
    /// order.
    pub clip_num: u32,
    /// `HU_Offset_in_Clip#I` — offset, in Hash Units, from the head
    /// of the Clip AV stream file to the Hash Unit that the Hash
    /// Value at `starting_hu_num` covers. Starts from zero (non-zero
    /// only when an earlier extent of the Clip lives on a different
    /// layer).
    pub hu_offset_in_clip: u32,
}

/// A parsed Content Hash Table for one physical layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentHashTable {
    /// The `Number_of_Digests` per-Clip descriptors (Table 2-2 first
    /// loop).
    pub clips: Vec<ClipDescriptor>,
    /// The `Number_of_HashUnits` 8-byte Hash Values, in the on-disc
    /// order: ascending Clip file-name number, then ascending logical
    /// position within the Clip (§2.3.1).
    pub hash_values: Vec<[u8; 8]>,
}

/// Byte size of one header (per-Clip) descriptor:
/// `Starting_HU_Num (4) + Clip_Num (4) + HU_Offset_in_Clip (4)`.
const CLIP_DESCRIPTOR_SIZE: usize = 12;

/// Byte size of one stored Hash Value (§2.3.1: "an 8-byte Hash
/// Value").
pub const HASH_VALUE_SIZE: usize = 8;

impl ContentHashTable {
    /// Parse a Content Hash Table (`ContentHash00N.tbl`) per Table
    /// 2-2.
    ///
    /// `number_of_digests` and `number_of_hash_units` are the
    /// matching-layer fields from the Content Certificate (Table
    /// 2-1) — the table file itself does not store them.
    ///
    /// Trailing `00`-padding after the table body is tolerated for
    /// authoring/mastering purposes (mirrors the MKB / CRL
    /// trailing-padding rule the spec applies elsewhere), so a buffer
    /// longer than the exact computed size is accepted as long as the
    /// declared counts fit.
    pub fn parse(
        bytes: &[u8],
        number_of_digests: u32,
        number_of_hash_units: u32,
    ) -> Result<Self, AacsError> {
        let n_digests = number_of_digests as usize;
        let n_hash_units = number_of_hash_units as usize;

        let header_len = n_digests
            .checked_mul(CLIP_DESCRIPTOR_SIZE)
            .ok_or(AacsError::Truncated("Content Hash Table header"))?;
        let body_len = n_hash_units
            .checked_mul(HASH_VALUE_SIZE)
            .ok_or(AacsError::Truncated("Content Hash Table body"))?;
        let total = header_len
            .checked_add(body_len)
            .ok_or(AacsError::Truncated("Content Hash Table"))?;
        if bytes.len() < total {
            return Err(AacsError::OversizedRecord {
                what: "Content Hash Table",
                declared: total,
                available: bytes.len(),
            });
        }

        let mut clips = Vec::with_capacity(n_digests);
        let mut cursor = 0usize;
        for _ in 0..n_digests {
            let starting_hu_num = u32::from_be_bytes([
                bytes[cursor],
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
            ]);
            let clip_num = u32::from_be_bytes([
                bytes[cursor + 4],
                bytes[cursor + 5],
                bytes[cursor + 6],
                bytes[cursor + 7],
            ]);
            let hu_offset_in_clip = u32::from_be_bytes([
                bytes[cursor + 8],
                bytes[cursor + 9],
                bytes[cursor + 10],
                bytes[cursor + 11],
            ]);
            clips.push(ClipDescriptor {
                starting_hu_num,
                clip_num,
                hu_offset_in_clip,
            });
            cursor += CLIP_DESCRIPTOR_SIZE;
        }

        let mut hash_values = Vec::with_capacity(n_hash_units);
        for _ in 0..n_hash_units {
            let mut hv = [0u8; HASH_VALUE_SIZE];
            hv.copy_from_slice(&bytes[cursor..cursor + HASH_VALUE_SIZE]);
            hash_values.push(hv);
            cursor += HASH_VALUE_SIZE;
        }

        Ok(Self { clips, hash_values })
    }

    /// Number of stored Hash Values (= `Number_of_HashUnits` for the
    /// layer).
    pub fn len(&self) -> usize {
        self.hash_values.len()
    }

    /// True when this table holds no Hash Values. The spec permits a
    /// zero-byte CHT for a layer with no Clip AV stream file of at
    /// least 96 Logical Sectors (§2.3.1).
    pub fn is_empty(&self) -> bool {
        self.hash_values.is_empty()
    }

    /// Verify the Hash Unit at table index `hash_unit_index` against
    /// its stored Hash Value, by recomputing
    /// `[SHA-1(hash_unit_bytes)]_lsb_64` (§2.3.2.1).
    ///
    /// `hash_unit_bytes` must be exactly [`HASH_UNIT_SIZE`] bytes —
    /// the *encrypted* on-disc bytes are hashed (no decryption
    /// first), so this works whether or not the caller holds the
    /// Title Key.
    ///
    /// Returns [`AacsError::InvalidValue`] if `hash_unit_index` is out
    /// of range, [`AacsError::BadHashUnitLength`] if the supplied unit
    /// is the wrong size, and [`AacsError::ContentHashMismatch`] if
    /// the recomputed value does not match.
    pub fn verify_hash_unit(
        &self,
        hash_unit_index: usize,
        hash_unit_bytes: &[u8],
    ) -> Result<(), AacsError> {
        let stored = self
            .hash_values
            .get(hash_unit_index)
            .ok_or(AacsError::InvalidValue {
                what: "Content Hash Table hash-unit index",
                value: hash_unit_index as u64,
            })?;
        if hash_unit_bytes.len() != HASH_UNIT_SIZE {
            return Err(AacsError::BadHashUnitLength(hash_unit_bytes.len()));
        }
        let computed = hash_value_of_unit(hash_unit_bytes);
        if &computed == stored {
            Ok(())
        } else {
            Err(AacsError::ContentHashMismatch {
                index: hash_unit_index,
            })
        }
    }
}

/// Compute the 8-byte AACS Content Hash Value of a single Hash Unit
/// per BD-Prerecorded §2.3.2.1:
///
/// `Hash_Value = [SHA-1(Hash_Unit)]_lsb_64`
///
/// i.e. the least-significant (last) 8 bytes of the 20-byte SHA-1
/// digest. The Hash Unit may be the still-encrypted on-disc bytes.
///
/// This helper does **not** enforce the [`HASH_UNIT_SIZE`] length;
/// [`ContentHashTable::verify_hash_unit`] does that for the disc
/// path. Exposed separately so a CHT *author* can hash a final
/// 96-LS-aligned unit directly.
pub fn hash_value_of_unit(hash_unit: &[u8]) -> [u8; HASH_VALUE_SIZE] {
    let digest = sha1(hash_unit);
    let mut out = [0u8; HASH_VALUE_SIZE];
    out.copy_from_slice(&digest[20 - HASH_VALUE_SIZE..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic Hash Unit whose bytes are deterministic in a
    /// seed, so tests don't embed any disc-derived material.
    fn synth_hash_unit(seed: u8) -> Vec<u8> {
        (0..HASH_UNIT_SIZE)
            .map(|i| (i as u8).wrapping_add(seed).wrapping_mul(31))
            .collect()
    }

    #[test]
    fn hash_unit_size_is_1344kb_over_seven() {
        assert_eq!(HASH_UNIT_SIZE, 96 * 2048);
        assert_eq!(HASH_UNIT_SIZE, 196_608);
        // The spec's 1344 KB minimum is exactly seven Hash Units.
        assert_eq!(7 * HASH_UNIT_SIZE, 1344 * 1024);
    }

    #[test]
    fn hash_value_is_lsb_64_of_sha1() {
        let unit = synth_hash_unit(0x10);
        let digest = sha1(&unit);
        let hv = hash_value_of_unit(&unit);
        assert_eq!(&hv[..], &digest[12..20]);
    }

    #[test]
    fn parse_roundtrips_header_and_body() {
        // Two clips, three hash values.
        let clips = [
            ClipDescriptor {
                starting_hu_num: 0,
                clip_num: 0,
                hu_offset_in_clip: 0,
            },
            ClipDescriptor {
                starting_hu_num: 2,
                clip_num: 17,
                hu_offset_in_clip: 0,
            },
        ];
        let units: Vec<Vec<u8>> = (0..3u8).map(synth_hash_unit).collect();

        let mut buf = Vec::new();
        for c in &clips {
            buf.extend_from_slice(&c.starting_hu_num.to_be_bytes());
            buf.extend_from_slice(&c.clip_num.to_be_bytes());
            buf.extend_from_slice(&c.hu_offset_in_clip.to_be_bytes());
        }
        for u in &units {
            buf.extend_from_slice(&hash_value_of_unit(u));
        }

        let cht = ContentHashTable::parse(&buf, clips.len() as u32, units.len() as u32).unwrap();
        assert_eq!(cht.clips, clips);
        assert_eq!(cht.len(), 3);
        assert!(!cht.is_empty());

        // Every unit verifies against its own bytes.
        for (i, u) in units.iter().enumerate() {
            cht.verify_hash_unit(i, u).unwrap();
        }
    }

    #[test]
    fn verify_rejects_tampered_unit() {
        let unit = synth_hash_unit(5);
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&hash_value_of_unit(&unit));
        let cht = ContentHashTable::parse(&buf, 1, 1).unwrap();

        let mut tampered = unit.clone();
        tampered[123] ^= 0x01;
        assert_eq!(
            cht.verify_hash_unit(0, &tampered),
            Err(AacsError::ContentHashMismatch { index: 0 })
        );
    }

    #[test]
    fn verify_rejects_wrong_unit_length() {
        let unit = synth_hash_unit(1);
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; CLIP_DESCRIPTOR_SIZE]);
        buf.extend_from_slice(&hash_value_of_unit(&unit));
        let cht = ContentHashTable::parse(&buf, 1, 1).unwrap();
        let short = vec![0u8; HASH_UNIT_SIZE - 1];
        assert_eq!(
            cht.verify_hash_unit(0, &short),
            Err(AacsError::BadHashUnitLength(HASH_UNIT_SIZE - 1))
        );
    }

    #[test]
    fn verify_rejects_out_of_range_index() {
        let unit = synth_hash_unit(2);
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; CLIP_DESCRIPTOR_SIZE]);
        buf.extend_from_slice(&hash_value_of_unit(&unit));
        let cht = ContentHashTable::parse(&buf, 1, 1).unwrap();
        assert!(matches!(
            cht.verify_hash_unit(9, &unit),
            Err(AacsError::InvalidValue { .. })
        ));
    }

    #[test]
    fn parse_tolerates_trailing_padding() {
        let unit = synth_hash_unit(3);
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; CLIP_DESCRIPTOR_SIZE]);
        buf.extend_from_slice(&hash_value_of_unit(&unit));
        buf.extend_from_slice(&[0u8; 2048]); // authoring/mastering padding
        let cht = ContentHashTable::parse(&buf, 1, 1).unwrap();
        assert_eq!(cht.len(), 1);
        cht.verify_hash_unit(0, &unit).unwrap();
    }

    #[test]
    fn parse_rejects_truncated_body() {
        // Declare 4 hash units but supply only 1.
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; CLIP_DESCRIPTOR_SIZE]);
        buf.extend_from_slice(&[0u8; HASH_VALUE_SIZE]);
        assert!(matches!(
            ContentHashTable::parse(&buf, 1, 4),
            Err(AacsError::OversizedRecord { .. })
        ));
    }

    #[test]
    fn zero_byte_table_is_empty() {
        let cht = ContentHashTable::parse(&[], 0, 0).unwrap();
        assert!(cht.is_empty());
        assert_eq!(cht.len(), 0);
    }
}
