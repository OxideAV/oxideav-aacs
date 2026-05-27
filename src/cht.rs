//! Content Hash Table parser + per-hash-unit SHA-1 verification per
//! AACS BD-Prerecorded Final 0.953 §2.3.
//!
//! The Content Hash Table (CHT) is the on-disc SHA-1 integrity check
//! that lets a Licensed Player confirm a Clip AV stream hasn't been
//! tampered with between mastering and playback, without having to
//! decrypt the data first (§2.3.2.1 — "If the data is encrypted, the
//! encrypted data itself is used as the input to the hashing function,
//! so that the Licensed Player need not decrypt the data before
//! calculating a Hash Value").
//!
//! ## Layout (§2.3.1, Table 2-2)
//!
//! Each physical layer of a BD-ROM gets one CHT file:
//!
//! - Single-layer disc: `AACS/ContentHash000.tbl`.
//! - Dual-layer disc: `AACS/ContentHash000.tbl` (Layer 0) +
//!   `AACS/ContentHash001.tbl` (Layer 1).
//!
//! Both are duplicated in `AACS/DUPLICATE/`. The CHT file itself is a
//! header section followed by a body of 8-byte hash values:
//!
//! ```text
//! +---------------------------------------------------------+
//! |  for I = 0 .. Number_of_Digests - 1:                    |
//! |    Starting_HU_Num#I   (u32 BE)                          |
//! |    Clip_Num#I          (u32 BE)                          |
//! |    HU_Offset_in_Clip#I (u32 BE)                          |
//! |  for I = 0 .. Number_of_HashUnits - 1:                  |
//! |    Hash_Value#I        (8 bytes — lsb_64 of SHA-1)       |
//! +---------------------------------------------------------+
//! ```
//!
//! `Number_of_Digests` (count of Clip AV stream files ≥ 96 logical
//! sectors) and `Number_of_HashUnits` (per-layer hash-unit count) are
//! NOT carried inside the CHT — they live in the Content Certificate
//! (`Content000.cer` / `Content001.cer`, §2.1 Table 2-1). So a CHT
//! cannot be parsed in isolation; the caller must supply both counts.
//!
//! Per spec §2.3.1 the body Hash_Values are recorded in ascending
//! order of (Clip file number, logical position inside the clip).
//!
//! ## Hash value computation (§2.3.2.1)
//!
//! ```text
//! Hash_Value = [SHA-1(Hash_Unit)]_lsb_64
//! ```
//!
//! - A Hash Unit is 96 Logical Sectors = `96 × 2048` = `196 608` bytes
//!   (§1.7 "Hash Unit: A Hash Unit consists of a series of 96 Logical
//!   Sectors").
//! - `_lsb_64` selects the low 64 bits of the SHA-1 output. SHA-1 is
//!   defined to emit its 160-bit output big-endian, so the
//!   least-significant 64 bits are bytes 12..20 of the digest (not
//!   bytes 0..8).
//!
//! ## Scope
//!
//! This module owns parse + per-Hash-Unit verification. The Content
//! Certificate parser and the Content_Hash_Table_Digest cross-check
//! (Content Cert ↔ CHT, §2.3.2/§2.3.3) are deferred — they need the
//! AACS LA root public key for signature verification, which is out of
//! scope for the same reason as `AACS_Verify(AACS_LA_pub, ...)` on the
//! MKB (`README.md` "Out of scope").

use crate::ecdsa::sha1;
use crate::error::AacsError;

/// Hash Unit size in bytes — 96 Logical Sectors × 2048 bytes
/// (BD-Prerecorded §1.7 + Blu-ray Logical Sector = 2 KiB).
///
/// The encrypted Aligned Unit is 6144 bytes (= 3 Logical Sectors), so a
/// Hash Unit covers exactly 32 Aligned Units — same as one ECC Cluster
/// (§1.7 "ECC Cluster: An ECC Cluster consists of a series of 32
/// Physical Sectors"). Each Hash_Value therefore digests one ECC
/// Cluster's worth of payload.
pub const HASH_UNIT_SIZE: usize = 96 * 2048;

/// Bytes per stored Hash_Value (`lsb_64` of SHA-1 = 8 bytes, §2.3.2.1).
pub const HASH_VALUE_LEN: usize = 8;

/// Bytes per Digest record (`Starting_HU_Num || Clip_Num ||
/// HU_Offset_in_Clip`, three big-endian 32-bit fields).
pub const DIGEST_RECORD_LEN: usize = 12;

/// One row of the CHT header — the position-in-disc of the first Hash
/// Value belonging to one Clip AV stream file.
///
/// Per BD-Prerecorded §2.3.1:
///
/// - `starting_hu_num` (4 bytes): position (in Hash Units) of the
///   first Hash Value of this Clip in the body, *counted within this
///   layer's Hash Value array*. Starts from zero (for Layer 0) or
///   continues from where Layer 0 left off (for Layer 1 in a
///   dual-layer disc) — see the
///   [`ContentHashTable::lookup_hash_value`] note on dual-layer
///   `hu_offset_in_clip` resume semantics.
/// - `clip_num` (4 bytes): the 5-digit number in the Clip AV stream
///   file's name (e.g. `00001` for `00001.m2ts`). Listed in ascending
///   order.
/// - `hu_offset_in_clip` (4 bytes): Hash-Unit offset *inside the
///   Clip*, counted from the top of the clip file. Starts from zero
///   for the first extent of a clip; non-zero when an earlier extent
///   of the same clip lives on a different layer (dual-layer split).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DigestRecord {
    /// Position in Hash Units of the first Hash Value of this Clip in
    /// the body, within this layer.
    pub starting_hu_num: u32,
    /// 5-digit Clip number (file-name root).
    pub clip_num: u32,
    /// Hash-Unit offset inside the Clip itself.
    pub hu_offset_in_clip: u32,
}

/// A parsed Content Hash Table for one physical layer
/// (`ContentHash000.tbl` or `ContentHash001.tbl`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContentHashTable {
    /// Per-Clip digest records (Table 2-2 first loop). Length equals
    /// the `Number_of_Digests` from the Content Certificate header.
    pub digests: Vec<DigestRecord>,
    /// Concatenated Hash Values (Table 2-2 second loop), one 8-byte
    /// entry per Hash Unit on this layer. Length equals the
    /// `Number_of_HashUnits` from the Content Certificate header.
    pub hash_values: Vec<[u8; HASH_VALUE_LEN]>,
}

impl ContentHashTable {
    /// Parse a `ContentHashNNN.tbl` byte stream using counts supplied
    /// from the layer's Content Certificate.
    ///
    /// Both counts must come from the certificate (Table 2-1
    /// `Number_of_Digests` and `Number_of_HashUnits`) because the CHT
    /// file itself stores neither.
    ///
    /// Per §2.3.1 "the size of CHT is zero bytes if there is no Clip
    /// AV stream that has a file greater than or equal to 96 Logical
    /// Sectors on the corresponding layer" — when both counts are zero
    /// the parser accepts an empty buffer.
    ///
    /// Trailing zero padding (§3.1 "MKB data shall be recorded from
    /// the first byte of the file, and null `(00_16)` padding may be
    /// appended after the MKB data in the file for authoring and
    /// mastering purposes" — the same authoring convention applies to
    /// `.tbl` files) is tolerated.
    pub fn parse(
        bytes: &[u8],
        number_of_digests: u32,
        number_of_hash_units: u32,
    ) -> Result<Self, AacsError> {
        let n_digests = number_of_digests as usize;
        let n_hashes = number_of_hash_units as usize;
        let header_len =
            n_digests
                .checked_mul(DIGEST_RECORD_LEN)
                .ok_or(AacsError::InvalidValue {
                    what: "ContentHashTable Number_of_Digests",
                    value: number_of_digests as u64,
                })?;
        let body_len = n_hashes
            .checked_mul(HASH_VALUE_LEN)
            .ok_or(AacsError::InvalidValue {
                what: "ContentHashTable Number_of_HashUnits",
                value: number_of_hash_units as u64,
            })?;
        let required = header_len
            .checked_add(body_len)
            .ok_or(AacsError::InvalidValue {
                what: "ContentHashTable size",
                value: u64::MAX,
            })?;
        if bytes.len() < required {
            return Err(AacsError::OversizedRecord {
                what: "ContentHashTable",
                declared: required,
                available: bytes.len(),
            });
        }
        // §2.3.1: zero-sized CHT is legal — bail out cleanly when both
        // counts are zero rather than returning an empty struct that
        // accidentally compared equal to an unparsed default.
        if required == 0 {
            // Still confirm any trailing bytes (if any) are zero
            // padding before accepting; a non-zero stray byte against
            // a (0, 0)-sized CHT means counts disagreed with the file.
            if bytes.iter().any(|&b| b != 0) {
                return Err(AacsError::InvalidValue {
                    what: "ContentHashTable nonzero bytes against (0,0) counts",
                    value: bytes.len() as u64,
                });
            }
            return Ok(Self::default());
        }
        let mut digests = Vec::with_capacity(n_digests);
        for i in 0..n_digests {
            let off = i * DIGEST_RECORD_LEN;
            let starting_hu_num = read_u32_be(&bytes[off..off + 4]);
            let clip_num = read_u32_be(&bytes[off + 4..off + 8]);
            let hu_offset_in_clip = read_u32_be(&bytes[off + 8..off + 12]);
            digests.push(DigestRecord {
                starting_hu_num,
                clip_num,
                hu_offset_in_clip,
            });
        }
        let mut hash_values = Vec::with_capacity(n_hashes);
        for i in 0..n_hashes {
            let off = header_len + i * HASH_VALUE_LEN;
            let mut hv = [0u8; HASH_VALUE_LEN];
            hv.copy_from_slice(&bytes[off..off + HASH_VALUE_LEN]);
            hash_values.push(hv);
        }
        // Tolerate authoring-tail zero padding after `required` bytes.
        if bytes[required..].iter().any(|&b| b != 0) {
            return Err(AacsError::InvalidValue {
                what: "ContentHashTable trailing non-zero padding",
                value: (bytes.len() - required) as u64,
            });
        }
        Ok(Self {
            digests,
            hash_values,
        })
    }

    /// Look up the stored Hash_Value for a given Clip number + offset
    /// inside the Clip.
    ///
    /// `hu_in_clip` is the Hash-Unit-aligned offset within the clip
    /// (`physical_byte_offset / HASH_UNIT_SIZE`). Returns `None` when
    /// `clip_num` is not represented on this layer, or when the
    /// requested in-clip offset falls outside the layer's coverage of
    /// that clip (e.g. the request is for Layer 0's portion of a
    /// dual-layer-split clip but this is the Layer 1 CHT).
    ///
    /// Per §2.3.1 last paragraph and Figure 2-2: when a clip is split
    /// across layers, the per-clip in-clip offsets *resume* from where
    /// the previous layer left off — i.e. the Layer 1 CHT's
    /// `hu_offset_in_clip` for the split clip is the count of
    /// HashUnits already covered by Layer 0, so this lookup needs the
    /// CHT's `digests` entry for that clip plus the *next* clip (or
    /// the layer-end) to bracket the in-clip range stored on this
    /// layer.
    pub fn lookup_hash_value(
        &self,
        clip_num: u32,
        hu_in_clip: u32,
    ) -> Option<&[u8; HASH_VALUE_LEN]> {
        // Find the digest record for this clip on this layer.
        let pos = self.digests.iter().position(|d| d.clip_num == clip_num)?;
        let d = &self.digests[pos];
        // The window of `hu_in_clip` values this layer's record covers
        // runs from `d.hu_offset_in_clip` to (next record's
        // hu_offset_in_clip - 1) when the next record is for the same
        // clip, or to the layer's hash_values tail otherwise. The
        // next record is always for a different clip (clip records are
        // unique within one CHT — clip-extent splitting is across
        // layers, not within one CHT).
        if hu_in_clip < d.hu_offset_in_clip {
            return None;
        }
        let local_hu_idx = (hu_in_clip - d.hu_offset_in_clip) as usize + d.starting_hu_num as usize;
        self.hash_values.get(local_hu_idx)
    }

    /// Verify one Hash Unit's bytes against the stored Hash_Value for
    /// `(clip_num, hu_in_clip)` on this layer.
    ///
    /// `hash_unit` must be exactly [`HASH_UNIT_SIZE`] bytes; for the
    /// encrypted Clip AV stream case the bytes are passed through
    /// unchanged (§2.3.2.1 — the encrypted data is what's hashed, no
    /// decryption needed).
    ///
    /// Returns:
    /// - `Ok(())` on match.
    /// - `Err(AacsError::InvalidValue { .. })` for a wrong-sized Hash
    ///   Unit, or for a `(clip_num, hu_in_clip)` not represented on
    ///   this layer.
    /// - `Err(AacsError::ContentHashMismatch)` when the SHA-1 lsb_64
    ///   differs from the stored Hash_Value.
    pub fn verify_hash_unit(
        &self,
        clip_num: u32,
        hu_in_clip: u32,
        hash_unit: &[u8],
    ) -> Result<(), AacsError> {
        if hash_unit.len() != HASH_UNIT_SIZE {
            return Err(AacsError::InvalidValue {
                what: "Hash Unit byte length (must be 96 Logical Sectors = 196608 bytes)",
                value: hash_unit.len() as u64,
            });
        }
        let expected =
            self.lookup_hash_value(clip_num, hu_in_clip)
                .ok_or(AacsError::InvalidValue {
                    what:
                        "ContentHashTable: no Hash_Value for (clip_num, hu_in_clip) on this layer",
                    value: ((clip_num as u64) << 32) | hu_in_clip as u64,
                })?;
        let actual = compute_hash_value(hash_unit);
        if &actual == expected {
            Ok(())
        } else {
            Err(AacsError::ContentHashMismatch {
                clip_num,
                hu_in_clip,
            })
        }
    }
}

/// Compute the 8-byte Hash_Value for one Hash Unit per §2.3.2.1:
/// `Hash_Value = [SHA-1(Hash_Unit)]_lsb_64`.
///
/// SHA-1 emits its 160-bit digest as 20 big-endian bytes, so the
/// least-significant 64 bits are bytes 12..20.
pub fn compute_hash_value(hash_unit: &[u8]) -> [u8; HASH_VALUE_LEN] {
    let digest = sha1(hash_unit);
    let mut out = [0u8; HASH_VALUE_LEN];
    out.copy_from_slice(&digest[12..20]);
    out
}

fn read_u32_be(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synth_cht_bytes(digests: &[DigestRecord], hash_values: &[[u8; 8]]) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            digests.len() * DIGEST_RECORD_LEN + hash_values.len() * HASH_VALUE_LEN,
        );
        for d in digests {
            out.extend_from_slice(&d.starting_hu_num.to_be_bytes());
            out.extend_from_slice(&d.clip_num.to_be_bytes());
            out.extend_from_slice(&d.hu_offset_in_clip.to_be_bytes());
        }
        for hv in hash_values {
            out.extend_from_slice(hv);
        }
        out
    }

    #[test]
    fn parse_roundtrips_single_clip_two_hash_units() {
        let digests = vec![DigestRecord {
            starting_hu_num: 0,
            clip_num: 1,
            hu_offset_in_clip: 0,
        }];
        let hvs = vec![[0x11u8; 8], [0x22u8; 8]];
        let bytes = synth_cht_bytes(&digests, &hvs);
        let cht = ContentHashTable::parse(&bytes, 1, 2).unwrap();
        assert_eq!(cht.digests, digests);
        assert_eq!(cht.hash_values, hvs);
    }

    #[test]
    fn parse_accepts_zero_sized_cht_when_counts_are_zero() {
        // §2.3.1: empty CHT is legal when no Clip AV stream ≥ 96
        // Logical Sectors lives on the layer.
        let cht = ContentHashTable::parse(&[], 0, 0).unwrap();
        assert!(cht.digests.is_empty());
        assert!(cht.hash_values.is_empty());
    }

    #[test]
    fn parse_tolerates_authoring_trailing_zero_padding() {
        let digests = vec![DigestRecord {
            starting_hu_num: 0,
            clip_num: 5,
            hu_offset_in_clip: 0,
        }];
        let hvs = vec![[0xABu8; 8]];
        let mut bytes = synth_cht_bytes(&digests, &hvs);
        bytes.extend_from_slice(&[0u8; 32]); // sector-pad zeros
        let cht = ContentHashTable::parse(&bytes, 1, 1).unwrap();
        assert_eq!(cht.hash_values, hvs);
    }

    #[test]
    fn parse_rejects_truncated_buffer() {
        // 1 digest + 3 hash values = 12 + 24 = 36 bytes required.
        let bytes = vec![0u8; 35];
        assert!(matches!(
            ContentHashTable::parse(&bytes, 1, 3),
            Err(AacsError::OversizedRecord { .. })
        ));
    }

    #[test]
    fn parse_rejects_nonzero_trailing_bytes_against_zero_counts() {
        // (0, 0) counts must reject non-zero stray bytes — that
        // indicates the counts disagreed with the on-disc file.
        let bytes = vec![1u8; 4];
        assert!(matches!(
            ContentHashTable::parse(&bytes, 0, 0),
            Err(AacsError::InvalidValue { .. })
        ));
    }

    #[test]
    fn parse_rejects_nonzero_trailing_padding() {
        // Trailing junk after the declared body is not valid.
        let digests = vec![DigestRecord {
            starting_hu_num: 0,
            clip_num: 7,
            hu_offset_in_clip: 0,
        }];
        let hvs = vec![[0xCDu8; 8]];
        let mut bytes = synth_cht_bytes(&digests, &hvs);
        bytes.extend_from_slice(&[0xFFu8; 8]); // garbage tail
        assert!(matches!(
            ContentHashTable::parse(&bytes, 1, 1),
            Err(AacsError::InvalidValue { .. })
        ));
    }

    #[test]
    fn compute_hash_value_matches_sha1_lsb_64() {
        // Pin: a Hash_Unit of all-zero bytes hashes to a known SHA-1
        // value; the low-64 bits of that value are what we store.
        let unit = vec![0u8; HASH_UNIT_SIZE];
        let hv = compute_hash_value(&unit);
        let full = sha1(&unit);
        assert_eq!(&hv[..], &full[12..20]);
    }

    #[test]
    fn lookup_hash_value_indexes_local_hu_window() {
        // One clip, three hash units starting at hu_offset_in_clip=0.
        // Lookup for in-clip indices 0..3 should yield indices 0..3 of
        // the hash_values vector.
        let digests = vec![DigestRecord {
            starting_hu_num: 0,
            clip_num: 42,
            hu_offset_in_clip: 0,
        }];
        let hvs = vec![[1u8; 8], [2u8; 8], [3u8; 8]];
        let cht = ContentHashTable {
            digests,
            hash_values: hvs.clone(),
        };
        assert_eq!(cht.lookup_hash_value(42, 0), Some(&hvs[0]));
        assert_eq!(cht.lookup_hash_value(42, 1), Some(&hvs[1]));
        assert_eq!(cht.lookup_hash_value(42, 2), Some(&hvs[2]));
        // Out-of-range in-clip offset on a known clip.
        assert_eq!(cht.lookup_hash_value(42, 3), None);
        // Unknown clip.
        assert_eq!(cht.lookup_hash_value(99, 0), None);
    }

    #[test]
    fn lookup_hash_value_handles_layer1_resume_offset() {
        // Dual-layer split: the second extent of clip #1 lives on
        // Layer 1; its CHT row sets hu_offset_in_clip to the count of
        // HashUnits Layer 0 already covered (= 5 in Figure 2-2).
        // Layer 1's local hash_values[0] therefore belongs to in-clip
        // hu_index = 5, NOT 0.
        let digests = vec![DigestRecord {
            starting_hu_num: 0,
            clip_num: 1,
            hu_offset_in_clip: 5,
        }];
        let hvs = vec![[0xAAu8; 8], [0xBBu8; 8]];
        let cht = ContentHashTable {
            digests,
            hash_values: hvs.clone(),
        };
        // In-clip index < hu_offset_in_clip belongs to a different
        // layer — not on this CHT.
        assert_eq!(cht.lookup_hash_value(1, 4), None);
        assert_eq!(cht.lookup_hash_value(1, 5), Some(&hvs[0]));
        assert_eq!(cht.lookup_hash_value(1, 6), Some(&hvs[1]));
        assert_eq!(cht.lookup_hash_value(1, 7), None);
    }

    #[test]
    fn lookup_hash_value_two_clips_on_one_layer() {
        // Figure 2-2 Layer 0: Clip 0 contributes HU 0..2 (2 hashes),
        // Clip 1 contributes HU 2..5 (next 3 hashes — but Figure-2-2
        // is "Clip 1 starts at 3 with 1 hash, Clip 2 starts at 5..").
        // We test the simpler shape "two clips on one layer with their
        // own contiguous hash-value runs".
        let digests = vec![
            DigestRecord {
                starting_hu_num: 0,
                clip_num: 0,
                hu_offset_in_clip: 0,
            },
            DigestRecord {
                starting_hu_num: 2,
                clip_num: 1,
                hu_offset_in_clip: 0,
            },
        ];
        let hvs = vec![
            [0xC0u8; 8], // clip 0 hu 0
            [0xC1u8; 8], // clip 0 hu 1
            [0xD0u8; 8], // clip 1 hu 0
            [0xD1u8; 8], // clip 1 hu 1
        ];
        let cht = ContentHashTable {
            digests,
            hash_values: hvs.clone(),
        };
        assert_eq!(cht.lookup_hash_value(0, 0), Some(&hvs[0]));
        assert_eq!(cht.lookup_hash_value(0, 1), Some(&hvs[1]));
        assert_eq!(cht.lookup_hash_value(1, 0), Some(&hvs[2]));
        assert_eq!(cht.lookup_hash_value(1, 1), Some(&hvs[3]));
    }

    #[test]
    fn verify_hash_unit_round_trips() {
        // Construct a Hash Unit, compute its Hash_Value, store it,
        // then round-trip through verify_hash_unit.
        let mut unit = vec![0u8; HASH_UNIT_SIZE];
        for (i, b) in unit.iter_mut().enumerate() {
            *b = (i & 0xFF) as u8;
        }
        let hv = compute_hash_value(&unit);
        let cht = ContentHashTable {
            digests: vec![DigestRecord {
                starting_hu_num: 0,
                clip_num: 7,
                hu_offset_in_clip: 0,
            }],
            hash_values: vec![hv],
        };
        cht.verify_hash_unit(7, 0, &unit).expect("should verify");
    }

    #[test]
    fn verify_hash_unit_rejects_tampered_bytes() {
        let mut unit = vec![0xAAu8; HASH_UNIT_SIZE];
        let good = compute_hash_value(&unit);
        let cht = ContentHashTable {
            digests: vec![DigestRecord {
                starting_hu_num: 0,
                clip_num: 1,
                hu_offset_in_clip: 0,
            }],
            hash_values: vec![good],
        };
        // Flip one byte in the middle of the unit.
        unit[HASH_UNIT_SIZE / 2] ^= 0x01;
        match cht.verify_hash_unit(1, 0, &unit) {
            Err(AacsError::ContentHashMismatch {
                clip_num,
                hu_in_clip,
            }) => {
                assert_eq!(clip_num, 1);
                assert_eq!(hu_in_clip, 0);
            }
            other => panic!("expected ContentHashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_hash_unit_rejects_wrong_size_input() {
        let cht = ContentHashTable {
            digests: vec![DigestRecord {
                starting_hu_num: 0,
                clip_num: 0,
                hu_offset_in_clip: 0,
            }],
            hash_values: vec![[0u8; 8]],
        };
        let short = vec![0u8; HASH_UNIT_SIZE - 1];
        assert!(matches!(
            cht.verify_hash_unit(0, 0, &short),
            Err(AacsError::InvalidValue { .. })
        ));
    }

    #[test]
    fn verify_hash_unit_rejects_unknown_clip() {
        let cht = ContentHashTable {
            digests: vec![DigestRecord {
                starting_hu_num: 0,
                clip_num: 1,
                hu_offset_in_clip: 0,
            }],
            hash_values: vec![[0u8; 8]],
        };
        let unit = vec![0u8; HASH_UNIT_SIZE];
        assert!(matches!(
            cht.verify_hash_unit(99, 0, &unit),
            Err(AacsError::InvalidValue { .. })
        ));
    }
}
