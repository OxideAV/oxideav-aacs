//! AACS Subset-Difference broadcast-encryption tree walk
//! (Common spec §3.2.1 — §3.2.4).
//!
//! Each compliant device holds a small set of 128-bit *Device Keys*.
//! Each Device Key sits at a position in a binary key-tree, identified
//! by a 32-bit `uv` number with separate `u_mask` and `v_mask`
//! "don't-care" masks. To extract the Media Key from an MKB, the
//! device must:
//!
//! 1. Find an Explicit-Subset-Difference Record entry `(uv', m_u', m_v')`
//!    that *applies* to it — i.e. its leaf node `D_node` satisfies
//!    `(D_node & m_u) == (uv & m_u) && (D_node & m_v) != (uv & m_v)`.
//! 2. Find a stored Device Key whose path matches the `m_u` part of
//!    the entry but whose `m_v'` doesn't match the entry's `m_v` —
//!    i.e. the stored key sits between the entry's `u`-node and the
//!    target `v`-node.
//! 3. Walk down from that stored Device Key toward the entry's `v`
//!    node by repeated AES-G3 left/right-child derivation, ending at
//!    the device-key for the subset-difference's (u, v) pair.
//! 4. Apply AES-G3 once more on the final Device Key to extract its
//!    *Processing Key* `K_p`.
//! 5. The Media Key is then
//!    `K_m = AES-128D(K_p, C) XOR (0^96 || uv)` where `C` is the
//!    16-byte ciphertext from the Media Key Data Record for this
//!    subset-difference.
//!
//! This module exposes each step as a public function so a caller can
//! validate the intermediate Processing Key against a test vector if
//! one becomes available, and to keep the cryptographic primitives
//! decoupled from the MKB I/O.

use crate::aes::{aes_128_ecb_decrypt, BLOCK_SIZE};

/// AACS Triple-AES Generator seed register IV per Common spec §3.2.2
/// Figure 3-3 (`s0 = 7B103C5DCB08C4E51A27B01799053BD9`).
pub const AES_G3_SEED_S0: [u8; 16] = [
    0x7B, 0x10, 0x3C, 0x5D, 0xCB, 0x08, 0xC4, 0xE5, 0x1A, 0x27, 0xB0, 0x17, 0x99, 0x05, 0x3B, 0xD9,
];

/// Output of [`aes_g3`]: the three 128-bit values derived from a
/// single input Device Key.
///
/// Per Common spec §3.2.2 these are interpreted as:
///
/// - `left_child` — the subsidiary Device Key for the left child of
///   the current node (or "ignored if the device key is a leaf").
/// - `processing_key` — the Processing Key associated with the
///   current node's subset-difference (if any).
/// - `right_child` — the subsidiary Device Key for the right child.
///
/// All three are computed as `AES-128D(k, s0 + i) XOR (s0 + i)` for
/// `i = 0, 1, 2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AesG3Output {
    /// Subsidiary Device Key for the left child of the current node.
    pub left_child: [u8; 16],
    /// Processing Key for the current node's subset-difference.
    pub processing_key: [u8; 16],
    /// Subsidiary Device Key for the right child of the current node.
    pub right_child: [u8; 16],
}

/// AACS Triple-AES Generator (`AES-G3`) per Common spec §3.2.2,
/// Figure 3-3.
///
/// `seed_register` starts at [`AES_G3_SEED_S0`] for the canonical
/// generator; tests can supply other seeds.
pub fn aes_g3(device_key: &[u8; 16]) -> AesG3Output {
    aes_g3_with_seed(device_key, &AES_G3_SEED_S0)
}

/// `aes_g3` with a caller-supplied seed (used internally by
/// [`aes_g3`] and exposed for the test crate).
pub fn aes_g3_with_seed(device_key: &[u8; 16], seed: &[u8; 16]) -> AesG3Output {
    let outs = [
        aes_g3_step(device_key, seed, 0),
        aes_g3_step(device_key, seed, 1),
        aes_g3_step(device_key, seed, 2),
    ];
    AesG3Output {
        left_child: outs[0],
        processing_key: outs[1],
        right_child: outs[2],
    }
}

/// One step of the Triple-AES Generator: take the seed register
/// incremented by `i`, decrypt it under the Device Key, then XOR the
/// (incremented) seed back in. Spec §3.2.2, Figure 3-3.
///
/// The "seed register is incremented by one each time" in the figure
/// is interpreted (per the text following) as treating the seed
/// register as a 128-bit big-endian integer and adding `i`.
fn aes_g3_step(key: &[u8; 16], seed: &[u8; 16], i: u8) -> [u8; 16] {
    let mut s = *seed;
    add_be_u128(&mut s, i as u128);
    let d = aes_128_ecb_decrypt(key, &s);
    let mut out = [0u8; 16];
    for j in 0..BLOCK_SIZE {
        out[j] = d[j] ^ s[j];
    }
    out
}

/// Treat `buf` as a 128-bit big-endian unsigned integer and add
/// `addend` (wrapping). The seed register is only ever incremented by
/// 0, 1, or 2 in the AACS pipeline so we never overflow in practice.
fn add_be_u128(buf: &mut [u8; 16], addend: u128) {
    let cur = u128::from_be_bytes(*buf);
    let new = cur.wrapping_add(addend);
    *buf = new.to_be_bytes();
}

/// A parsed Explicit-Subset-Difference entry per Common spec §3.2.5.1.5,
/// i.e. one row of the Explicit-Subset-Difference Record. The `u_mask`
/// is the first byte (number of low-order zero bits in the full
/// 32-bit `m_u`); `uv` is the 32-bit `uv` number itself.
///
/// The `v_mask` is *derived* from `uv` per Common spec §3.2.3 (the
/// `while ((uv & ~v_mask) == 0) v_mask <<= 1` C snippet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubsetDifference {
    /// Number of trailing zero bits in the 32-bit `m_u` mask — i.e.
    /// `m_u = 0xFFFFFFFF << u_mask_zero_bits`.
    pub u_mask_zero_bits: u8,
    /// The 32-bit `uv` number itself.
    pub uv: u32,
}

impl SubsetDifference {
    /// Expand `u_mask_zero_bits` into the full 32-bit `m_u`.
    pub fn u_mask(&self) -> u32 {
        if self.u_mask_zero_bits == 0 {
            0xFFFF_FFFF
        } else if self.u_mask_zero_bits >= 32 {
            0
        } else {
            0xFFFF_FFFFu32 << self.u_mask_zero_bits
        }
    }

    /// Derive `m_v` from `uv` per Common spec §3.2.3 ("the mask for v
    /// is given by the first lower-order 1-bit in the uv number.
    /// **That bit, and all lower-order 0-bits, are zero bits in the
    /// 'v' mask.**"). The spec's reference C code is:
    ///
    /// ```c
    /// long v_mask = 0xFFFFFFFF;
    /// while ((uv & ~v_mask) == 0) v_mask <<= 1;
    /// ```
    ///
    /// i.e. the zero region of `m_v` is `trailing_zeros(uv) + 1` bits
    /// wide — the lowest-order 1-bit AND every 0-bit below it.
    pub fn v_mask(&self) -> u32 {
        if self.uv == 0 {
            // All "don't care" — degenerate but well-defined.
            0
        } else {
            let zero_bits = self.uv.trailing_zeros() + 1;
            if zero_bits >= 32 {
                0
            } else {
                u32::MAX << zero_bits
            }
        }
    }
}

/// Test whether the subset-difference `sd` covers the device whose
/// 32-bit `D_node` is given, per Common spec §3.2.4:
///
/// `((D_node & m_u) == (uv & m_u)) && ((D_node & m_v) != (uv & m_v))`.
pub fn applies_to_device(sd: &SubsetDifference, d_node: u32) -> bool {
    let m_u = sd.u_mask();
    let m_v = sd.v_mask();
    ((d_node & m_u) == (sd.uv & m_u)) && ((d_node & m_v) != (sd.uv & m_v))
}

/// Walk down the Subset-Difference tree from a stored Device Key to
/// the Processing Key for a target subset-difference, per Common spec
/// §3.2.4 "the device does that as follows: …".
///
/// Inputs:
///
/// - `stored_device_key`: the 128-bit Device Key in the device's set
///   that matched the target subset-difference's `m_u` half.
/// - `stored_uv`: the `uv` number of `stored_device_key` (i.e. the
///   node it sits at in the tree).
/// - `stored_v_mask_zero_bits`: trailing zero bits of the stored
///   key's `v` mask.
/// - `target_uv`: the `uv` of the target subset-difference (the
///   Explicit-Subset-Difference Record entry).
/// - `target_v_mask_zero_bits`: trailing zero bits of the target
///   subset-difference's `v` mask.
///
/// Returns the Processing Key for the target subset-difference, or
/// `None` if `stored_v_mask_zero_bits == target_v_mask_zero_bits`
/// (which means `stored_device_key` is *itself* the final key — in
/// that case the caller should just call [`aes_g3`] on it and take
/// `processing_key`).
pub fn derive_processing_key(
    stored_device_key: &[u8; 16],
    stored_uv: u32,
    stored_v_mask_zero_bits: u8,
    target_uv: u32,
    target_v_mask_zero_bits: u8,
) -> Option<[u8; 16]> {
    if stored_v_mask_zero_bits == target_v_mask_zero_bits {
        // The stored key IS the final Device Key. Per spec §3.2.4:
        // "If m'_v equals m_v, the starting Device Key is the final
        // Device Key, and is used directly to derive the Processing
        // Key, as described above."
        return Some(aes_g3(stored_device_key).processing_key);
    }
    // Walk down: for each level, the bit *just above* the current
    // m_v zero count tells us which child to take.
    let mut d_k = *stored_device_key;
    let mut m_zeros = stored_v_mask_zero_bits;
    let _ = stored_uv; // not needed for the walk — only target_uv matters
    while m_zeros > target_v_mask_zero_bits {
        // Inspect the bit in `target_uv` at position (m_zeros - 1).
        let bit_pos = m_zeros - 1;
        let bit = (target_uv >> bit_pos) & 1;
        let triple = aes_g3(&d_k);
        d_k = if bit == 0 {
            triple.left_child
        } else {
            triple.right_child
        };
        m_zeros -= 1;
    }
    Some(aes_g3(&d_k).processing_key)
}

/// Recover the Media Key from a Processing Key + the subset-
/// difference's `uv` + the matching 16-byte Media-Key-Data entry, per
/// Common spec §3.2.4 end:
///
/// `K_m = AES-128D(K_p, C) XOR (0^96 || uv)`
///
/// where `uv` is interpreted as a 32-bit big-endian value left-padded
/// with 12 zero bytes.
///
/// **Note on MKB type**: for a Type-3 MKB this returns the actual
/// Media Key `K_m`. For a Type-4 MKB the same calculation yields the
/// Media Key *Precursor* `K_mp`, which the device must then post-
/// process with the disc's Key Conversion Data via
/// [`apply_key_conversion_data`] to obtain `K_m`. Common spec
/// §3.2.5.1.4 and BD-Prerecorded §3.8.
pub fn media_key_from_processing_key(
    processing_key: &[u8; 16],
    target_uv: u32,
    encrypted_media_key: &[u8; 16],
) -> [u8; 16] {
    let mut d = aes_128_ecb_decrypt(processing_key, encrypted_media_key);
    let uv_be = target_uv.to_be_bytes();
    // XOR the 4-byte uv into the *last 4 bytes* of d (since the
    // padding is "0^96 || uv" — 96 leading zero bits then the 32-bit
    // uv).
    d[12] ^= uv_be[0];
    d[13] ^= uv_be[1];
    d[14] ^= uv_be[2];
    d[15] ^= uv_be[3];
    d
}

/// Apply Key Conversion Data to a Media Key Precursor to obtain the
/// Media Key, per AACS Common spec §3.2.5.1.4 and BD-Prerecorded
/// spec §3.8:
///
/// ```text
/// K_m = AES-G(K_mp, KCD)
/// ```
///
/// For Type-4 MKBs (`MKBType = 0x0004_1003`), the subset-difference
/// tree walk yields a Media Key Precursor `K_mp` rather than the
/// Media Key directly. Devices that are required to use KCD (per the
/// AACS Compliance Rules — broadly, non-PC Licensed Players without
/// proactive renewal) combine the precursor with the disc's KCD
/// payload to obtain `K_m`.
///
/// The 16-byte `kcd` parameter corresponds to the payload of the
/// BD-ROM "KCD-Mark" (BD-Prerecorded Table 3-11), which a device
/// reads via an out-of-band mechanism not described in the public
/// spec set. In `oxideav-aacs` the KCD is supplied externally — most
/// commonly via the `| KCD |` row of a `KEYDB.cfg` file, surfaced as
/// [`crate::keydb::DiscRecords::kcd`].
///
/// **Important "old MKB" rule** (Common spec §3.2.5.1.4 final
/// paragraph): a device that normally uses KCD must NOT apply it if
/// the precursor already verifies as the Media Key. Callers that
/// don't know the MKB type in advance should call
/// [`Mkb::verify_media_key`](crate::mkb::Mkb::verify_media_key) on
/// the precursor first, and only invoke `apply_key_conversion_data`
/// when verification fails.
pub fn apply_key_conversion_data(media_key_precursor: &[u8; 16], kcd: &[u8; 16]) -> [u8; 16] {
    crate::aes::aes_g(media_key_precursor, kcd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_g3_outputs_are_distinct() {
        let dk = [0x55u8; 16];
        let triple = aes_g3(&dk);
        assert_ne!(triple.left_child, triple.processing_key);
        assert_ne!(triple.processing_key, triple.right_child);
        assert_ne!(triple.left_child, triple.right_child);
    }

    #[test]
    fn u_mask_expansion() {
        let sd = SubsetDifference {
            u_mask_zero_bits: 0x01,
            uv: 0x1234_5678,
        };
        assert_eq!(sd.u_mask(), 0xFFFF_FFFE);
        let sd = SubsetDifference {
            u_mask_zero_bits: 0x0A,
            uv: 0,
        };
        assert_eq!(sd.u_mask(), 0xFFFF_FC00);
    }

    #[test]
    fn v_mask_from_uv() {
        // Per Common spec §3.2.3, zero bits in m_v include the lowest
        // 1-bit AND all 0-bits below it. The spec's reference C is
        //   `while ((uv & ~v_mask) == 0) v_mask <<= 1;`
        // — for `uv = 0x10` that means trailing_zeros(4) + 1 = 5 zero
        // bits and `m_v = 0xFFFF_FFE0`.
        let sd = SubsetDifference {
            u_mask_zero_bits: 0,
            uv: 0x0000_0010,
        };
        assert_eq!(sd.v_mask(), 0xFFFF_FFE0);
        // uv with low bit at position 0 -> 1 zero bit -> m_v = 0xFFFFFFFE
        let sd = SubsetDifference {
            u_mask_zero_bits: 0,
            uv: 0x0000_0001,
        };
        assert_eq!(sd.v_mask(), 0xFFFF_FFFE);
        // uv = 0 is degenerate (no 1-bit) -> m_v = 0
        let sd = SubsetDifference {
            u_mask_zero_bits: 0,
            uv: 0,
        };
        assert_eq!(sd.v_mask(), 0);
    }

    #[test]
    fn applies_to_device_basic() {
        // Pick a subset-difference where m_u spans 1 byte but m_v
        // spans 2 — that gives applies() something meaningful to test
        // (when m_u == m_v every applicable device has identical v
        // halves, so the v-check is trivial).
        //
        // uv = 0x1101_0000 -> low bit at position 16 -> 17 zero bits
        // (bit 16 + bits 0..15) -> m_v = 0xFFFE_0000.
        // u_mask_zero_bits = 24 -> m_u = 0xFF00_0000.
        let sd = SubsetDifference {
            u_mask_zero_bits: 24,
            uv: 0x1101_0000,
        };
        assert_eq!(sd.u_mask(), 0xFF00_0000);
        assert_eq!(sd.v_mask(), 0xFFFE_0000);

        // Device 0x1102_0000: D&m_u = 0x1100_0000 = uv&m_u (OK);
        //                     D&m_v = 0x1102_0000 & 0xFFFE_0000 = 0x1102_0000,
        //                     uv&m_v = 0x1101_0000 & 0xFFFE_0000 = 0x1100_0000;
        //                     -> applies = true.
        assert!(applies_to_device(&sd, 0x1102_0000));
        // Device 0x1101_FFFF: D&m_v = 0x1100_0000 == uv&m_v -> false.
        assert!(!applies_to_device(&sd, 0x1101_FFFF));
        // Device 0x2200_0000: D&m_u = 0x2200_0000 != uv&m_u -> false.
        assert!(!applies_to_device(&sd, 0x2200_0000));
    }

    #[test]
    fn media_key_xor_lower_4_bytes() {
        // With uv = 0 the XOR contributes nothing, so K_m must equal
        // AES-128D(K_p, C).
        let kp = [0x42u8; 16];
        let c = [0xAAu8; 16];
        let km = media_key_from_processing_key(&kp, 0, &c);
        assert_eq!(km, aes_128_ecb_decrypt(&kp, &c));
        // With uv != 0 the lower 4 bytes flip:
        let km2 = media_key_from_processing_key(&kp, 0xDEAD_BEEF, &c);
        let mut expected = aes_128_ecb_decrypt(&kp, &c);
        expected[12] ^= 0xDE;
        expected[13] ^= 0xAD;
        expected[14] ^= 0xBE;
        expected[15] ^= 0xEF;
        assert_eq!(km2, expected);
    }

    /// Common spec §3.2.5.1.4 / BD-Prerecorded §3.8 define KCD post-
    /// processing as `K_m = AES-G(K_mp, KCD)`. The helper must be
    /// exactly equal to the public [`crate::aes::aes_g`] primitive.
    #[test]
    fn apply_kcd_equals_aes_g() {
        let kmp = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let kcd = [
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xF0, 0x0D, 0xFA, 0xCE, 0x12, 0x34,
            0x56, 0x78,
        ];
        let km_direct = crate::aes::aes_g(&kmp, &kcd);
        let km_helper = apply_key_conversion_data(&kmp, &kcd);
        assert_eq!(
            km_helper, km_direct,
            "apply_key_conversion_data must be aes_g(kmp, kcd)"
        );
    }

    /// Idempotence-style sanity check: zero KCD with the AES-G
    /// definition is still meaningful (it's `AES-128D(kmp, 0) XOR 0`).
    /// Just pin that two distinct KCDs produce two distinct media
    /// keys, so a future refactor that accidentally ignored `kcd`
    /// would fail.
    #[test]
    fn apply_kcd_distinguishes_distinct_kcds() {
        let kmp = [0x55u8; 16];
        let a = apply_key_conversion_data(&kmp, &[0x00u8; 16]);
        let b = apply_key_conversion_data(&kmp, &[0xFFu8; 16]);
        assert_ne!(a, b, "different KCDs must yield different Media Keys");
    }
}
