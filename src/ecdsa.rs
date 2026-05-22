//! Phase C — ECDSA over the AACS 160-bit curve (`AACS_Sign` /
//! `AACS_Verify`).
//!
//! AACS Common Final 0.953 §2.3 specifies that "all digital signatures
//! in AACS utilize the ECDSA digital signature scheme defined in
//! [ANSI X9.62 / FIPS 186-2]" over the curve in Table 2-1, and §2.1.5
//! fixes the message digest to **SHA-1** (FIPS 180-2). The two
//! signing/verification functions the rest of the spec references are
//!
//! ```text
//!   S = AACS_Sign(Kpriv, D)
//!   AACS_Verify(Kpub, S, D)
//! ```
//!
//! On the wire (§4.3 Tables 4-9 / 4-25) a signature `S` is the 40-byte
//! concatenation `r(20) || s(20)`, each component a 20-byte big-endian
//! integer mod the group order `n`.
//!
//! This is a **clean-room** implementation derived from the textbook
//! ECDSA equations (X9.62 §7.3 sign / §7.4 verify); no external crypto
//! library source was consulted. The deterministic-`k` helper below is
//! *not* RFC 6979 — it is a self-contained SHA-1-based derivation used
//! only so the synthetic test handshake is reproducible. A real Licensed
//! Drive / Host uses the §2.2 RNG for `k`; AACS verification is
//! `k`-agnostic.

use crate::aes::aes_h;
use crate::ec::{
    scalar_add, scalar_inv, scalar_mul, scalar_reduce, scalar_reduce_wide, Point, N, U160,
};

/// SHA-1 digest length in bytes (the AACS ECDSA hash, §2.1.5).
pub const SHA1_LEN: usize = 20;

/// A 40-byte ECDSA signature `r(20) || s(20)` big-endian.
pub type Signature = [u8; 40];

// ---------------------------------------------------------------------
// SHA-1 (FIPS 180-2) — the AACS ECDSA message digest (§2.1.5)
// ---------------------------------------------------------------------

/// Compute the SHA-1 digest of `data` per FIPS 180-2 / RFC 3174. A
/// straightforward clean-room transcription of the published algorithm
/// (the same well-known 80-round compression function in the FIPS
/// standard text); used solely as the ECDSA message hash.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([
                block[4 * i],
                block[4 * i + 1],
                block[4 * i + 2],
                block[4 * i + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Fold a 20-byte SHA-1 digest into a scalar `e` mod `n`. The group
/// order `n` is 160 bits, so the full digest is used (X9.62 §7.3 takes
/// the leftmost `min(N_bits, hashlen)` bits — both 160 here).
fn digest_to_scalar(digest: &[u8; 20]) -> U160 {
    scalar_reduce(U160::from_be_bytes(digest))
}

// ---------------------------------------------------------------------
// AACS_Sign / AACS_Verify
// ---------------------------------------------------------------------

/// `AACS_Sign(Kpriv, D)` — sign message `data` with private scalar
/// `priv_key` using the per-signature secret `k`. Returns the 40-byte
/// `r || s` signature. `k` and `priv_key` must be in `(0, n)`.
///
/// Retries the caller's `k` deterministically (folding in a counter)
/// only if it produces a degenerate `r == 0` or `s == 0`, which is
/// astronomically unlikely for this curve but handled for completeness
/// per X9.62 §7.3.
pub fn sign_with_k(priv_key: &U160, data: &[u8], k: &U160) -> Option<Signature> {
    let e = digest_to_scalar(&sha1(data));
    let mut k = scalar_reduce(*k);
    for attempt in 0..8u8 {
        if k.is_zero() {
            k = rederive_k(&k, attempt);
            continue;
        }
        // R = k·G ; r = R.x mod n
        let r_point = Point::generator().mul_scalar(&k);
        if r_point.is_infinity() {
            k = rederive_k(&k, attempt);
            continue;
        }
        let r = scalar_reduce(r_point.x_u160());
        if r.is_zero() {
            k = rederive_k(&k, attempt);
            continue;
        }
        // s = k^{-1} · (e + r·d) mod n
        let kinv = scalar_inv(&k);
        let rd = scalar_mul(&r, priv_key);
        let s = scalar_mul(&kinv, &scalar_add(&e, &rd));
        if s.is_zero() {
            k = rederive_k(&k, attempt);
            continue;
        }
        let mut sig = [0u8; 40];
        sig[..20].copy_from_slice(&r.to_be_bytes());
        sig[20..].copy_from_slice(&s.to_be_bytes());
        return Some(sig);
    }
    None
}

/// Deterministic clean-room `k` derivation for the synthetic test
/// handshake (NOT RFC 6979 — see module docs). `k = AES-H(priv || data
/// || counter) mod n`, retried until non-zero. A real device draws `k`
/// from the §2.2 RNG.
pub fn derive_k(priv_key: &U160, data: &[u8]) -> U160 {
    let mut counter = 0u8;
    loop {
        let mut buf = Vec::with_capacity(20 + data.len() + 1);
        buf.extend_from_slice(&priv_key.to_be_bytes());
        buf.extend_from_slice(data);
        buf.push(counter);
        let h = aes_h(&buf);
        // Expand the 128-bit AES-H output into a 160-bit candidate by
        // appending the first 4 bytes of SHA-1 of it, then reduce mod n.
        let extra = sha1(&h);
        let mut wide = [0u8; 20];
        wide[..16].copy_from_slice(&h);
        wide[16..].copy_from_slice(&extra[..4]);
        let k = scalar_reduce(U160::from_be_bytes(&wide));
        if !k.is_zero() {
            return k;
        }
        counter = counter.wrapping_add(1);
    }
}

/// Re-derive `k` on a degenerate retry by folding in the attempt index.
fn rederive_k(prev: &U160, attempt: u8) -> U160 {
    let mut buf = Vec::with_capacity(21);
    buf.extend_from_slice(&prev.to_be_bytes());
    buf.push(attempt.wrapping_add(1));
    let h = aes_h(&buf);
    let extra = sha1(&h);
    let mut wide = [0u8; 20];
    wide[..16].copy_from_slice(&h);
    wide[16..].copy_from_slice(&extra[..4]);
    scalar_reduce(U160::from_be_bytes(&wide))
}

/// `AACS_Sign(Kpriv, D)` with a deterministic `k` (test convenience).
pub fn sign(priv_key: &U160, data: &[u8]) -> Signature {
    let k = derive_k(priv_key, data);
    // derive_k never yields a zero k; retries inside cover degeneracy.
    sign_with_k(priv_key, data, &k).expect("ECDSA sign retries exhausted")
}

/// `AACS_Verify(Kpub, S, D)` — verify the 40-byte signature `sig` over
/// `data` against public point `pub_key`. Returns `true` iff valid
/// (X9.62 §7.4).
pub fn verify(pub_key: &Point, sig: &Signature, data: &[u8]) -> bool {
    let mut r_bytes = [0u8; 20];
    let mut s_bytes = [0u8; 20];
    r_bytes.copy_from_slice(&sig[..20]);
    s_bytes.copy_from_slice(&sig[20..]);
    let r = U160::from_be_bytes(&r_bytes);
    let s = U160::from_be_bytes(&s_bytes);

    // 1. r, s must be in [1, n-1].
    if r.is_zero() || s.is_zero() {
        return false;
    }
    if r.cmp(&N) != core::cmp::Ordering::Less || s.cmp(&N) != core::cmp::Ordering::Less {
        return false;
    }
    // Public key must be a valid affine curve point.
    if pub_key.is_infinity() || !pub_key.is_on_curve() {
        return false;
    }

    let e = digest_to_scalar(&sha1(data));
    let w = scalar_inv(&s);
    let u1 = scalar_mul(&e, &w);
    let u2 = scalar_mul(&r, &w);
    // X = u1·G + u2·Q
    let x = Point::generator()
        .mul_scalar(&u1)
        .add(&pub_key.mul_scalar(&u2));
    if x.is_infinity() {
        return false;
    }
    let v = scalar_reduce(x.x_u160());
    v == r
}

/// Wide-digest variant used when the caller already holds a 320-bit hash
/// folded into a scalar (kept for parity with the reduction helpers; the
/// AACS path always uses [`sha1`]).
pub fn scalar_from_wide_digest(wide: &[u32; 10]) -> U160 {
    scalar_reduce_wide(wide)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::Point;

    // FIPS 180-2 / RFC 3174 published SHA-1 test vectors.
    #[test]
    fn sha1_abc_vector() {
        assert_eq!(
            sha1(b"abc"),
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
        );
    }

    #[test]
    fn sha1_empty_vector() {
        assert_eq!(
            sha1(b""),
            [
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
                0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
            ]
        );
    }

    #[test]
    fn sha1_two_block_vector() {
        // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(
            sha1(msg),
            [
                0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51,
                0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1
            ]
        );
    }

    fn small_scalar(v: u32) -> U160 {
        U160 {
            limbs: [v, 0, 0, 0, 0],
        }
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let d = small_scalar(0x1357_9bdf);
        let q = Point::generator().mul_scalar(&d);
        let msg = b"AACS drive authentication test message";
        let sig = sign(&d, msg);
        assert!(verify(&q, &sig, msg));
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let d = small_scalar(0x2468_ace0);
        let q = Point::generator().mul_scalar(&d);
        let sig = sign(&d, b"original");
        assert!(!verify(&q, &sig, b"tampered"));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let d = small_scalar(99);
        let other = small_scalar(100);
        let wrong_q = Point::generator().mul_scalar(&other);
        let sig = sign(&d, b"msg");
        assert!(!verify(&wrong_q, &sig, b"msg"));
    }

    #[test]
    fn verify_rejects_zero_components() {
        let d = small_scalar(7);
        let q = Point::generator().mul_scalar(&d);
        let zero_sig = [0u8; 40];
        assert!(!verify(&q, &zero_sig, b"msg"));
    }

    #[test]
    fn explicit_k_matches_textbook_equations() {
        let d = small_scalar(0x0011_2233);
        let q = Point::generator().mul_scalar(&d);
        let k = small_scalar(0x00aa_bbcc);
        let sig = sign_with_k(&d, b"vector", &k).unwrap();
        assert!(verify(&q, &sig, b"vector"));
    }

    /// Cross-check against an independent Python reference (Python
    /// big-int arithmetic over the spec's Table 2-1 decimal parameters
    /// plus the standard `hashlib` SHA-1) for the deterministic vector
    /// `d=0x112233, k=0xaabbcc, msg="vector"`. The expected point `Q`
    /// and the `r`/`s` components were produced by that opaque oracle,
    /// not copied from any crypto library source.
    #[test]
    fn matches_independent_reference_vector() {
        let d = small_scalar(0x0011_2233);
        let k = small_scalar(0x00aa_bbcc);
        let q = Point::generator().mul_scalar(&d);

        // Reference Q coordinates.
        let qx: [u8; 20] = [
            0x74, 0x02, 0x9e, 0x29, 0x07, 0xa5, 0x98, 0x0d, 0x4d, 0x5d, 0x09, 0x11, 0xbc, 0x3c,
            0x6a, 0x6d, 0x5d, 0xe5, 0x94, 0x71,
        ];
        let qy: [u8; 20] = [
            0x5b, 0xde, 0xf9, 0x76, 0xe4, 0xb9, 0xe0, 0xf7, 0xac, 0xbf, 0xf6, 0xed, 0xae, 0x55,
            0xaf, 0x8f, 0x88, 0x80, 0xab, 0x5e,
        ];
        assert_eq!(
            q,
            Point::from_coords(&qx, &qy).expect("reference Q must be on curve")
        );

        // Reference r || s.
        let expected: [u8; 40] = [
            0x27, 0xdd, 0x46, 0xeb, 0x6c, 0x9d, 0x11, 0x39, 0xdf, 0x0f, 0xaa, 0xe2, 0x32, 0xe9,
            0xc1, 0x04, 0x6e, 0xcb, 0x82, 0x4b, 0x81, 0x11, 0x0c, 0x40, 0x4d, 0xe4, 0x59, 0xc5,
            0xcb, 0x6e, 0x43, 0x3e, 0x91, 0x99, 0xb5, 0x9c, 0x3e, 0x1f, 0xe3, 0x2c,
        ];
        let sig = sign_with_k(&d, b"vector", &k).unwrap();
        assert_eq!(sig, expected, "signature must match independent reference");
        assert!(verify(&q, &sig, b"vector"));
    }
}
