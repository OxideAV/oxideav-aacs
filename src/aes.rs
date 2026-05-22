//! AES-based cryptographic primitives used by AACS.
//!
//! All of these are defined in the AACS *Common* spec Chapter 2:
//!
//! - [`aes_128_ecb_encrypt`] / [`aes_128_ecb_decrypt`] (§2.1.1)
//! - [`aes_128_cbc_encrypt`] / [`aes_128_cbc_decrypt`] (§2.1.2)
//! - [`aes_g`] (§2.1.3, Figure 2-1) — `AES-G(x1, x2) = AES-128D(x1, x2) XOR x2`
//! - [`aes_h`] (§2.1.4, Figure 2-2) — SHA-1-style padded AES-G hash
//!
//! The default IV for AES-128-CBC is [`IV0_AACS`]
//! (`0BA0F8DDFEA61FB3D8DF9F566A050F78`) per §2.1.2; the AES-H seed is
//! [`H0_AACS`] (`2DC2DF39420321D0CEF1FE2374029D95`) per §2.1.4.

use ::aes::cipher::generic_array::GenericArray;
use ::aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use ::aes::Aes128;

/// AES-128 block size (and AACS-Common key size).
pub const BLOCK_SIZE: usize = 16;

/// Default Initialization Vector for AES-128-CBC per AACS Common spec
/// §2.1.2 (`0BA0F8DDFEA61FB3D8DF9F566A050F78`). Format-specific books
/// (e.g. BD-Prerecorded §3.10 — content scrambling) refer back to this
/// constant rather than defining their own.
pub const IV0_AACS: [u8; 16] = [
    0x0B, 0xA0, 0xF8, 0xDD, 0xFE, 0xA6, 0x1F, 0xB3, 0xD8, 0xDF, 0x9F, 0x56, 0x6A, 0x05, 0x0F, 0x78,
];

/// Initial hash value for AES-H per AACS Common spec §2.1.4
/// (`2DC2DF39420321D0CEF1FE2374029D95`).
pub const H0_AACS: [u8; 16] = [
    0x2D, 0xC2, 0xDF, 0x39, 0x42, 0x03, 0x21, 0xD0, 0xCE, 0xF1, 0xFE, 0x23, 0x74, 0x02, 0x9D, 0x95,
];

/// AES-128 ECB encryption of a single 16-byte block (`AES-128E(k, d)`
/// per §2.1.1).
pub fn aes_128_ecb_encrypt(key: &[u8; 16], data: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut out = *data;
    cipher.encrypt_block(GenericArray::from_mut_slice(&mut out));
    out
}

/// AES-128 ECB decryption of a single 16-byte block (`AES-128D(k, d)`
/// per §2.1.1).
pub fn aes_128_ecb_decrypt(key: &[u8; 16], data: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut out = *data;
    cipher.decrypt_block(GenericArray::from_mut_slice(&mut out));
    out
}

/// AES-128 CBC encryption of a buffer whose length is a multiple of
/// 16 bytes (`AES-128CBCE(k, d)` per §2.1.2). Panics if the buffer is
/// not a multiple of [`BLOCK_SIZE`].
pub fn aes_128_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    assert!(
        data.len() % BLOCK_SIZE == 0,
        "AES-128-CBC requires data length multiple of 16; got {}",
        data.len()
    );
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut out = Vec::with_capacity(data.len());
    let mut prev = *iv;
    for chunk in data.chunks_exact(BLOCK_SIZE) {
        let mut block = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            block[i] = chunk[i] ^ prev[i];
        }
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));
        out.extend_from_slice(&block);
        prev = block;
    }
    out
}

/// AES-128 CBC decryption of a buffer whose length is a multiple of
/// 16 bytes (`AES-128CBCD(k, d)` per §2.1.2). Panics if the buffer is
/// not a multiple of [`BLOCK_SIZE`].
pub fn aes_128_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    assert!(
        data.len() % BLOCK_SIZE == 0,
        "AES-128-CBC requires data length multiple of 16; got {}",
        data.len()
    );
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut out = Vec::with_capacity(data.len());
    let mut prev = *iv;
    for chunk in data.chunks_exact(BLOCK_SIZE) {
        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(chunk);
        let ct = block;
        cipher.decrypt_block(GenericArray::from_mut_slice(&mut block));
        for i in 0..BLOCK_SIZE {
            block[i] ^= prev[i];
        }
        out.extend_from_slice(&block);
        prev = ct;
    }
    out
}

/// AACS *Common* one-way function `AES-G` per spec §2.1.3, Figure 2-1:
/// `AES-G(x1, x2) = AES-128D(x1, x2) XOR x2`.
///
/// Used pervasively in the spec to derive child keys (e.g.
/// `K_vu = AES-G(K_m, ID_v)`).
pub fn aes_g(x1: &[u8; 16], x2: &[u8; 16]) -> [u8; 16] {
    let mut out = aes_128_ecb_decrypt(x1, x2);
    for i in 0..16 {
        out[i] ^= x2[i];
    }
    out
}

/// AACS *Common* hash function `AES-H` per spec §2.1.4, Figure 2-2.
///
/// Procedure:
/// 1. Pad the input with SHA-1-style padding (`0x80` then enough
///    `0x00` to bring the length, including the appended 64-bit
///    big-endian bit-length, to a multiple of 128 bits).
/// 2. Iterate `h_i = AES-G(x'_i, h_{i-1})` starting from
///    [`H0_AACS`].
/// 3. Return the final `h_n`.
pub fn aes_h(data: &[u8]) -> [u8; 16] {
    let bit_len: u64 = (data.len() as u64) * 8;
    // SHA-1 / AES-H padding: append 0x80, then 0x00s so that the total
    // length (including the trailing 8-byte big-endian bit-length) is
    // a multiple of 16 bytes.
    let mut padded = Vec::with_capacity(data.len() + 16 + 8);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() + 8) % 16 != 0 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut h = H0_AACS;
    for chunk in padded.chunks_exact(16) {
        let mut x = [0u8; 16];
        x.copy_from_slice(chunk);
        h = aes_g(&x, &h);
    }
    h
}

/// AES-128-CMAC per NIST SP 800-38B, used by AACS Common §2.1.6 as the
/// `CMAC(k, D)` message-authentication function. Returns the full
/// 128-bit MAC (the spec uses the complete 16-byte output).
///
/// The subkey-generation step left-shifts `L = AES-128E(k, 0^128)` by
/// one bit (with the `Rb = 0x87` reduction for AES's 128-bit block) to
/// derive `K1`, and again for `K2`, exactly as SP 800-38B §6.1.
pub fn aes_128_cmac(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    // Subkey generation.
    let l = aes_128_ecb_encrypt(key, &[0u8; 16]);
    let k1 = cmac_subkey(&l);
    let k2 = cmac_subkey(&k1);

    let n_blocks = data.len().div_ceil(BLOCK_SIZE);
    // SP 800-38B: an empty message uses a single padded block.
    let (n_blocks, complete_last) = if n_blocks == 0 {
        (1, false)
    } else {
        (n_blocks, data.len() % BLOCK_SIZE == 0)
    };

    // Last block: M_n XOR K1 (complete) or pad(M_n) XOR K2 (partial).
    let mut last = [0u8; 16];
    let last_start = (n_blocks - 1) * BLOCK_SIZE;
    let tail = &data[last_start..];
    if complete_last {
        last.copy_from_slice(tail);
        for i in 0..16 {
            last[i] ^= k1[i];
        }
    } else {
        last[..tail.len()].copy_from_slice(tail);
        last[tail.len()] = 0x80;
        for i in 0..16 {
            last[i] ^= k2[i];
        }
    }

    let mut x = [0u8; 16];
    for blk in 0..n_blocks - 1 {
        let chunk = &data[blk * BLOCK_SIZE..(blk + 1) * BLOCK_SIZE];
        for i in 0..16 {
            x[i] ^= chunk[i];
        }
        x = aes_128_ecb_encrypt(key, &x);
    }
    for i in 0..16 {
        x[i] ^= last[i];
    }
    aes_128_ecb_encrypt(key, &x)
}

/// CMAC subkey derivation: left-shift `input` by one bit, conditionally
/// XOR with `Rb = 0x...87` when the high bit was set (SP 800-38B §6.1).
fn cmac_subkey(input: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut carry = 0u8;
    for i in (0..16).rev() {
        out[i] = (input[i] << 1) | carry;
        carry = input[i] >> 7;
    }
    if input[0] & 0x80 != 0 {
        out[15] ^= 0x87;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecb_roundtrips() {
        let key = [0x42u8; 16];
        let pt = [0x11u8; 16];
        let ct = aes_128_ecb_encrypt(&key, &pt);
        let rt = aes_128_ecb_decrypt(&key, &ct);
        assert_eq!(rt, pt);
        assert_ne!(ct, pt);
    }

    #[test]
    fn cbc_roundtrips_with_iv0() {
        let key = [0x77u8; 16];
        let pt: Vec<u8> = (0..64u8).collect();
        let ct = aes_128_cbc_encrypt(&key, &IV0_AACS, &pt);
        let rt = aes_128_cbc_decrypt(&key, &IV0_AACS, &ct);
        assert_eq!(rt, pt);
        assert_ne!(ct, pt);
    }

    #[test]
    fn aes_g_is_inverse_xor_of_aes_128d() {
        // Direct check against the spec equation:
        // AES-G(x1, x2) == AES-128D(x1, x2) XOR x2.
        let x1 = [0x33u8; 16];
        let x2 = [0xa5u8; 16];
        let d = aes_128_ecb_decrypt(&x1, &x2);
        let mut expected = [0u8; 16];
        for i in 0..16 {
            expected[i] = d[i] ^ x2[i];
        }
        assert_eq!(aes_g(&x1, &x2), expected);
    }

    #[test]
    fn aes_h_is_deterministic_and_distinguishes_inputs() {
        let a = aes_h(b"hello");
        let b = aes_h(b"hello");
        let c = aes_h(b"world");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn aes_h_empty_message_does_not_panic() {
        let _ = aes_h(b"");
    }

    // NIST SP 800-38B, Appendix D.1 (AES-128) published example vectors.
    // These are the standard's own worked examples — the same key and
    // messages that define the algorithm — not values copied from any
    // implementation.
    const CMAC_KEY: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    const CMAC_MSG: [u8; 64] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
        0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a,
        0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b,
        0xe6, 0x6c, 0x37, 0x10,
    ];

    #[test]
    fn cmac_nist_empty_example() {
        // Example 1: Mlen = 0 → T = bb1d6929 e9593728 7fa37d12 9b756746.
        let mac = aes_128_cmac(&CMAC_KEY, &[]);
        assert_eq!(
            mac,
            [
                0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75,
                0x67, 0x46
            ]
        );
    }

    #[test]
    fn cmac_nist_one_block_example() {
        // Example 2: Mlen = 128 → T = 070a16b4 6b4d4144 f79bdd9d d04a287c.
        let mac = aes_128_cmac(&CMAC_KEY, &CMAC_MSG[..16]);
        assert_eq!(
            mac,
            [
                0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a,
                0x28, 0x7c
            ]
        );
    }

    #[test]
    fn cmac_nist_partial_block_example() {
        // Example 3: Mlen = 320 → T = dfa66747 de9ae630 30ca3261 1497c827.
        let mac = aes_128_cmac(&CMAC_KEY, &CMAC_MSG[..40]);
        assert_eq!(
            mac,
            [
                0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30, 0x30, 0xca, 0x32, 0x61, 0x14, 0x97,
                0xc8, 0x27
            ]
        );
    }

    #[test]
    fn cmac_nist_full_message_example() {
        // Example 4: Mlen = 512 → T = 51f0bebf 7e3b9d92 fc497417 79363cfe.
        let mac = aes_128_cmac(&CMAC_KEY, &CMAC_MSG);
        assert_eq!(
            mac,
            [
                0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92, 0xfc, 0x49, 0x74, 0x17, 0x79, 0x36,
                0x3c, 0xfe
            ]
        );
    }
}
