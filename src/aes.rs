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
}
