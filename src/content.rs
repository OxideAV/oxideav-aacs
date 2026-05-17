//! AACS content scrambling on the Aligned Unit per BD-Prerecorded
//! spec §3.10.
//!
//! An Aligned Unit is exactly **6144 bytes**: 32 MPEG-2 source packets
//! (each `[TP_extra_header: 4B][TS packet: 188B]` = 192 B). Within an
//! Aligned Unit:
//!
//! - The **first 16 bytes** are the cleartext "seed" — used to derive
//!   a per-unit `BlockKey`, but transmitted in the clear.
//! - The remaining **6128 bytes** are AES-128-CBC-encrypted under
//!   `BlockKey` with the AACS default IV ([`crate::aes::IV0_AACS`]).
//!
//! The `BlockKey` is computed per Figure 3-8:
//!
//! `BlockKey = AES-128E(CPSUnitKey, seed) XOR seed`
//!
//! Note: the structure of `BlockKey` calculation is exactly that of
//! AES-G but with AES-128E in place of AES-128D — i.e. it is *not*
//! [`crate::aes::aes_g`].

use crate::aes::{aes_128_cbc_decrypt, aes_128_cbc_encrypt, aes_128_ecb_encrypt, IV0_AACS};
use crate::error::AacsError;

/// Size of an AACS Aligned Unit in bytes (BD-Prerecorded spec §3.10).
pub const ALIGNED_UNIT_SIZE: usize = 6144;

/// Number of cleartext "seed" bytes at the start of each Aligned Unit.
pub const ALIGNED_UNIT_SEED_SIZE: usize = 16;

/// Compute the per-Aligned-Unit `BlockKey` from the CPS Unit Key and
/// the 16-byte seed: `BlockKey = AES-128E(K_cu, seed) XOR seed`
/// (BD-Prerecorded spec §3.10 Figure 3-8).
pub fn derive_block_key(cps_unit_key: &[u8; 16], seed: &[u8; 16]) -> [u8; 16] {
    let mut out = aes_128_ecb_encrypt(cps_unit_key, seed);
    for i in 0..16 {
        out[i] ^= seed[i];
    }
    out
}

/// Decrypt a single 6144-byte AACS Aligned Unit per BD-Prerecorded
/// spec §3.10. Returns a fresh 6144-byte buffer: the first 16 bytes
/// are the original seed (passthrough), the remaining 6128 bytes are
/// the AES-128-CBC plaintext.
pub fn decrypt_aligned_unit(
    cps_unit_key: &[u8; 16],
    unit_bytes: &[u8],
) -> Result<[u8; ALIGNED_UNIT_SIZE], AacsError> {
    if unit_bytes.len() != ALIGNED_UNIT_SIZE {
        return Err(AacsError::BadAlignedUnitLength(unit_bytes.len()));
    }
    let mut seed = [0u8; 16];
    seed.copy_from_slice(&unit_bytes[..ALIGNED_UNIT_SEED_SIZE]);
    let block_key = derive_block_key(cps_unit_key, &seed);
    let pt = aes_128_cbc_decrypt(&block_key, &IV0_AACS, &unit_bytes[ALIGNED_UNIT_SEED_SIZE..]);
    let mut out = [0u8; ALIGNED_UNIT_SIZE];
    out[..ALIGNED_UNIT_SEED_SIZE].copy_from_slice(&seed);
    out[ALIGNED_UNIT_SEED_SIZE..].copy_from_slice(&pt);
    Ok(out)
}

/// Encrypt a 6144-byte plaintext Aligned Unit (passing the 16-byte
/// seed through and AES-128-CBC-encrypting the trailing 6128 bytes
/// under the derived `BlockKey`).
///
/// Provided to support roundtrip tests; not used by the decrypt path.
pub fn encrypt_aligned_unit(
    cps_unit_key: &[u8; 16],
    unit_bytes: &[u8],
) -> Result<[u8; ALIGNED_UNIT_SIZE], AacsError> {
    if unit_bytes.len() != ALIGNED_UNIT_SIZE {
        return Err(AacsError::BadAlignedUnitLength(unit_bytes.len()));
    }
    let mut seed = [0u8; 16];
    seed.copy_from_slice(&unit_bytes[..ALIGNED_UNIT_SEED_SIZE]);
    let block_key = derive_block_key(cps_unit_key, &seed);
    let ct = aes_128_cbc_encrypt(&block_key, &IV0_AACS, &unit_bytes[ALIGNED_UNIT_SEED_SIZE..]);
    let mut out = [0u8; ALIGNED_UNIT_SIZE];
    out[..ALIGNED_UNIT_SEED_SIZE].copy_from_slice(&seed);
    out[ALIGNED_UNIT_SEED_SIZE..].copy_from_slice(&ct);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deterministic_payload(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn aligned_unit_round_trips() {
        let key = [0x33u8; 16];
        let pt = deterministic_payload(ALIGNED_UNIT_SIZE);
        let ct = encrypt_aligned_unit(&key, &pt).unwrap();
        let rt = decrypt_aligned_unit(&key, &ct).unwrap();
        assert_eq!(rt.as_slice(), pt.as_slice());
        // Seed passes through.
        assert_eq!(&ct[..16], &pt[..16]);
        // Body is actually different.
        assert_ne!(&ct[16..], &pt[16..]);
    }

    #[test]
    fn rejects_wrong_size() {
        let key = [0u8; 16];
        let bad = vec![0u8; 1024];
        assert!(matches!(
            decrypt_aligned_unit(&key, &bad),
            Err(AacsError::BadAlignedUnitLength(1024))
        ));
    }

    #[test]
    fn block_key_changes_with_seed() {
        let cuk = [0x77u8; 16];
        let seed_a = [0x00u8; 16];
        let seed_b = [0x01u8; 16];
        assert_ne!(
            derive_block_key(&cuk, &seed_a),
            derive_block_key(&cuk, &seed_b)
        );
    }
}
