//! Volume Unique Key derivation per BD-Prerecorded spec §3.3.
//!
//! `K_vu = AES-G(K_m, ID_v)`.

use crate::aes::aes_g;

/// A 128-bit Volume Unique Key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vuk(pub [u8; 16]);

impl Vuk {
    /// Construct a VUK from raw 16-byte material (e.g. from KEYDB.cfg).
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying 16-byte buffer.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Derive `K_vu` from Media Key + Volume ID per BD-Prerecorded spec
/// §3.3: `K_vu = AES-G(K_m, ID_v)`.
pub fn derive_vuk(media_key: &[u8; 16], volume_id: &[u8; 16]) -> Vuk {
    Vuk(aes_g(media_key, volume_id))
}

/// Derive the 20-byte KEYDB.cfg disc identifier from the 16-byte AACS
/// Volume Identifier per the de-facto libbluray convention:
///
/// ```text
/// disc_id = SHA-1(volume_id)
/// ```
///
/// AACS LA itself doesn't define a "disc_id" — that concept is a
/// libbluray invention for keying off-line VUK databases. Every
/// KEYDB.cfg in the wild uses SHA-1 of the 16-byte Volume Identifier
/// read from the disc's BD-ROM Mark via the drive's MMC `READ DISC
/// STRUCTURE` (format 0x80) command.
pub fn disc_id_for_volume_id(volume_id: &[u8; 16]) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(volume_id);
    let d = h.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&d);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vuk_derivation_is_deterministic() {
        let km = [0xAAu8; 16];
        let idv = [0x55u8; 16];
        let a = derive_vuk(&km, &idv);
        let b = derive_vuk(&km, &idv);
        assert_eq!(a, b);
    }

    #[test]
    fn different_media_keys_yield_different_vuks() {
        let km1 = [0x01u8; 16];
        let km2 = [0x02u8; 16];
        let idv = [0xFFu8; 16];
        assert_ne!(derive_vuk(&km1, &idv), derive_vuk(&km2, &idv));
    }
}
