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
