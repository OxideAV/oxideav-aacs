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

/// Derive the 20-byte KEYDB.cfg disc identifier from the bytes of the
/// disc's on-disc unit-key file.
///
/// AACS LA itself doesn't define a "disc_id" — that concept is a
/// libbluray / libaacs invention for keying off-line VUK databases.
/// Every KEYDB.cfg in the wild uses SHA-1 of the unit-key file bytes
/// (libaacs's `_calc_title_hash` / `aacs_get_disc_id`):
///
/// ```text
/// disc_id = SHA-1(unit_key_file_bytes)
/// ```
///
/// Which file gets hashed depends on the content type:
///
/// | Content type        | File hashed                    |
/// |---------------------|--------------------------------|
/// | BD-ROM BDMV         | `AACS/Unit_Key_RO.inf`         |
/// | BD-Recordable BDMV  | `AACS_mv/Unit_Key_RW.inf`      |
/// | BD-Recordable BDAV  | `AACS/AACS_av/Unit_Key_RW.inf` |
/// | HD-DVD Std Audio    | `AACS/ATKF.AACS`               |
/// | HD-DVD Std Video    | `AACS/VTKF.AACS`               |
/// | HD-DVD Adv Audio    | `AACS/ATKF000.AACS`            |
/// | HD-DVD Adv Video    | `AACS/VTKF000.AACS`            |
///
/// For BD-ROM the canonical fallback path is `AACS/DUPLICATE/Unit_Key_RO.inf`
/// per BD-Prerecorded §2.1 (the duplicate copy mirror's content).
///
/// Pass the whole file's bytes — no skipping headers, no padding
/// stripped. Libaacs hashes the file verbatim.
pub fn disc_id_from_unit_key_file_bytes(bytes: &[u8]) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(bytes);
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
