//! Disc-level integration: walk an `AACS/` directory, parse the MKB +
//! Unit_Key_RO.inf, and expose the per-CPS-Unit decryption surface.
//!
//! BD-Prerecorded spec §3.1 + Figure 3-5 fix the directory layout:
//!
//! ```text
//! <disc_root>/
//!   AACS/
//!     MKB_RO.inf
//!     MKB_RW.inf
//!     Unit_Key_RO.inf
//!     Content_Hash_Table_*.inf
//!     Content000.cer
//!     ...
//!     DUPLICATE/
//!       MKB_RO.inf
//!       Unit_Key_RO.inf
//!       (duplicates of the above)
//!   BDMV/
//!     STREAM/
//!       <NNNNN>.m2ts          (encrypted Clip AV streams)
//! ```
//!
//! `DUPLICATE/` holds backup copies. If the primary file cannot be
//! read we fall back to the duplicate per spec ("DUPLICATE directory
//! contains the duplication of CPS information files and is used when
//! these files in `\AACS` directory cannot be read").

use crate::aes::aes_128_ecb_decrypt;
use crate::cht::ContentHashTable;
use crate::content::{decrypt_aligned_unit, ALIGNED_UNIT_SIZE};
use crate::error::AacsError;
use crate::keydb::KeyDb;
use crate::mkb::Mkb;
use crate::unit_key::UnitKeyFile;
use crate::vuk::Vuk;
use std::path::{Path, PathBuf};

/// A 128-bit AACS Device Key — `K_d_i` in the Common spec's notation
/// — together with the metadata required to walk the
/// Subset-Difference tree:
///
/// - `uv` is the 32-bit node-identifier of this device key in the
///   master tree (per Common spec §3.2.3 "the path number and the v
///   mask are encoded in a single 32-bit number, referred to as the
///   uv number").
/// - `u_mask_zero_bits` and `v_mask_zero_bits` are the number of
///   trailing zero bits in the `m_u` / `m_v` masks of this stored
///   key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceKey {
    /// The 128-bit key material.
    pub key: [u8; 16],
    /// 32-bit uv number identifying the device's node in the tree.
    pub uv: u32,
    /// Trailing zero bits in `m_u`.
    pub u_mask_zero_bits: u8,
    /// Trailing zero bits in `m_v`.
    pub v_mask_zero_bits: u8,
}

/// A 128-bit unwrapped CPS Unit Title Key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TitleKey(pub [u8; 16]);

/// One CPS Unit known to a volume: index, encrypted-on-disc title
/// key, and (once [`AacsVolume::unwrap_title_keys`] has been called)
/// the unwrapped title key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpsUnit {
    /// 1-based CPS Unit number on disc.
    pub id: u16,
    /// The on-disc `AES-128E(K_vu, K_cu)` blob from
    /// `Unit_Key_RO.inf`.
    pub encrypted_title_key: [u8; 16],
    /// `Some(K_cu)` once unwrapped; `None` until then.
    pub title_key: Option<TitleKey>,
}

/// A parsed AACS volume — i.e. a disc whose `AACS/` directory has
/// been walked. Holds enough state to decrypt any Aligned Unit
/// belonging to any of its CPS units, once title keys have been
/// unwrapped via VUK.
#[derive(Debug, Clone)]
pub struct AacsVolume {
    /// Parsed `MKB_RO.inf`.
    pub mkb: Mkb,
    /// Parsed `Unit_Key_RO.inf`.
    pub unit_key_file: UnitKeyFile,
    /// Per-CPS-Unit metadata; `title_key` is filled in by
    /// [`Self::unwrap_title_keys`].
    pub cps_units: Vec<CpsUnit>,
    /// The disc-mount root supplied to [`Self::open`], retained so a
    /// caller can resolve clip-AV-stream paths against it.
    pub disc_root: PathBuf,
}

impl AacsVolume {
    /// Open the AACS volume rooted at `disc_root` by parsing
    /// `AACS/MKB_RO.inf` and `AACS/Unit_Key_RO.inf`.
    pub fn open(disc_root: impl AsRef<Path>) -> Result<Self, AacsError> {
        let disc_root = disc_root.as_ref().to_path_buf();
        let mkb_bytes = read_aacs_file(&disc_root, "MKB_RO.inf")?;
        let unit_key_bytes = read_aacs_file(&disc_root, "Unit_Key_RO.inf")?;
        let mkb = Mkb::parse(&mkb_bytes)?;
        let unit_key_file = UnitKeyFile::parse(&unit_key_bytes)?;
        let cps_units = unit_key_file
            .cps_units
            .iter()
            .enumerate()
            .map(|(i, rec)| CpsUnit {
                id: (i + 1) as u16,
                encrypted_title_key: rec.encrypted_cps_unit_key,
                title_key: None,
            })
            .collect();
        Ok(Self {
            mkb,
            unit_key_file,
            cps_units,
            disc_root,
        })
    }

    /// Resolve a VUK from a KEYDB.cfg database using the
    /// Content-Certificate disc ID (caller supplies it because the
    /// `.cer` file is out of scope for this round).
    pub fn resolve_vuk_from_keydb(&self, keydb: &KeyDb, disc_id: &[u8; 20]) -> Option<Vuk> {
        keydb.vuk_for_disc(disc_id)
    }

    /// Derive a VUK by walking the MKB with a Device Key. This is
    /// the full pipeline: Device Key → Processing Key → Media Key
    /// (via the Subset-Difference tree) → Volume Unique Key (via
    /// `AES-G(K_m, ID_v)`).
    ///
    /// Returns [`AacsError::DeviceRevoked`] if no MKB
    /// subset-difference applies to the Device Key.
    ///
    /// This is the **Type-3 path** (and is also correct for a Type-4
    /// MKB whose recovered precursor happens to verify directly — the
    /// "old MKB" rule in Common spec §3.2.5.1.4 final paragraph).
    /// For Type-4 MKBs where the precursor does NOT verify, callers
    /// must use [`Self::derive_vuk_from_device_key_with_kcd`].
    pub fn derive_vuk_from_device_key(
        &self,
        device_key: &DeviceKey,
        volume_id: &[u8; 16],
    ) -> Result<Vuk, AacsError> {
        let km = self.derive_media_key_from_device_key(device_key)?;
        self.mkb.verify_media_key(&km)?;
        Ok(crate::vuk::derive_vuk(&km, volume_id))
    }

    /// Type-4 aware variant of [`Self::derive_vuk_from_device_key`].
    ///
    /// Implements the Common spec §3.2.5.1.4 "verify-then-apply-KCD"
    /// decision tree:
    ///
    /// 1. Walk the Subset-Difference tree to obtain the raw output
    ///    of `media_key_from_processing_key` — for a Type-3 MKB this
    ///    is `K_m`; for a Type-4 MKB it's the Media Key Precursor
    ///    `K_mp`.
    /// 2. Run that output through the Verify Media Key Record. If it
    ///    verifies as the Media Key directly (which can happen for an
    ///    old Type-4 MKB whose KCD has not yet been incorporated into
    ///    this part of the tree, per the spec's "old MKB" paragraph),
    ///    we adopt it as `K_m` and skip KCD application — even if
    ///    a KCD value was supplied.
    /// 3. Otherwise apply `K_m = AES-G(K_mp, KCD)` and verify *that*
    ///    against the Verify Media Key Record.
    /// 4. Derive `K_vu = AES-G(K_m, ID_v)`.
    ///
    /// `kcd` is the 16-byte Key Conversion Data the device read from
    /// the disc's KCD-Mark (BD-Prerecorded §3.8, Table 3-11) — in
    /// `oxideav-aacs` this is most commonly the
    /// [`crate::keydb::DiscRecords::kcd`] field of a `KEYDB.cfg` row
    /// (the first 16 bytes of which are the KCD payload).
    /// `kcd = None` is equivalent to calling
    /// [`Self::derive_vuk_from_device_key`].
    ///
    /// Returns [`AacsError::DeviceRevoked`] if no subset-difference
    /// applies, or [`AacsError::MediaKeyVerificationFailed`] if
    /// neither the precursor nor the KCD-converted value verifies.
    pub fn derive_vuk_from_device_key_with_kcd(
        &self,
        device_key: &DeviceKey,
        volume_id: &[u8; 16],
        kcd: Option<&[u8; 16]>,
    ) -> Result<Vuk, AacsError> {
        let candidate = self.derive_media_key_from_device_key(device_key)?;
        // Step 2 — direct verify. Covers Type-3 always, and Type-4 in
        // the "old MKB" case where KCD must NOT be applied.
        if self.mkb.is_verified_media_key(&candidate) {
            return Ok(crate::vuk::derive_vuk(&candidate, volume_id));
        }
        // Step 3 — try KCD post-processing if we have a KCD.
        if let Some(kcd_bytes) = kcd {
            let km = crate::subdiff::apply_key_conversion_data(&candidate, kcd_bytes);
            self.mkb.verify_media_key(&km)?;
            return Ok(crate::vuk::derive_vuk(&km, volume_id));
        }
        // Step 4 — neither verifies and no KCD supplied. Surface the
        // (precursor) verification failure.
        Err(AacsError::MediaKeyVerificationFailed)
    }

    /// Subset-Difference half of the pipeline: walk the MKB with a
    /// Device Key and return the raw 16-byte value emitted by
    /// `media_key_from_processing_key`. For a Type-3 MKB this is
    /// the Media Key `K_m`; for a Type-4 MKB it is the Media Key
    /// Precursor `K_mp` (which the caller post-processes with KCD).
    ///
    /// Returns [`AacsError::DeviceRevoked`] if no subset-difference
    /// applies to the device, or
    /// [`AacsError::MissingVerifyMediaKeyRecord`] if the MKB has no
    /// `0x05` Media Key Data Record entry at the matching index.
    ///
    /// This is the cryptographic primitive callers reach for when
    /// they want to make the verify / KCD decision themselves rather
    /// than letting `derive_vuk_from_device_key_with_kcd` drive it.
    pub fn derive_media_key_from_device_key(
        &self,
        device_key: &DeviceKey,
    ) -> Result<[u8; 16], AacsError> {
        use crate::subdiff::{
            applies_to_device, derive_processing_key, media_key_from_processing_key,
            SubsetDifference,
        };
        // §3.2.3: device node numbers are device numbers shifted left
        // by 1, with the low-order bit set.
        let d_node = (device_key.uv << 1) | 1;
        let mut chosen: Option<(usize, SubsetDifference)> = None;
        for (i, e) in self.mkb.explicit_subdiff.iter().enumerate() {
            let sd = SubsetDifference {
                u_mask_zero_bits: e.u_mask_zero_bits,
                uv: e.uv,
            };
            if applies_to_device(&sd, d_node) {
                chosen = Some((i, sd));
                break;
            }
        }
        let (idx, sd) = chosen.ok_or(AacsError::DeviceRevoked)?;
        let target_v_mask_zero_bits = sd.uv.trailing_zeros() as u8;
        let pk = derive_processing_key(
            &device_key.key,
            device_key.uv,
            device_key.v_mask_zero_bits,
            sd.uv,
            target_v_mask_zero_bits,
        )
        .ok_or(AacsError::DeviceRevoked)?;
        let enc_km = *self
            .mkb
            .media_key_data
            .get(idx)
            .ok_or(AacsError::MissingVerifyMediaKeyRecord)?;
        Ok(media_key_from_processing_key(&pk, sd.uv, &enc_km))
    }

    /// Unwrap every CPS Unit's title key using the supplied VUK.
    /// Updates each [`CpsUnit::title_key`] in place.
    pub fn unwrap_title_keys(&mut self, vuk: &Vuk) -> Result<(), AacsError> {
        for unit in self.cps_units.iter_mut() {
            let pt = aes_128_ecb_decrypt(vuk.as_bytes(), &unit.encrypted_title_key);
            unit.title_key = Some(TitleKey(pt));
        }
        Ok(())
    }

    /// Load and parse the Content Hash Table for one physical layer
    /// per BD-Prerecorded §2.3.
    ///
    /// `layer` is the layer number (0 for single-layer or the lower
    /// layer of a dual-layer disc; 1 for the upper layer of a
    /// dual-layer disc) — used to resolve the on-disc file name
    /// `AACS/ContentHash000.tbl` vs `AACS/ContentHash001.tbl`.
    ///
    /// `number_of_digests` and `number_of_hash_units` come from the
    /// layer's Content Certificate (Table 2-1). They are supplied by
    /// the caller because this crate does not yet parse the Content
    /// Certificate (`Content000.cer` / `Content001.cer`) — the
    /// certificate's `AACS_Verify` signature step needs the AACS LA
    /// root public key, which is out of scope for the same reason as
    /// the MKB's `AACS_Verify` is.
    ///
    /// `AACS/DUPLICATE/` is consulted as fallback when the primary
    /// file is unreadable, matching the [`Self::open`] behaviour.
    pub fn load_content_hash_table(
        &self,
        layer: u8,
        number_of_digests: u32,
        number_of_hash_units: u32,
    ) -> Result<ContentHashTable, AacsError> {
        let name: &'static str = match layer {
            0 => "ContentHash000.tbl",
            1 => "ContentHash001.tbl",
            _ => {
                return Err(AacsError::InvalidValue {
                    what: "ContentHashTable layer number (must be 0 or 1)",
                    value: layer as u64,
                })
            }
        };
        let bytes = read_aacs_file(&self.disc_root, name)?;
        ContentHashTable::parse(&bytes, number_of_digests, number_of_hash_units)
    }

    /// Decrypt one 6144-byte Aligned Unit using a CPS Unit that has
    /// had its title key unwrapped. Returns
    /// [`AacsError::InvalidValue`] if the unit doesn't yet have a
    /// title key.
    pub fn decrypt_unit(
        &self,
        cps_unit: &CpsUnit,
        unit_bytes: &[u8],
    ) -> Result<[u8; ALIGNED_UNIT_SIZE], AacsError> {
        let tk = cps_unit.title_key.ok_or(AacsError::InvalidValue {
            what: "CPS Unit title key (not yet unwrapped)",
            value: cps_unit.id as u64,
        })?;
        decrypt_aligned_unit(&tk.0, unit_bytes)
    }
}

fn read_aacs_file(disc_root: &Path, name: &'static str) -> Result<Vec<u8>, AacsError> {
    let primary = disc_root.join("AACS").join(name);
    if let Ok(bytes) = std::fs::read(&primary) {
        return Ok(bytes);
    }
    let dup = disc_root.join("AACS").join("DUPLICATE").join(name);
    if let Ok(bytes) = std::fs::read(&dup) {
        return Ok(bytes);
    }
    Err(AacsError::MissingDiscFile(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unwrap_title_keys_uses_aes_128e_inverse() {
        // Construct synthetic state without going through disc I/O.
        let vuk = Vuk::from_bytes([0x11u8; 16]);
        let title_key = [0xABu8; 16];
        let enc = crate::aes::aes_128_ecb_encrypt(vuk.as_bytes(), &title_key);
        let mut vol = AacsVolume {
            mkb: Mkb::default(),
            unit_key_file: UnitKeyFile {
                unit_key_block_start_address: 0,
                header: crate::unit_key::UnitKeyFileHeader {
                    application_type: 1,
                    num_of_bd_directory: 1,
                    use_skb_unified_mkb: false,
                    bd_directories: Vec::new(),
                },
                cps_units: Vec::new(),
            },
            cps_units: vec![CpsUnit {
                id: 1,
                encrypted_title_key: enc,
                title_key: None,
            }],
            disc_root: PathBuf::new(),
        };
        vol.unwrap_title_keys(&vuk).unwrap();
        assert_eq!(vol.cps_units[0].title_key, Some(TitleKey(title_key)));
    }
}
