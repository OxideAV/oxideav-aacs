//! Pure-Rust, clean-room AACS (Advanced Access Content System)
//! decryption library, implementing the publicly-published AACS LA
//! technical specifications **Common Final 0.953** (Oct 2012) and
//! **BD-Prerecorded Final 0.953** (Oct 2012).
//!
//! See the crate `README.md` for an overview, the per-module spec
//! mapping, and the legal-hygiene notes. The full pipeline is:
//!
//! ```text
//! Device Key + MKB              KEYDB.cfg
//!     |  (subdiff)                  | (direct)
//!     v                              v
//!   Media Key (K_m)                  |
//!     |  AES-G(K_m, ID_v)           |
//!     v                              |
//!   Volume Unique Key (K_vu)  <-----+
//!     |  AES-128D(K_vu, EncCpsUnitKey)
//!     v
//!   CPS Unit Key (K_cu)
//!     |  BlockKey = AES-128E(K_cu, seed) XOR seed,
//!     |  then AES-128-CBC-decrypt under BlockKey with IV0
//!     v
//!   Decrypted Aligned Unit (6144 B)
//! ```
//!
//! This crate has **no real-disc fixtures**, no embedded Device Keys,
//! no embedded Processing Keys, and no disc-specific test vectors —
//! every test constructs its own key material and roundtrips through
//! encrypt → parse → decrypt.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rust_2018_idioms)]

pub mod aes;
pub mod content;
pub mod error;
pub mod keydb;
pub mod mkb;
pub mod subdiff;
pub mod unit_key;
pub mod volume;
pub mod vuk;

pub use crate::content::{decrypt_aligned_unit, encrypt_aligned_unit, ALIGNED_UNIT_SIZE};
pub use crate::error::AacsError;
pub use crate::keydb::KeyDb;
pub use crate::mkb::{Mkb, MkbType, RevocationEntry, SubsetDifferenceEntry};
pub use crate::subdiff::{aes_g3, applies_to_device, derive_processing_key, SubsetDifference};
pub use crate::unit_key::{CpsUnitRecord, UnitKeyFile, UnitKeyFileHeader};
pub use crate::volume::{AacsVolume, CpsUnit, DeviceKey, TitleKey};
pub use crate::vuk::{derive_vuk, Vuk};

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, AacsError>;
