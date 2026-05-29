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
pub mod ake;
pub mod cht;
pub mod content;
pub mod ec;
pub mod ecdsa;
pub mod error;
pub mod keydb;
pub mod mkb;
pub mod mmc;
pub mod subdiff;
pub mod unit_key;
pub mod volume;
pub mod vuk;

pub use crate::ake::{
    build_signed_certificate, bus_key_from_point, host_authenticate, read_verified_volume_id,
    AkeResult, Certificate, DriveAuthState, HostCredentials, BUS_KEY_LEN, CERT_TYPE_DRIVE,
    CERT_TYPE_HOST,
};
pub use crate::cht::{
    hash_value_of_unit, ClipDescriptor, ContentHashTable, HASH_UNIT_SIZE, HASH_VALUE_SIZE,
    LOGICAL_SECTORS_PER_HASH_UNIT, LOGICAL_SECTOR_SIZE,
};
pub use crate::content::{decrypt_aligned_unit, encrypt_aligned_unit, ALIGNED_UNIT_SIZE};
pub use crate::ec::{Fp, Point, U160};
pub use crate::ecdsa::{sign, sign_with_k, verify, Signature};
pub use crate::error::AacsError;
pub use crate::keydb::{
    DeviceKeyRecord, DiscRecords, DriveCertRecord, HostCertRecord, KeyDb, KeyDbEntry, ProcessingKey,
};
pub use crate::mkb::{
    Mkb, MkbType, RevocationEntry, RevocationSignatureBlock, SubsetDifferenceEntry,
};
pub use crate::mmc::{
    build_send_key_host_cert_chal, build_send_key_host_key, parse_media_id_response,
    parse_media_serial_response, parse_mkb_pack_response, parse_report_key_agid,
    parse_report_key_drive_cert, parse_report_key_drive_cert_chal, parse_report_key_drive_key,
    parse_send_key_host_cert_chal, parse_send_key_host_key, parse_volume_id_response, AgidResponse,
    DataDirection, DriveCertChallengeResponse, DriveCertResponse, DriveCommand, DriveKeyResponse,
    MediaIdentifierResponse, MediaSerialNumberResponse, MkbPackResponse, MockDrive,
    ReadDiscStructure, ReportKey, ScsiResponse, SendKey, VolumeIdResponse,
};
pub use crate::subdiff::{
    aes_g3, applies_to_device, apply_key_conversion_data, derive_processing_key, SubsetDifference,
};
pub use crate::unit_key::{CpsUnitRecord, UnitKeyFile, UnitKeyFileHeader};
pub use crate::volume::{AacsVolume, CpsUnit, DeviceKey, TitleKey};
pub use crate::vuk::{derive_vuk, Vuk};

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, AacsError>;
