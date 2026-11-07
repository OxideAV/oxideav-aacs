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

#[doc(hidden)]
pub mod aes;
pub mod ake;
pub mod cci;
pub mod cht;
pub mod content;
pub mod content_certificate;
pub mod crl;
pub mod ec;
pub mod ecdsa;
pub mod error;
pub mod keydb;
pub mod mkb;
pub mod mmc;
pub mod online;
pub mod self_check;
pub mod subdiff;
pub mod unit_key;
pub mod volume;
pub mod vuk;

pub use crate::ake::{
    AACS_LA_PUB_X, AACS_LA_PUB_Y, AkeResult, BUS_KEY_LEN, CERT_TYPE_DRIVE, CERT_TYPE_HOST,
    Certificate, DriveAuthState, HostCredentials, aacs_la_pub_point, build_signed_certificate,
    bus_key_from_point, host_authenticate, read_verified_volume_id,
};
pub use crate::cci::{
    BASIC_CCI_DATA_LEN, BasicCci, BindingType, CCI_AREA_HEADER_LEN, CCI_HEADER_LEN, CCI_TYPE_BASIC,
    CCI_TYPE_CONTENT_OWNER_OUTPUTS, CCI_TYPE_ENHANCED_TITLE_USAGE, CCI_TYPE_KEY_MANAGEMENT_ONLINE,
    CCI_VERSION_0100, CONTENT_OWNER_OUTPUTS_DATA_LEN, Cacheable, Cci, CciAndOtherInfo,
    ContentOwnerAuthorizedOutputs, CpsUnitUsageFile, ENHANCED_TITLE_USAGE_DATA_LEN,
    EnhancedTitleUsage, KEY_MANAGEMENT_ONLINE_DATA_LEN, KeyManagementOnline, PRIMARY_CCI_AREA_LEN,
    TitleDate, TypeOfTitle,
};
pub use crate::cht::{
    ClipDescriptor, ContentHashTable, HASH_UNIT_SIZE, HASH_VALUE_SIZE, LOGICAL_SECTOR_SIZE,
    LOGICAL_SECTORS_PER_HASH_UNIT, hash_value_of_unit,
};
pub use crate::content::{ALIGNED_UNIT_SIZE, decrypt_aligned_unit, encrypt_aligned_unit};
pub use crate::content_certificate::{
    BdFormatSpecificSection, CERTIFICATE_TYPE_FIRST_GEN, CONTENT_HASH_TABLE_DIGEST_LEN,
    ContentCertificate, ContentCertificateId, ContentSequenceNumber, SIGNATURE_DATA_LEN,
    usage_rules_hash,
};
pub use crate::crl::{
    CRL_HEADER_LEN, ContentRevocationList, CrlSegment, LIST_TYPE_FIRST_GEN,
    ManagedCopyServerCertificateId, RECORD_TYPE_CONTENT_CERTIFICATE_ID,
    RECORD_TYPE_MANAGED_COPY_SERVER_ID, RECORD_TYPE_RMRR_PART_1, RECORD_TYPE_RMRR_PART_2,
    RECORD_TYPE_RMRR_PART_3, REVOCATION_RECORD_LEN, RecordableMediaRevocation, RecordableMediaType,
    RevocationRecord, SEGMENT_1_SIZE_MAX, SEGMENT_SIGNATURE_LEN,
};
pub use crate::ec::{Fp, Point, U160};
pub use crate::ecdsa::{Signature, sign, sign_with_k, verify};
pub use crate::error::AacsError;
pub use crate::keydb::{
    DeviceKeyRecord, DiscRecords, DriveCertRecord, HostCertRecord, KeyDb, KeyDbEntry, ParseReport,
    ProcessingKey, SkippedLine,
};
pub use crate::mkb::{
    Mkb, MkbType, RevocationEntry, RevocationSignatureBlock, SubsetDifferenceEntry,
};
pub use crate::mmc::{
    AacsFeatureDescriptor, AgidResponse, BindingNonceResponse, BusEncryptionSectorExtent,
    BusEncryptionSectorExtentsResponse, CprmMkbPackResponse, DataDirection, DataKeysResponse,
    DriveCertChallengeResponse, DriveCertResponse, DriveCommand, DriveKeyResponse,
    GetConfiguration, MediaIdentifierResponse, MediaSerialNumberResponse, MkbPackResponse,
    ReadDiscStructure, ReportKey, ScsiResponse, SendDiscStructure, SendKey, VolumeIdResponse,
    build_get_configuration_aacs_response, build_send_disc_structure_bus_encryption_sector_extents,
    build_send_disc_structure_write_data_key, build_send_key_host_cert_chal,
    build_send_key_host_key, find_aacs_feature_descriptor, parse_aacs_feature_descriptor,
    parse_bus_encryption_sector_extents_response, parse_cprm_mkb_pack_response,
    parse_data_keys_response, parse_media_id_response, parse_media_serial_response,
    parse_mkb_pack_response, parse_report_key_agid, parse_report_key_binding_nonce,
    parse_report_key_drive_cert, parse_report_key_drive_cert_chal, parse_report_key_drive_key,
    parse_send_disc_structure_bus_encryption_sector_extents,
    parse_send_disc_structure_write_data_key, parse_send_key_host_cert_chal,
    parse_send_key_host_key, parse_volume_id_response, validate_bus_encryption_sector_extents,
};
// `MockDrive` is a `test-util`-gated synthetic-drive fixture, not part of
// the default public API. See the `test-util` cargo feature.
// internal — exposed for tests/fuzz; not part of the stable API
#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
pub use crate::mmc::MockDrive;
pub use crate::online::{
    ONLINE_TITLE_ID_LEN, PERMISSION_MESSAGE_LEN, enhanced_title_key_message,
    recover_enhanced_title_key, title_binding_hash, verify_enhanced_permission,
};
pub use crate::self_check::{aacs_la_pub_self_check, ake_ecdh_self_check, curve_self_check};
// `ake_full_self_check` + `all_self_checks` drive the `test-util`-gated
// `MockDrive`, so they are gated together behind `test-util`.
// internal — exposed for tests/fuzz; not part of the stable API
#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
pub use crate::self_check::{ake_full_self_check, all_self_checks};
pub use crate::subdiff::{
    SubsetDifference, aes_g3, applies_to_device, apply_key_conversion_data, derive_processing_key,
};
pub use crate::unit_key::{CpsUnitRecord, UnitKeyFile, UnitKeyFileHeader};
pub use crate::volume::{AacsVolume, CpsUnit, DeviceKey, TitleKey};
pub use crate::vuk::{Vuk, derive_vuk};

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, AacsError>;
