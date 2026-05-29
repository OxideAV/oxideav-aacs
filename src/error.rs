//! Error type for the crate.
//!
//! When the `registry` cargo feature is on (the default), the public
//! surface uses [`AacsError`] directly. We do **not** re-alias to
//! `oxideav_core::Error` because AACS is sufficiently self-contained
//! that surfacing parser/crypto failures through a generic framework
//! error would erase useful detail. The framework consumer can map
//! these via `From<AacsError>` at the boundary.

use core::fmt;

/// Errors produced by the AACS crate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AacsError {
    /// A parser ran out of input before a field finished.
    ///
    /// The associated string names which structure was being parsed
    /// (`"MKB record header"`, `"Unit Key Block"`, etc.).
    Truncated(&'static str),
    /// A multi-byte length field declared a record larger than the
    /// surrounding buffer.
    OversizedRecord {
        /// Identifier of the surrounding structure (e.g. `"MKB"`).
        what: &'static str,
        /// Declared length in bytes.
        declared: usize,
        /// Number of bytes actually remaining in the buffer.
        available: usize,
    },
    /// A field had a value the spec doesn't define.
    InvalidValue {
        /// Identifier of the field (e.g. `"MKBType"`).
        what: &'static str,
        /// The unexpected value (formatted as decimal by the
        /// `Display` impl).
        value: u64,
    },
    /// The expected `Type and Version Record` (record type `0x10`)
    /// wasn't the first record of the MKB.
    MissingTypeAndVersionRecord,
    /// The MKB has no `Verify Media Key Record` (record type `0x81`).
    /// This is mandatory per Common spec §3.2.5.1.4 for any MKB that
    /// is going to derive a usable Media Key.
    MissingVerifyMediaKeyRecord,
    /// `verify_media_key()` was called with a candidate Km that does
    /// not pass the Verify Media Key check
    /// (`[AES-128D(Km, Vd)]_msb_64 != 0x0123456789ABCDEF`).
    MediaKeyVerificationFailed,
    /// The Subset-Difference walk could not find an applicable
    /// subset-difference for this Device Key — the device is revoked
    /// by this MKB (Common spec §3.2.4 final paragraph).
    DeviceRevoked,
    /// The disc-mount root does not contain an `AACS/` directory, or
    /// `MKB_RO.inf` / `Unit_Key_RO.inf` cannot be located in either
    /// `AACS/` or `AACS/DUPLICATE/`.
    MissingDiscFile(&'static str),
    /// I/O failure while reading from disk.
    Io(String),
    /// The Aligned Unit handed to [`crate::content::decrypt_aligned_unit`]
    /// is not exactly [`crate::content::ALIGNED_UNIT_SIZE`] bytes.
    BadAlignedUnitLength(usize),
    /// A KEYDB.cfg line did not parse. The string carries a
    /// best-effort excerpt of the offending text (truncated to 80
    /// chars) for diagnostics.
    KeyDbParseError(String),
    /// The Drive Certificate's AACS LA signature failed verification
    /// during the §4.3 AKE (step 15) — the drive is not an
    /// AACS-compliant device or the certificate is corrupt.
    DriveCertSignatureInvalid,
    /// The Host Certificate's AACS LA signature failed verification
    /// during the §4.3 AKE (step 9).
    HostCertSignatureInvalid,
    /// The drive's `Dsig` over `Hn || Dv` failed verification (§4.3
    /// step 22).
    DriveSignatureInvalid,
    /// The host's `Hsig` over `Dn || Hv` failed verification (§4.3
    /// step 27).
    HostSignatureInvalid,
    /// The drive's CMAC (`Dm`) over a transferred ID did not match the
    /// host's recomputed `Hm` under the Bus Key (§4.4 step 4).
    VolumeIdMacInvalid,
    /// A KEYDB.cfg `|`-leader header line (one of `DK` / `PK` / `HC`
    /// / `DC` / `VID` / `VUK` / `MEK` / `TK` / `KCD` / `DISCID`) was
    /// malformed: wrong number of fields, hex value with the wrong
    /// byte-count for that field, malformed hex literal, or an
    /// unrecognised leader token. The string carries a best-effort
    /// excerpt of the offending line (truncated to 80 chars) plus a
    /// short description.
    HeaderParseError(String),
    /// An MKB signature record (End-of-MKB `0x02`, Host Revocation
    /// List `0x21`, or Drive Revocation List `0x20`) was missing the
    /// 40-byte ECDSA signature payload, or the parsed MKB carried no
    /// signature blocks for that record at all. `verify_*_signature`
    /// surfaces this so the caller can distinguish "no signature to
    /// verify" from "signature present but invalid".
    MkbSignatureMissing,
    /// An MKB signature failed `AACS_Verify(AACS_LApub, sig, data)`.
    /// Returned by `verify_end_of_block_signature` and the per-block
    /// `verify_{host,drive}_revocation_list` methods.
    MkbSignatureInvalid,
}

impl fmt::Display for AacsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated(what) => write!(f, "truncated input while parsing {what}"),
            Self::OversizedRecord {
                what,
                declared,
                available,
            } => write!(
                f,
                "{what} record declares {declared} bytes but only {available} bytes remain"
            ),
            Self::InvalidValue { what, value } => {
                write!(f, "invalid {what} value: {value}")
            }
            Self::MissingTypeAndVersionRecord => {
                f.write_str("MKB does not start with a Type-and-Version Record")
            }
            Self::MissingVerifyMediaKeyRecord => f.write_str("MKB has no Verify Media Key Record"),
            Self::MediaKeyVerificationFailed => {
                f.write_str("Verify Media Key Record rejected the derived Media Key")
            }
            Self::DeviceRevoked => f.write_str(
                "no applicable subset-difference for this Device Key — device is revoked",
            ),
            Self::MissingDiscFile(name) => {
                write!(f, "AACS disc layout missing required file: {name}")
            }
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
            Self::BadAlignedUnitLength(n) => {
                write!(f, "Aligned Unit must be exactly 6144 bytes; got {n} bytes")
            }
            Self::DriveCertSignatureInvalid => {
                f.write_str("Drive Certificate AACS LA signature verification failed")
            }
            Self::HostCertSignatureInvalid => {
                f.write_str("Host Certificate AACS LA signature verification failed")
            }
            Self::DriveSignatureInvalid => {
                f.write_str("Drive signature (Dsig over Hn || Dv) verification failed")
            }
            Self::HostSignatureInvalid => {
                f.write_str("Host signature (Hsig over Dn || Hv) verification failed")
            }
            Self::VolumeIdMacInvalid => f.write_str("transferred-ID CMAC mismatch under Bus Key"),
            Self::KeyDbParseError(line) => write!(f, "KEYDB.cfg parse error near: {line:?}"),
            Self::HeaderParseError(msg) => write!(f, "KEYDB.cfg header parse error: {msg}"),
            Self::MkbSignatureMissing => {
                f.write_str("MKB signature record absent or carried no signature payload to verify")
            }
            Self::MkbSignatureInvalid => f.write_str(
                "AACS_Verify rejected the MKB signature against the supplied public key",
            ),
        }
    }
}

impl std::error::Error for AacsError {}

impl From<std::io::Error> for AacsError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}
