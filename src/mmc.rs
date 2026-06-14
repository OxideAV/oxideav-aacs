//! Phase B — SCSI MMC drive command layer.
//!
//! This module implements the **wire-format** for the three SCSI MMC
//! commands an AACS Host needs to talk to a Licensed Drive:
//!
//! - `REPORT_KEY` (`0xA4`) — drive-to-host data flow. Key Class `0x02`
//!   carries the AACS sub-payloads (AGID, Drive Certificate Challenge,
//!   Drive Key, Drive Certificate, Binding Nonce, Invalidate AGID).
//! - `SEND_KEY` (`0xA3`) — host-to-drive data flow. Key Class `0x02`
//!   carries the AACS Host Certificate Challenge (Host Nonce `Hn` +
//!   Host Certificate) and Host Key (`Hv` + `Hsig`).
//! - `READ_DISC_STRUCTURE` (`0xAD`) — drive-to-host data flow. Format
//!   `0x80` returns the AACS Volume Identifier + MAC.
//!
//! All byte layouts are taken from the publicly-hosted T10 working
//! drafts of **MMC-6 r02g** + **SPC-3 r23** (staged in
//! `docs/container/aacs/mmc/`) cross-referenced against the AACS LA
//! **Common Final 0.953** spec (`docs/container/aacs/`).
//!
//! # Layering
//!
//! This module owns **only** the byte-format of the SCSI CDB and its
//! response payloads. The transport — `SG_IO` on Linux,
//! `IOSCSITaskDeviceInterface` on macOS, `IOCTL_SCSI_PASS_THROUGH_DIRECT`
//! on Windows — is abstracted behind the [`DriveCommand`] trait. Phase
//! B ships no real transport: only the wire format + the trait surface
//! + the in-process [`MockDrive`] for tests.
//!
//! # Spec map
//!
//! | Section in this module                  | MMC-6 §              | AACS Common §           |
//! |-----------------------------------------|----------------------|--------------------------|
//! | `ReportKey::cdb()`                       | 6.28.2.1, Table 513  | 4.14.2                   |
//! | `ReportKey` AACS Key Format definitions  | 6.28.3.2, Table 525  | 4.14.2 (Table 4-7)       |
//! | `SendKey::cdb()`                         | 6.37.2.1, Table 599  | 4.14.4                   |
//! | `SendKey` AACS Key Format definitions    | 6.37.3.2, Table 605  | 4.14.4 (Table 4-23)      |
//! | `ReadDiscStructure::cdb()`               | 6.22.2.1, Table 381  | 4.14.3                   |
//! | `ReadDiscStructure` Format 0x80 response | 6.22.3.1.1, Table 384 | 4.14.3.1, Table 4-15    |
//! | `parse_report_key_agid`                  | Table 526            | 4.14.2.1, Table 4-7      |
//! | `parse_report_key_drive_cert_chal`       | Table 527            | 4.14.2.2, Table 4-8      |
//! | `parse_report_key_drive_key`             | Table 528            | 4.14.2.3, Table 4-9      |
//! | `parse_report_key_drive_cert`            | Table 531            | 4.14.2.6                 |
//! | `build_send_key_host_cert_chal`          | Table 606            | 4.14.4.1, Table 4-24     |
//! | `build_send_key_host_key`                | Table 607            | 4.14.4.2, Table 4-25     |
//! | `parse_volume_id_response`               | Table 384            | 4.14.3.1, Table 4-15     |
//! | `parse_media_serial_response`            | Table 384            | 4.14.3.2, Table 4-16     |
//! | `parse_media_id_response`                | Table 384            | 4.14.3.3, Table 4-17     |
//! | `parse_mkb_pack_response`                | Table 384            | 4.14.3.4, Table 4-18     |
//! | `parse_data_keys_response`               | Table 384            | 4.14.3.5, Table 4-19     |
//! | `parse_bus_encryption_sector_extents_response` | Table 389       | 4.14.3.6, Table 4-20     |
//!
//! # Notes on the workspace `docs/container/aacs/mmc/README.md`
//!
//! That README factually summarises the REPORT KEY sub-payloads with a
//! list extending to Key Format values up to `0x1F` for Key Class
//! `0x02`. The MMC-6 specification (Table 525) defines only Key Formats
//! `0x00`, `0x01`, `0x02`, `0x20`, `0x21`, `0x38`, `0x3F` for AACS via
//! REPORT KEY. The README list mixed REPORT KEY Key-Format values with
//! READ DISC STRUCTURE Format Codes (Volume ID lives in READ DISC
//! STRUCTURE Format `0x80`, *not* REPORT KEY Key Format `0x12`). This
//! module implements per the MMC-6 spec tables; see the docs-gap note in
//! the Phase B CHANGELOG entry.

use crate::AacsError;

// ---------------------------------------------------------------------
// SCSI opcodes
// ---------------------------------------------------------------------

/// SCSI MMC `REPORT KEY` opcode (MMC-6 §6.28.2.1).
pub const REPORT_KEY_OPCODE: u8 = 0xA4;
/// SCSI MMC `SEND KEY` opcode (MMC-6 §6.37.2.1).
pub const SEND_KEY_OPCODE: u8 = 0xA3;
/// SCSI MMC `READ DISC STRUCTURE` opcode (MMC-6 §6.22.2.1).
pub const READ_DISC_STRUCTURE_OPCODE: u8 = 0xAD;
/// SCSI MMC `SEND DISC STRUCTURE` opcode (MMC-6 §6.36.2.1; AACS Common
/// §4.14.5 Table 4-26).
pub const SEND_DISC_STRUCTURE_OPCODE: u8 = 0xBF;

/// SCSI Multi-Media Commands CDB fixed length for REPORT KEY / SEND
/// KEY / READ DISC STRUCTURE (12 bytes — SPC-3 §4.3.2 categorises these
/// as group-5 fixed CDBs).
pub const MMC_CDB_LEN: usize = 12;

// ---------------------------------------------------------------------
// Key Class & Key Format constants
// ---------------------------------------------------------------------

/// Key Class `0x00`: DVD CSS / CPPM / CPRM (legacy, included for
/// completeness — this crate's AACS callers use Key Class `0x02`).
pub const KEY_CLASS_CSS: u8 = 0x00;

/// Key Class `0x02`: **AACS** (MMC-6 Table 514, AACS Common §4.14.2
/// Table 4-7).
pub const KEY_CLASS_AACS: u8 = 0x02;

/// REPORT KEY Key Format `0x00`: AGID for AACS (MMC-6 §6.28.3.2.2,
/// AACS Common §4.14.2.1).
pub const KF_REPORT_AACS_AGID: u8 = 0x00;
/// REPORT KEY Key Format `0x01`: Drive Certificate Challenge (MMC-6
/// §6.28.3.2.3, AACS Common §4.14.2.2).
pub const KF_REPORT_AACS_DRIVE_CERT_CHAL: u8 = 0x01;
/// REPORT KEY Key Format `0x02`: Drive Key (MMC-6 §6.28.3.2.4,
/// AACS Common §4.14.2.3).
pub const KF_REPORT_AACS_DRIVE_KEY: u8 = 0x02;
/// REPORT KEY Key Format `0x20`: Binding Nonce — generated in drive
/// (MMC-6 §6.28.3.2.5).
pub const KF_REPORT_AACS_BINDING_NONCE_GEN: u8 = 0x20;
/// REPORT KEY Key Format `0x21`: Binding Nonce — read from medium
/// (MMC-6 §6.28.3.2.6).
pub const KF_REPORT_AACS_BINDING_NONCE_READ: u8 = 0x21;
/// REPORT KEY Key Format `0x38`: Drive Certificate (MMC-6 §6.28.3.2.7,
/// AACS Common §4.14.2.6).
pub const KF_REPORT_AACS_DRIVE_CERT: u8 = 0x38;
/// REPORT KEY Key Format `0x3F`: Invalidate AGID for AACS (MMC-6
/// §6.28.3.2.8).
pub const KF_REPORT_AACS_INVALIDATE_AGID: u8 = 0x3F;

/// SEND KEY Key Format `0x01`: Host Certificate Challenge (MMC-6
/// §6.37.3.2.1, AACS Common §4.14.4.1).
pub const KF_SEND_AACS_HOST_CERT_CHAL: u8 = 0x01;
/// SEND KEY Key Format `0x02`: Host Key (MMC-6 §6.37.3.2.2, AACS
/// Common §4.14.4.2).
pub const KF_SEND_AACS_HOST_KEY: u8 = 0x02;
/// SEND KEY Key Format `0x3F`: Invalidate AGID for AACS (MMC-6
/// §6.37.3.2.3).
pub const KF_SEND_AACS_INVALIDATE_AGID: u8 = 0x3F;

/// READ DISC STRUCTURE Format Code `0x80`: AACS Volume Identifier
/// (MMC-6 §6.22.3.1.1, AACS Common §4.14.3.1).
pub const FORMAT_AACS_VOLUME_ID: u8 = 0x80;
/// READ DISC STRUCTURE Format Code `0x81`: AACS Pre-recorded Media
/// Serial Number (MMC-6 §6.22.3.1.2, AACS Common §4.14.3.2).
pub const FORMAT_AACS_MEDIA_SERIAL: u8 = 0x81;
/// READ DISC STRUCTURE Format Code `0x82`: AACS Media Identifier
/// (MMC-6 §6.22.3.1.3, AACS Common §4.14.3.3).
pub const FORMAT_AACS_MEDIA_ID: u8 = 0x82;
/// READ DISC STRUCTURE Format Code `0x83`: AACS Media Key Block pack
/// (MMC-6 §6.22.3.1.4, AACS Common §4.14.3.4).
pub const FORMAT_AACS_MEDIA_KEY_BLOCK: u8 = 0x83;
/// READ DISC STRUCTURE Format Code `0x84`: AACS Data Keys
/// (Bus-Encryption Read/Write Data Keys, encrypted under the Bus Key
/// using AES-128E per AACS Common §4.11). Spec §4.14.3.5 Table 4-19.
pub const FORMAT_AACS_DATA_KEYS: u8 = 0x84;
/// READ DISC STRUCTURE Format Code `0x85`: AACS Bus-Encryption Sector
/// Extents (the LBA-Extent table that flags which sectors are subject
/// to §4.11 Bus Encryption). MMC-6 §6.22.3.1.6 Table 389; AACS Common
/// §4.14.3.6 Table 4-20. Does **not** require AACS authentication.
pub const FORMAT_AACS_BUS_ENCRYPTION_SECTOR_EXTENTS: u8 = 0x85;
/// SEND DISC STRUCTURE Format Code `0x84`: Write Data Key of AACS
/// (AACS Common §4.14.5 Table 4-27 / §4.14.5.1 Table 4-28; MMC-6
/// §6.36.3.2.11 Table 591). Numerically the same Format Code value as
/// [`FORMAT_AACS_DATA_KEYS`] on the READ side, but the data-out payload
/// carries only the host's replacement Write Data Key (encrypted under
/// the Bus Key with AES-128E).
pub const FORMAT_AACS_WRITE_DATA_KEY: u8 = 0x84;

/// READ DISC STRUCTURE Media Type `0001b`: BD (MMC-6 Table 382).
pub const MEDIA_TYPE_BD: u8 = 0x01;
/// READ DISC STRUCTURE Media Type `0000b`: DVD (MMC-6 Table 382).
pub const MEDIA_TYPE_DVD: u8 = 0x00;

// ---------------------------------------------------------------------
// Field sizes documented in the AACS Common spec
// ---------------------------------------------------------------------

/// 160-bit Host Nonce `Hn` — AACS Common §4.3 step 6, Table 4-24
/// bytes 4..23.
pub const HOST_NONCE_LEN: usize = 20;
/// 160-bit Drive Nonce `Dn` — AACS Common §4.3 step 12, Table 4-8
/// bytes 4..23.
pub const DRIVE_NONCE_LEN: usize = 20;
/// 92-byte Host Certificate — AACS Common §4.2 Table 4-2 (byte 0..91).
pub const HOST_CERT_LEN: usize = 92;
/// 92-byte Drive Certificate — AACS Common §4.1 Table 4-1 (byte 0..91).
pub const DRIVE_CERT_LEN: usize = 92;
/// 320-bit (40-byte) elliptic curve point `Hv` / `Dv` over
/// secp160r1 — AACS Common §4.3 step 22 / 14, Table 4-25 / 4-9
/// bytes 4..43.
pub const EC_POINT_LEN: usize = 40;
/// 320-bit (40-byte) ECDSA-secp160r1 signature `Hsig` / `Dsig` —
/// AACS Common §4.3 step 23 / 16, Table 4-25 / 4-9 bytes 44..83.
pub const EC_SIG_LEN: usize = 40;
/// 128-bit (16-byte) Volume Identifier value — AACS Common §4.14.3.1
/// Table 4-15 bytes 4..19.
pub const VOLUME_ID_LEN: usize = 16;
/// 128-bit (16-byte) Message Authentication Code accompanying the
/// Volume Identifier (and other §4.14.3 IDs) — Table 4-15 bytes 20..35.
pub const ID_MAC_LEN: usize = 16;
/// 128-bit (16-byte) Binding Nonce returned by REPORT KEY Key Format
/// `0x20` / `0x21` — AACS Common §4.14.2.4 Table 4-10 bytes 4..19 (and
/// §4.14.2.5 Table 4-11, identical layout).
pub const BINDING_NONCE_LEN: usize = 16;
/// 128-bit (16-byte) Message Authentication Code accompanying the
/// Binding Nonce in the REPORT KEY Key Format `0x20` / `0x21` response —
/// AACS Common §4.14.2.4 Table 4-10 bytes 20..35.
pub const BINDING_NONCE_MAC_LEN: usize = 16;
/// 128-bit (16-byte) Read Data Key / Write Data Key payload length on
/// the wire — AACS Common §4.14.3.5 Table 4-19 (bytes 4..19 carry the
/// encrypted `Krd`, bytes 20..35 carry the encrypted `Kwd`). Each Data
/// Key is wrapped under the Bus Key with AES-128E per §4.11.
pub const DATA_KEY_LEN: usize = 16;
/// 16-byte stride of one Bus-Encryption Sector Extent record on the
/// READ DISC STRUCTURE Format `0x85` wire layout — AACS Common
/// §4.14.3.6 Table 4-20. Each record is `[Reserved:8 || Start LBA:4 ||
/// LBA Count:4]`, with the eight Reserved bytes preceding the
/// 4+4 LBA pair (bytes 4..11 / 4+n*16..11+n*16 in the table).
pub const BUS_ENCRYPTION_SECTOR_EXTENT_LEN: usize = 16;

// ---------------------------------------------------------------------
// REPORT_KEY (0xA4) CDB
// ---------------------------------------------------------------------

/// Typed builder for the `REPORT_KEY` (`0xA4`) CDB.
///
/// Per MMC-6 Table 513 the CDB layout is:
///
/// ```text
///  Byte 0  : Operation Code (0xA4)
///  Byte 1  : Reserved
///  Bytes 2-5: Reserved / Logical Block Address / Starting Offset
///  Byte 6  : Reserved / Block Count Function
///  Byte 7  : Key Class
///  Bytes 8-9: Allocation Length (big-endian)
///  Byte 10 : (AGID << 6) | Key Format
///  Byte 11 : Control (SAM-3 §6, typically 0x00)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportKey {
    /// Key Class byte — `KEY_CLASS_*` constant. AACS uses
    /// [`KEY_CLASS_AACS`] (`0x02`).
    pub key_class: u8,
    /// Key Format value (low 6 bits of byte 10). AACS sub-payload
    /// selector — `KF_REPORT_AACS_*`.
    pub key_format: u8,
    /// Authentication Grant ID (high 2 bits of byte 10). `0..=3`.
    pub agid: u8,
    /// Reserved/LBA/starting-offset field (bytes 2..5, big-endian).
    /// The vast majority of REPORT KEY Key Formats reserve this; only
    /// the `Binding Nonce (read)` (`0x21`) format uses it as an
    /// `Starting LBA` per MMC-6 §6.28.3.2.6.
    pub lba_or_starting_offset: u32,
    /// Byte 6, used only by binding-nonce key formats per MMC-6
    /// §6.28.3.2.5; reserved (zero) otherwise.
    pub block_count_function: u8,
    /// Allocation length in bytes the host expects back (bytes 8..9,
    /// big-endian).
    pub allocation_length: u16,
    /// SAM-3 control byte — typically `0x00`.
    pub control: u8,
}

impl ReportKey {
    /// Constructor for the AACS AGID request (MMC-6 §6.28.3.2.2,
    /// Key Format `0x00`, Key Class `0x02`). The response is the
    /// 8-byte payload parsed by [`parse_report_key_agid`].
    pub fn aacs_agid() -> Self {
        Self {
            key_class: KEY_CLASS_AACS,
            key_format: KF_REPORT_AACS_AGID,
            agid: 0,
            lba_or_starting_offset: 0,
            block_count_function: 0,
            // 4-byte length field + 4-byte payload (AACS Common Table
            // 4-7 / MMC-6 Table 526).
            allocation_length: 8,
            control: 0,
        }
    }

    /// Constructor for the Drive Certificate Challenge request
    /// (Key Format `0x01`). Drive returns 116 bytes
    /// (`Dn || Drive Cert`).
    pub fn aacs_drive_cert_challenge(agid: u8) -> Self {
        Self {
            key_class: KEY_CLASS_AACS,
            key_format: KF_REPORT_AACS_DRIVE_CERT_CHAL,
            agid: agid & 0x03,
            lba_or_starting_offset: 0,
            block_count_function: 0,
            // 4-byte header + 20-byte Dn + 92-byte Drive Certificate.
            allocation_length: 116,
            control: 0,
        }
    }

    /// Constructor for the Drive Key request (Key Format `0x02`).
    /// Drive returns 84 bytes (`Dv || Dsig`).
    pub fn aacs_drive_key(agid: u8) -> Self {
        Self {
            key_class: KEY_CLASS_AACS,
            key_format: KF_REPORT_AACS_DRIVE_KEY,
            agid: agid & 0x03,
            lba_or_starting_offset: 0,
            block_count_function: 0,
            // 4-byte header + 40-byte Dv + 40-byte Dsig.
            allocation_length: 84,
            control: 0,
        }
    }

    /// Constructor for the Drive Certificate request
    /// (Key Format `0x38`). Drive returns 96 bytes (4-byte header +
    /// 92-byte Drive Certificate). This format does not require an
    /// AGID per MMC-6 §6.28.3.2.7 (the AGID field is "Reserved &
    /// N/A").
    pub fn aacs_drive_cert() -> Self {
        Self {
            key_class: KEY_CLASS_AACS,
            key_format: KF_REPORT_AACS_DRIVE_CERT,
            agid: 0,
            lba_or_starting_offset: 0,
            block_count_function: 0,
            allocation_length: 96,
            control: 0,
        }
    }

    /// Constructor for the Binding Nonce *generate-and-store* request
    /// (Key Format `0x20`, AACS Common §4.14.2.4 / Table 4-10, MMC-6
    /// §6.28.3.2.5 / Table 529). The drive generates a fresh 16-byte
    /// Binding Nonce, persists it for the LBA Extent identified by
    /// `starting_lba` + `block_count`, and returns the 36-byte payload
    /// (`length:u16=0x0022 || reserved:u16 || nonce:16 || mac:16`).
    ///
    /// `starting_lba` populates CDB bytes 2..5 (the LBA Extent's
    /// starting address) and `block_count` populates byte 6 (the LBA
    /// Extent's block count) per §4.14.2 final paragraph. A valid
    /// Bus Key established by the §4.3 AKE is a precondition; absent
    /// it a real drive surfaces SCSI sense `5/6F/02 KEY NOT
    /// ESTABLISHED` per AACS Common §4.7.1 (the wire-format reference
    /// in `docs/container/aacs/mmc/aacs-keyclass-02-wire-format.md`
    /// records this dependency).
    pub fn aacs_binding_nonce_gen(agid: u8, starting_lba: u32, block_count: u8) -> Self {
        Self {
            key_class: KEY_CLASS_AACS,
            key_format: KF_REPORT_AACS_BINDING_NONCE_GEN,
            agid: agid & 0x03,
            lba_or_starting_offset: starting_lba,
            block_count_function: block_count,
            // 4-byte header + 16-byte Binding Nonce + 16-byte MAC.
            allocation_length: 36,
            control: 0,
        }
    }

    /// Constructor for the Binding Nonce *read-from-medium* request
    /// (Key Format `0x21`, AACS Common §4.14.2.5 / Table 4-11, MMC-6
    /// §6.28.3.2.6 / Table 530). Same wire layout as the generate
    /// command; the difference is that the drive returns the nonce it
    /// previously stored for the LBA Extent rather than minting a new
    /// one (AACS Common §4.7.2 read protocol). Bus Key precondition is
    /// the same.
    pub fn aacs_binding_nonce_read(agid: u8, starting_lba: u32, block_count: u8) -> Self {
        Self {
            key_class: KEY_CLASS_AACS,
            key_format: KF_REPORT_AACS_BINDING_NONCE_READ,
            agid: agid & 0x03,
            lba_or_starting_offset: starting_lba,
            block_count_function: block_count,
            allocation_length: 36,
            control: 0,
        }
    }

    /// Constructor for the Invalidate-AGID command (Key Format
    /// `0x3F`). No data is returned by the drive.
    pub fn aacs_invalidate_agid(agid: u8) -> Self {
        Self {
            key_class: KEY_CLASS_AACS,
            key_format: KF_REPORT_AACS_INVALIDATE_AGID,
            agid: agid & 0x03,
            lba_or_starting_offset: 0,
            block_count_function: 0,
            allocation_length: 0,
            control: 0,
        }
    }

    /// Serialize this CDB into 12 bytes per MMC-6 Table 513.
    pub fn cdb(&self) -> [u8; MMC_CDB_LEN] {
        let mut cdb = [0u8; MMC_CDB_LEN];
        cdb[0] = REPORT_KEY_OPCODE;
        cdb[1] = 0;
        cdb[2] = (self.lba_or_starting_offset >> 24) as u8;
        cdb[3] = (self.lba_or_starting_offset >> 16) as u8;
        cdb[4] = (self.lba_or_starting_offset >> 8) as u8;
        cdb[5] = self.lba_or_starting_offset as u8;
        cdb[6] = self.block_count_function;
        cdb[7] = self.key_class;
        cdb[8] = (self.allocation_length >> 8) as u8;
        cdb[9] = self.allocation_length as u8;
        // AGID occupies bits 7..6 (the two high bits) and Key Format
        // bits 5..0 — MMC-6 Table 513.
        cdb[10] = ((self.agid & 0x03) << 6) | (self.key_format & 0x3F);
        cdb[11] = self.control;
        cdb
    }

    /// Inverse of [`ReportKey::cdb`]: reconstruct from 12 bytes. Used
    /// by [`MockDrive`] to dispatch + by tests. Returns
    /// [`AacsError::InvalidValue`] when the opcode byte is not
    /// `0xA4`.
    pub fn parse_cdb(cdb: &[u8; MMC_CDB_LEN]) -> Result<Self, AacsError> {
        if cdb[0] != REPORT_KEY_OPCODE {
            return Err(AacsError::InvalidValue {
                what: "REPORT_KEY opcode",
                value: cdb[0] as u64,
            });
        }
        Ok(Self {
            key_class: cdb[7],
            key_format: cdb[10] & 0x3F,
            agid: (cdb[10] >> 6) & 0x03,
            lba_or_starting_offset: ((cdb[2] as u32) << 24)
                | ((cdb[3] as u32) << 16)
                | ((cdb[4] as u32) << 8)
                | (cdb[5] as u32),
            block_count_function: cdb[6],
            allocation_length: ((cdb[8] as u16) << 8) | (cdb[9] as u16),
            control: cdb[11],
        })
    }
}

// ---------------------------------------------------------------------
// SEND_KEY (0xA3) CDB
// ---------------------------------------------------------------------

/// Typed builder for the `SEND_KEY` (`0xA3`) CDB.
///
/// Per MMC-6 Table 599 the CDB layout is:
///
/// ```text
///  Byte 0   : Operation Code (0xA3)
///  Bytes 1-5: Reserved
///  Byte 6   : Reserved Function
///  Byte 7   : Key Class
///  Bytes 8-9: Parameter List Length (big-endian)
///  Byte 10  : (AGID << 6) | Key Format
///  Byte 11  : Control
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendKey {
    /// Key Class byte — AACS uses [`KEY_CLASS_AACS`] (`0x02`).
    pub key_class: u8,
    /// Key Format value (low 6 bits of byte 10).
    pub key_format: u8,
    /// Authentication Grant ID (high 2 bits of byte 10). `0..=3`.
    pub agid: u8,
    /// Parameter list length in bytes the host will send (bytes 8..9,
    /// big-endian).
    pub parameter_list_length: u16,
    /// SAM-3 control byte — typically `0x00`.
    pub control: u8,
}

impl SendKey {
    /// Constructor for the Host Certificate Challenge command
    /// (Key Format `0x01`, Key Class `0x02`). Parameter List Length
    /// is 116 bytes (`Hn || Host Certificate`).
    pub fn aacs_host_cert_challenge(agid: u8) -> Self {
        Self {
            key_class: KEY_CLASS_AACS,
            key_format: KF_SEND_AACS_HOST_CERT_CHAL,
            agid: agid & 0x03,
            // 4-byte header + 20-byte Hn + 92-byte Host Certificate.
            parameter_list_length: 116,
            control: 0,
        }
    }

    /// Constructor for the Host Key command (Key Format `0x02`).
    /// Parameter List Length is 84 bytes (`Hv || Hsig`).
    pub fn aacs_host_key(agid: u8) -> Self {
        Self {
            key_class: KEY_CLASS_AACS,
            key_format: KF_SEND_AACS_HOST_KEY,
            agid: agid & 0x03,
            // 4-byte header + 40-byte Hv + 40-byte Hsig.
            parameter_list_length: 84,
            control: 0,
        }
    }

    /// Constructor for the Invalidate-AGID command (Key Format
    /// `0x3F`). Parameter List Length is zero.
    pub fn aacs_invalidate_agid(agid: u8) -> Self {
        Self {
            key_class: KEY_CLASS_AACS,
            key_format: KF_SEND_AACS_INVALIDATE_AGID,
            agid: agid & 0x03,
            parameter_list_length: 0,
            control: 0,
        }
    }

    /// Serialize this CDB into 12 bytes per MMC-6 Table 599.
    pub fn cdb(&self) -> [u8; MMC_CDB_LEN] {
        let mut cdb = [0u8; MMC_CDB_LEN];
        cdb[0] = SEND_KEY_OPCODE;
        cdb[1] = 0;
        cdb[2] = 0;
        cdb[3] = 0;
        cdb[4] = 0;
        cdb[5] = 0;
        cdb[6] = 0;
        cdb[7] = self.key_class;
        cdb[8] = (self.parameter_list_length >> 8) as u8;
        cdb[9] = self.parameter_list_length as u8;
        cdb[10] = ((self.agid & 0x03) << 6) | (self.key_format & 0x3F);
        cdb[11] = self.control;
        cdb
    }

    /// Inverse of [`SendKey::cdb`]. Returns
    /// [`AacsError::InvalidValue`] when the opcode byte is not
    /// `0xA3`.
    pub fn parse_cdb(cdb: &[u8; MMC_CDB_LEN]) -> Result<Self, AacsError> {
        if cdb[0] != SEND_KEY_OPCODE {
            return Err(AacsError::InvalidValue {
                what: "SEND_KEY opcode",
                value: cdb[0] as u64,
            });
        }
        Ok(Self {
            key_class: cdb[7],
            key_format: cdb[10] & 0x3F,
            agid: (cdb[10] >> 6) & 0x03,
            parameter_list_length: ((cdb[8] as u16) << 8) | (cdb[9] as u16),
            control: cdb[11],
        })
    }
}

// ---------------------------------------------------------------------
// READ_DISC_STRUCTURE (0xAD) CDB
// ---------------------------------------------------------------------

/// Typed builder for the `READ_DISC_STRUCTURE` (`0xAD`) CDB.
///
/// Per MMC-6 Table 381 the CDB layout is:
///
/// ```text
///  Byte 0   : Operation Code (0xAD)
///  Byte 1   : Reserved [7..4] | Media Type [3..0]
///  Bytes 2-5: Address (big-endian) — Format-dependent
///  Byte 6   : Layer Number — Format-dependent
///  Byte 7   : Format
///  Bytes 8-9: Allocation Length (big-endian)
///  Byte 10  : (AGID << 6) | Reserved
///  Byte 11  : Control
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadDiscStructure {
    /// Media Type — low 4 bits of byte 1. `0x00` = DVD (Table 382),
    /// `0x01` = BD.
    pub media_type: u8,
    /// Address field (bytes 2..5, big-endian). MKB-pack-number for
    /// Format `0x83`; otherwise reserved.
    pub address: u32,
    /// Layer Number — byte 6. Used for Format `0x83`; otherwise
    /// reserved.
    pub layer_number: u8,
    /// Format Code byte 7 — `FORMAT_AACS_*`.
    pub format: u8,
    /// Allocation length in bytes (bytes 8..9, big-endian).
    pub allocation_length: u16,
    /// AGID (high 2 bits of byte 10). Used when Format is one of
    /// `0x02/0x06/0x07/0x80/0x81/0x82/0x84/0x86` and Address is 0.
    /// Format `0x85` (Bus-Encryption Sector Extents) does not require
    /// authentication — the field is encoded but the drive ignores it
    /// per MMC-6 §6.22.2.7.
    pub agid: u8,
    /// SAM-3 control byte — typically `0x00`.
    pub control: u8,
}

impl ReadDiscStructure {
    /// Constructor for the AACS Volume Identifier read (Format
    /// `0x80`, Media Type BD). Returns 36 bytes (4-byte header +
    /// 16-byte Volume ID + 16-byte MAC).
    pub fn aacs_volume_id(agid: u8) -> Self {
        Self {
            media_type: MEDIA_TYPE_BD,
            address: 0,
            layer_number: 0,
            format: FORMAT_AACS_VOLUME_ID,
            // 4-byte header + 16-byte Volume ID + 16-byte MAC.
            allocation_length: 36,
            agid: agid & 0x03,
            control: 0,
        }
    }

    /// Constructor for the AACS Pre-recorded Media Serial Number
    /// (PMSN) read (Format `0x81`, AACS Common §4.14.3.2 Table 4-16).
    /// Returns 36 bytes (4-byte header + 16-byte PMSN + 16-byte MAC).
    pub fn aacs_media_serial(agid: u8) -> Self {
        Self {
            media_type: MEDIA_TYPE_BD,
            address: 0,
            layer_number: 0,
            format: FORMAT_AACS_MEDIA_SERIAL,
            allocation_length: 36,
            agid: agid & 0x03,
            control: 0,
        }
    }

    /// Constructor for the AACS Media Identifier read (Format `0x82`,
    /// AACS Common §4.14.3.3 Table 4-17). Returns 36 bytes (4-byte
    /// header + 16-byte Media Identifier + 16-byte MAC) — same wire
    /// layout as the Volume Identifier (Table 4-15) and the PMSN
    /// (Table 4-16).
    pub fn aacs_media_id(agid: u8) -> Self {
        Self {
            media_type: MEDIA_TYPE_BD,
            address: 0,
            layer_number: 0,
            format: FORMAT_AACS_MEDIA_ID,
            allocation_length: 36,
            agid: agid & 0x03,
            control: 0,
        }
    }

    /// Constructor for an AACS Media Key Block pack read
    /// (Format `0x83`). The `pack_number` argument goes into the
    /// `Address` field. Pack number `0xFF` returns only the 4-byte
    /// header (AACS Common §4.14.3, fourth paragraph of the
    /// READ DISC STRUCTURE introduction).
    pub fn aacs_media_key_block_pack(agid: u8, pack_number: u32, layer: u8) -> Self {
        Self {
            media_type: MEDIA_TYPE_BD,
            address: pack_number,
            layer_number: layer,
            format: FORMAT_AACS_MEDIA_KEY_BLOCK,
            // The MKB pack itself is up to 32 KiB; callers can adjust
            // this when issuing the command via the public field.
            allocation_length: 32 * 1024 + 4,
            agid: agid & 0x03,
            control: 0,
        }
    }

    /// Constructor for an AACS Data Keys read (Format `0x84`, AACS
    /// Common §4.14.3.5 Table 4-19). Returns 36 bytes total — 4-byte
    /// header (`length:u16=0x0022 || reserved:u16`) + 16-byte encrypted
    /// Read Data Key (bytes 4..19) + 16-byte encrypted Write Data Key
    /// (bytes 20..35). The two-byte length field value `0x0022` counts
    /// bytes 2..35 (34 bytes) per the MMC-6 convention. Both Data Keys
    /// are wrapped under the Bus Key established by the §4.3 AKE using
    /// AES-128E (§4.11). This command requires the Bus-Key-established
    /// state of the AACS authentication; otherwise the drive shall
    /// terminate with COPY PROTECTION KEY EXCHANGE FAILURE – KEY NOT
    /// ESTABLISHED (§4.14.3.5 final paragraph).
    pub fn aacs_data_keys(agid: u8) -> Self {
        Self {
            media_type: MEDIA_TYPE_BD,
            address: 0,
            layer_number: 0,
            format: FORMAT_AACS_DATA_KEYS,
            // 4-byte header + 16-byte Krd + 16-byte Kwd = 36 bytes.
            allocation_length: 36,
            agid: agid & 0x03,
            control: 0,
        }
    }

    /// Constructor for an AACS Bus-Encryption Sector Extents read
    /// (Format `0x85`, AACS Common §4.14.3.6 Table 4-20 / MMC-6
    /// §6.22.3.1.6 Table 389). The drive returns
    /// `[length:u16][reserved:u8][maximum:u8][reserved:8]` followed by
    /// `N` 16-byte LBA-Extent records, where `N` is the count of
    /// currently-defined Bus-Encryption Sector Extents. The Data Length
    /// field encodes `N*16 + 2`; an empty table yields length `2` and
    /// zero records (§4.14.3.6 paragraph 2). This Format Code does not
    /// require AACS authentication (§4.14.3.6 final sentence) — the
    /// AGID field is reserved per MMC-6 §6.22.2.7.
    ///
    /// `allocation_length` is sized for the worst case of 256 extents
    /// (the spec maximum the field can encode per Table 4-20): 12 bytes
    /// of header + reserved + 256 * 16-byte records = 4108 bytes.
    /// Callers issuing the command against a known smaller bound may
    /// shrink `allocation_length` after constructing the CDB.
    pub fn aacs_bus_encryption_sector_extents() -> Self {
        Self {
            media_type: MEDIA_TYPE_BD,
            address: 0,
            layer_number: 0,
            format: FORMAT_AACS_BUS_ENCRYPTION_SECTOR_EXTENTS,
            allocation_length: 12 + 256 * BUS_ENCRYPTION_SECTOR_EXTENT_LEN as u16,
            agid: 0,
            control: 0,
        }
    }

    /// Serialize this CDB into 12 bytes per MMC-6 Table 381.
    pub fn cdb(&self) -> [u8; MMC_CDB_LEN] {
        let mut cdb = [0u8; MMC_CDB_LEN];
        cdb[0] = READ_DISC_STRUCTURE_OPCODE;
        cdb[1] = self.media_type & 0x0F;
        cdb[2] = (self.address >> 24) as u8;
        cdb[3] = (self.address >> 16) as u8;
        cdb[4] = (self.address >> 8) as u8;
        cdb[5] = self.address as u8;
        cdb[6] = self.layer_number;
        cdb[7] = self.format;
        cdb[8] = (self.allocation_length >> 8) as u8;
        cdb[9] = self.allocation_length as u8;
        cdb[10] = (self.agid & 0x03) << 6;
        cdb[11] = self.control;
        cdb
    }

    /// Inverse of [`ReadDiscStructure::cdb`]. Returns
    /// [`AacsError::InvalidValue`] when the opcode byte is not
    /// `0xAD`.
    pub fn parse_cdb(cdb: &[u8; MMC_CDB_LEN]) -> Result<Self, AacsError> {
        if cdb[0] != READ_DISC_STRUCTURE_OPCODE {
            return Err(AacsError::InvalidValue {
                what: "READ_DISC_STRUCTURE opcode",
                value: cdb[0] as u64,
            });
        }
        Ok(Self {
            media_type: cdb[1] & 0x0F,
            address: ((cdb[2] as u32) << 24)
                | ((cdb[3] as u32) << 16)
                | ((cdb[4] as u32) << 8)
                | (cdb[5] as u32),
            layer_number: cdb[6],
            format: cdb[7],
            allocation_length: ((cdb[8] as u16) << 8) | (cdb[9] as u16),
            agid: (cdb[10] >> 6) & 0x03,
            control: cdb[11],
        })
    }
}

// ---------------------------------------------------------------------
// SEND_DISC_STRUCTURE (0xBF) CDB
// ---------------------------------------------------------------------

/// Typed builder for the `SEND_DISC_STRUCTURE` (`0xBF`) CDB — the
/// host→drive counterpart of [`ReadDiscStructure`].
///
/// Per AACS Common §4.14.5 Table 4-26 (MMC-6 §6.36.2.1 Table 572) the
/// CDB layout is:
///
/// ```text
///  Byte 0   : Operation Code (0xBF)
///  Byte 1   : Reserved [7..4] | Media Type [3..0]
///  Bytes 2-6: Reserved
///  Byte 7   : Format Code
///  Bytes 8-9: Parameter List Length (big-endian)
///  Byte 10  : (AGID << 6) | Reserved
///  Byte 11  : Control
/// ```
///
/// AACS defines two Format Codes for this command (§4.14.5 Table 4-27):
/// `0x84` (Write Data Key) and `0x85` (Bus-Encryption Sector Extents).
/// Per MMC-6 §6.36.2.4 the AGID field is used only when the Format Code
/// is `0x17` or `0x84`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendDiscStructure {
    /// Media Type — low 4 bits of byte 1. `0x00` = DVD, `0x01` = BD.
    pub media_type: u8,
    /// Format Code byte 7 — `0x84` (Write Data Key) or `0x85`
    /// (Bus-Encryption Sector Extents) for AACS per Table 4-27.
    pub format: u8,
    /// Parameter list length in bytes the host will send (bytes 8..9,
    /// big-endian).
    pub parameter_list_length: u16,
    /// AGID (high 2 bits of byte 10). Used when the Format Code is
    /// `0x84` per MMC-6 §6.36.2.4; reserved otherwise.
    pub agid: u8,
    /// SAM-3 control byte — typically `0x00`.
    pub control: u8,
}

impl SendDiscStructure {
    /// Constructor for the AACS Write Data Key send (Format `0x84`,
    /// Media Type BD) per AACS Common §4.14.5.1. The parameter list is
    /// 20 bytes — 4-byte header (`length:u16=0x0012 || reserved:u16`) +
    /// the 16-byte replacement Write Data Key encrypted under the Bus
    /// Key with AES-128E (Table 4-28). Requires the Bus-Key-established
    /// state of the §4.3 AKE; otherwise the drive shall terminate with
    /// COPY PROTECTION KEY EXCHANGE FAILURE – KEY NOT ESTABLISHED, and
    /// a host not authorized to send the Write Data Key shall be
    /// answered with INSUFFICIENT PERMISSION (§4.14.5.1 final
    /// paragraph).
    pub fn aacs_write_data_key(agid: u8) -> Self {
        Self {
            media_type: MEDIA_TYPE_BD,
            format: FORMAT_AACS_WRITE_DATA_KEY,
            // 4-byte header + 16-byte encrypted Write Data Key.
            parameter_list_length: 20,
            agid: agid & 0x03,
            control: 0,
        }
    }

    /// Constructor for the AACS Bus-Encryption Sector Extents send
    /// (Format `0x85`, Media Type BD) per AACS Common §4.14.5.2
    /// Table 4-29 — the host→drive command that establishes the sector
    /// extents whose Bus Encryption Flag shall be set when data is
    /// written. The parameter list is `4 + N*16` bytes: a 4-byte header
    /// (`length:u16 = 2 + N*16 || reserved:u16`) followed by `N` 16-byte
    /// LBA Extent Structures. `num_extents` is `N`; passing `0` clears
    /// the drive's current extents per §4.14.5.2 paragraph 1 ("If N is
    /// zero, the logical unit shall clear its Bus-Encrypted Sector
    /// Extents."). Unlike Format `0x84`, this command does not require
    /// AACS authentication (§4.14.5.2 final sentence), so the AGID field
    /// is reserved (MMC-6 §6.36.2.4 lists only `0x17` / `0x84`).
    pub fn aacs_bus_encryption_sector_extents(num_extents: usize) -> Self {
        Self {
            media_type: MEDIA_TYPE_BD,
            // 4-byte header + N * 16-byte LBA Extent Structures.
            parameter_list_length: (4 + num_extents * BUS_ENCRYPTION_SECTOR_EXTENT_LEN) as u16,
            format: FORMAT_AACS_BUS_ENCRYPTION_SECTOR_EXTENTS,
            agid: 0,
            control: 0,
        }
    }

    /// Serialize this CDB into 12 bytes per AACS Common Table 4-26 /
    /// MMC-6 Table 572.
    pub fn cdb(&self) -> [u8; MMC_CDB_LEN] {
        let mut cdb = [0u8; MMC_CDB_LEN];
        cdb[0] = SEND_DISC_STRUCTURE_OPCODE;
        cdb[1] = self.media_type & 0x0F;
        // Bytes 2..6 Reserved.
        cdb[7] = self.format;
        cdb[8] = (self.parameter_list_length >> 8) as u8;
        cdb[9] = self.parameter_list_length as u8;
        cdb[10] = (self.agid & 0x03) << 6;
        cdb[11] = self.control;
        cdb
    }

    /// Inverse of [`SendDiscStructure::cdb`]. Returns
    /// [`AacsError::InvalidValue`] when the opcode byte is not
    /// `0xBF`.
    pub fn parse_cdb(cdb: &[u8; MMC_CDB_LEN]) -> Result<Self, AacsError> {
        if cdb[0] != SEND_DISC_STRUCTURE_OPCODE {
            return Err(AacsError::InvalidValue {
                what: "SEND_DISC_STRUCTURE opcode",
                value: cdb[0] as u64,
            });
        }
        Ok(Self {
            media_type: cdb[1] & 0x0F,
            format: cdb[7],
            parameter_list_length: ((cdb[8] as u16) << 8) | (cdb[9] as u16),
            agid: (cdb[10] >> 6) & 0x03,
            control: cdb[11],
        })
    }
}

// ---------------------------------------------------------------------
// Response payload structures (AACS sub-payloads)
// ---------------------------------------------------------------------

/// Decoded AGID-for-AACS response (MMC-6 Table 526; AACS Common
/// Table 4-7).
///
/// The on-wire layout is `[length:u16=0x0006][reserved:u16][rsvd:u8 x3]
/// [AGID:2 | reserved:6]`. The 2-bit AGID lives in the **top** 2 bits
/// of byte 3 of the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgidResponse {
    /// The Authentication Grant ID assigned by the drive.
    pub agid: u8,
}

/// Decoded Drive Certificate Challenge response (MMC-6 Table 527;
/// AACS Common Table 4-8). 116 bytes on the wire — 4-byte header +
/// 20-byte `Dn` + 92-byte Drive Certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveCertChallengeResponse {
    /// 160-bit nonce generated by the drive.
    pub drive_nonce: [u8; DRIVE_NONCE_LEN],
    /// 92-byte Drive Certificate (`Cert_d`) per AACS Common §4.1.
    pub drive_cert: [u8; DRIVE_CERT_LEN],
}

/// Decoded Drive Key response (MMC-6 Table 528; AACS Common
/// Table 4-9). 84 bytes on the wire — 4-byte header + 40-byte `Dv`
/// elliptic curve point + 40-byte `Dsig` ECDSA-secp160r1 signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveKeyResponse {
    /// 320-bit elliptic curve point `Dv = Dk * G`.
    pub dv: [u8; EC_POINT_LEN],
    /// 320-bit ECDSA signature `Dsig = AACS_Sign(Dpriv, Hn || Dv)`.
    pub dsig: [u8; EC_SIG_LEN],
}

/// Decoded Drive Certificate response (MMC-6 Table 531). 96 bytes on
/// the wire — 4-byte header + 92-byte Drive Certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveCertResponse {
    /// 92-byte Drive Certificate (`Cert_d`).
    pub drive_cert: [u8; DRIVE_CERT_LEN],
}

/// Decoded AACS Volume Identifier response (MMC-6 Table 384; AACS
/// Common Table 4-15). 36 bytes on the wire — 4-byte header +
/// 16-byte Volume ID + 16-byte MAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeIdResponse {
    /// 128-bit Volume Identifier (`ID_v`).
    pub volume_id: [u8; VOLUME_ID_LEN],
    /// 128-bit Message Authentication Code `Dm` computed by the
    /// drive over the Volume Identifier under the Bus Key
    /// (AACS Common §4.4 step 3).
    pub mac: [u8; ID_MAC_LEN],
}

/// Decoded AACS Pre-recorded Media Serial Number (PMSN) response
/// (MMC-6 Table 384; AACS Common §4.14.3.2 Table 4-16). 36 bytes on
/// the wire — 4-byte header + 16-byte PMSN + 16-byte MAC. The MAC
/// is `Dm = CMAC(BK, PMSN)` per §4.5 step 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaSerialNumberResponse {
    /// 128-bit Pre-recorded Media Serial Number.
    pub pmsn: [u8; VOLUME_ID_LEN],
    /// 128-bit MAC over the PMSN keyed under the Bus Key.
    pub mac: [u8; ID_MAC_LEN],
}

/// Decoded AACS Media Identifier response (MMC-6 Table 384; AACS
/// Common §4.14.3.3 Table 4-17). 36 bytes on the wire — 4-byte
/// header + 16-byte Media Identifier + 16-byte MAC. The MAC is
/// `Dm = CMAC(BK, MediaID)` per §4.6 step 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaIdentifierResponse {
    /// 128-bit Media Identifier.
    pub media_id: [u8; VOLUME_ID_LEN],
    /// 128-bit MAC over the Media Identifier keyed under the Bus Key.
    pub mac: [u8; ID_MAC_LEN],
}

/// Decoded Binding Nonce response (MMC-6 Table 529 / Table 530; AACS
/// Common §4.14.2.4 Table 4-10 / §4.14.2.5 Table 4-11). 36 bytes on
/// the wire — 4-byte header (`length:u16=0x0022 || reserved:u16`) +
/// 16-byte Binding Nonce + 16-byte MAC.
///
/// The wire layout is identical for the *generate-and-store*
/// (Key Format `0x20`) and *read-from-medium* (Key Format `0x21`)
/// variants; the distinction lives entirely in the CDB Key Format
/// field, not the response payload. The Bus Key established by the
/// §4.3 AKE keys the MAC (`Dm = CMAC(BK, Nonce)` per the §4.7.1
/// transferred-binding-nonce protocol).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingNonceResponse {
    /// 128-bit Binding Nonce returned by the drive.
    pub binding_nonce: [u8; BINDING_NONCE_LEN],
    /// 128-bit MAC over the Binding Nonce keyed under the Bus Key.
    pub mac: [u8; BINDING_NONCE_MAC_LEN],
}

/// Decoded AACS Media Key Block Pack response (MMC-6 Table 384; AACS
/// Common §4.14.3.4 Table 4-18). Variable size on the wire: 4-byte
/// header `[length:u16][reserved:u8][total_packs:u8]` followed by
/// up to 32,768 bytes of MKB pack data. The MKB itself is *not*
/// AACS-LA-bus-encrypted (the spec note in §4.14.3.4 is explicit:
/// "the Media Key Block is transferred without using the AACS
/// authentication process").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MkbPackResponse {
    /// Total number of MKB packs the drive can return for this disc
    /// (ceiling of `MKB-data-length / 32,768`). Packs are addressed by
    /// `pack_number = 0..total_packs - 1` via the `Address` field of
    /// the [`ReadDiscStructure`] CDB.
    pub total_packs: u8,
    /// MKB pack data, up to 32,768 bytes. The last pack may end with
    /// zero-padding.
    pub pack_data: Vec<u8>,
}

/// Decoded AACS Data Keys response (MMC-6 Table 384; AACS Common
/// §4.14.3.5 Table 4-19). 40 bytes on the wire — 4-byte header
/// (`length:u16=0x0022 || reserved:u16`) + 16-byte encrypted Read
/// Data Key (bytes 4..19) + 16-byte encrypted Write Data Key
/// (bytes 20..35).
///
/// Both Data Keys are wrapped under the Bus Key established by the
/// §4.3 AKE using AES-128E (§4.11 paragraph 4):
///
/// ```text
///   wrapped_Krd = AES-128E(BK, Krd)
///   wrapped_Kwd = AES-128E(BK, Kwd)
/// ```
///
/// The host recovers each plaintext Data Key with AES-128D under the
/// same Bus Key. The plaintext Read Data Key `Krd` is derived by the
/// drive as `Krd = AES-128E(Sd, IDm)` from a confidential Drive Seed
/// `Sd` and the Media Identifier (or Volume Identifier for
/// pre-recorded media); the Write Data Key `Kwd` defaults to the
/// same value but the host may overwrite it via SEND DISC STRUCTURE
/// Format `0x84` (§4.14.5.1). Once recovered, the keys feed AES-128
/// CBC bus-encryption / bus-decryption of sector payloads flagged
/// for §4.11 protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataKeysResponse {
    /// 128-bit Read Data Key in its on-the-wire AES-128E(`BK`, ·)
    /// wrapped form. Use [`DataKeysResponse::decrypt_read_data_key`]
    /// to recover the plaintext `Krd`.
    pub read_data_key_encrypted: [u8; DATA_KEY_LEN],
    /// 128-bit Write Data Key in its on-the-wire AES-128E(`BK`, ·)
    /// wrapped form. The host shall ignore this field when the
    /// logical unit is read-only or the current disc is read-only
    /// (Table 4-19 paragraph 5). Use
    /// [`DataKeysResponse::decrypt_write_data_key`] to recover the
    /// plaintext `Kwd`.
    pub write_data_key_encrypted: [u8; DATA_KEY_LEN],
}

impl DataKeysResponse {
    /// Recover the plaintext Read Data Key `Krd` by applying AES-128D
    /// under the Bus Key per AACS Common §4.11 ("the Bus Key is used
    /// to protect the Data Keys using AES-128E"). The inverse of the
    /// drive's wrap step.
    pub fn decrypt_read_data_key(&self, bus_key: &[u8; 16]) -> [u8; DATA_KEY_LEN] {
        crate::aes::aes_128_ecb_decrypt(bus_key, &self.read_data_key_encrypted)
    }

    /// Recover the plaintext Write Data Key `Kwd` by applying AES-128D
    /// under the Bus Key per AACS Common §4.11. The drive sets `Kwd`
    /// equal to `Krd` on disc insert / reset / power-on (§4.11
    /// paragraph 6); the host may overwrite the drive's copy via
    /// SEND DISC STRUCTURE Format `0x84` (§4.14.5.1).
    pub fn decrypt_write_data_key(&self, bus_key: &[u8; 16]) -> [u8; DATA_KEY_LEN] {
        crate::aes::aes_128_ecb_decrypt(bus_key, &self.write_data_key_encrypted)
    }
}

/// One Bus-Encryption Sector Extent — a contiguous LBA range whose
/// sectors are flagged for §4.11 Bus Encryption.
///
/// `start_lba` is the first logical block of the extent and `lba_count`
/// is the number of consecutive blocks the extent covers, both 32-bit
/// big-endian fields on the wire (AACS Common §4.14.3.6 Table 4-20:
/// "Start LBA" at bytes 12+n*16..15+n*16; "LBA Count" at
/// 16+n*16..19+n*16). Per §4.14.3.6 paragraph 3 the extents are sorted
/// by `start_lba` ascending and shall not overlap; the parser preserves
/// the on-wire order verbatim and does not enforce the sort/no-overlap
/// invariant (the SEND DISC STRUCTURE Format `0x85` ingest path is
/// where the logical unit rejects malformed tables per §4.14.5.x).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BusEncryptionSectorExtent {
    /// First LBA of the extent. 32-bit big-endian on the wire.
    pub start_lba: u32,
    /// Number of consecutive sectors the extent covers. 32-bit
    /// big-endian on the wire.
    pub lba_count: u32,
}

/// Decoded AACS Bus-Encryption Sector Extents response (READ DISC
/// STRUCTURE Format `0x85`; MMC-6 Table 389 / AACS Common Table 4-20).
///
/// Wire layout (per Table 4-20):
///
/// ```text
///  Byte  | Field
///  0..1  | DISC STRUCTURE Data Length (= N*16 + 2)
///  2     | Reserved
///  3     | Maximum Number of Bus-Encryption Sector Extents (1..256;
///        | the value 0 denotes 256)
///  4..11 | Reserved
/// 12..15 | Start LBA, extent 0
/// 16..19 | LBA Count, extent 0
///  ...   | …
/// 4+n*16..11+n*16 | Reserved
/// 12+n*16..15+n*16 | Start LBA, extent n
/// 16+n*16..19+n*16 | LBA Count, extent n
/// ```
///
/// where `n = N - 1`. When `N = 0` the Data Length field equals `2`
/// and no extent records follow (§4.14.3.6 paragraph 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusEncryptionSectorExtentsResponse {
    /// Maximum number of Bus-Encryption Sector Extents the logical
    /// unit can store at one time. Always in the range `1..=256`;
    /// the on-wire encoding represents `256` as the byte value `0`
    /// (§4.14.3.6 paragraph 3 final sentence). This field is decoded
    /// to its semantic value, so `256` is returned literally here even
    /// when the wire byte was `0`.
    pub maximum: u16,
    /// The currently-defined Bus-Encryption Sector Extents, in wire
    /// order (sorted by `start_lba` ascending per §4.14.3.6 paragraph 3).
    pub extents: Vec<BusEncryptionSectorExtent>,
}

// ---------------------------------------------------------------------
// Response parsers
// ---------------------------------------------------------------------

fn read_u16_be(buf: &[u8], what: &'static str) -> Result<u16, AacsError> {
    if buf.len() < 2 {
        return Err(AacsError::Truncated(what));
    }
    Ok(((buf[0] as u16) << 8) | (buf[1] as u16))
}

/// Parse the 8-byte response payload for `REPORT_KEY` Key Format
/// `0x00` (AGID for AACS) per MMC-6 Table 526 / AACS Common
/// Table 4-7. Returns the assigned AGID (the top 2 bits of byte 3
/// of the AGID structure, i.e. byte 7 of the response).
pub fn parse_report_key_agid(buf: &[u8]) -> Result<AgidResponse, AacsError> {
    let length = read_u16_be(buf, "REPORT_KEY AGID header")?;
    if length != 0x0006 {
        return Err(AacsError::InvalidValue {
            what: "REPORT_KEY AGID length",
            value: length as u64,
        });
    }
    if buf.len() < 8 {
        return Err(AacsError::Truncated("REPORT_KEY AGID payload"));
    }
    Ok(AgidResponse {
        agid: (buf[7] >> 6) & 0x03,
    })
}

/// Parse the 116-byte response payload for `REPORT_KEY` Key Format
/// `0x01` (Drive Certificate Challenge) per MMC-6 Table 527 /
/// AACS Common Table 4-8.
pub fn parse_report_key_drive_cert_chal(
    buf: &[u8],
) -> Result<DriveCertChallengeResponse, AacsError> {
    let length = read_u16_be(buf, "REPORT_KEY Drive Cert Challenge header")?;
    if length != 0x0072 {
        return Err(AacsError::InvalidValue {
            what: "REPORT_KEY Drive Cert Challenge length",
            value: length as u64,
        });
    }
    if buf.len() < 116 {
        return Err(AacsError::Truncated(
            "REPORT_KEY Drive Cert Challenge payload",
        ));
    }
    let mut drive_nonce = [0u8; DRIVE_NONCE_LEN];
    drive_nonce.copy_from_slice(&buf[4..4 + DRIVE_NONCE_LEN]);
    let mut drive_cert = [0u8; DRIVE_CERT_LEN];
    drive_cert.copy_from_slice(&buf[24..24 + DRIVE_CERT_LEN]);
    Ok(DriveCertChallengeResponse {
        drive_nonce,
        drive_cert,
    })
}

/// Parse the 84-byte response payload for `REPORT_KEY` Key Format
/// `0x02` (Drive Key) per MMC-6 Table 528 / AACS Common Table 4-9.
pub fn parse_report_key_drive_key(buf: &[u8]) -> Result<DriveKeyResponse, AacsError> {
    let length = read_u16_be(buf, "REPORT_KEY Drive Key header")?;
    if length != 0x0052 {
        return Err(AacsError::InvalidValue {
            what: "REPORT_KEY Drive Key length",
            value: length as u64,
        });
    }
    if buf.len() < 84 {
        return Err(AacsError::Truncated("REPORT_KEY Drive Key payload"));
    }
    let mut dv = [0u8; EC_POINT_LEN];
    dv.copy_from_slice(&buf[4..4 + EC_POINT_LEN]);
    let mut dsig = [0u8; EC_SIG_LEN];
    dsig.copy_from_slice(&buf[44..44 + EC_SIG_LEN]);
    Ok(DriveKeyResponse { dv, dsig })
}

/// Parse the 96-byte response payload for `REPORT_KEY` Key Format
/// `0x38` (Drive Certificate) per MMC-6 Table 531.
pub fn parse_report_key_drive_cert(buf: &[u8]) -> Result<DriveCertResponse, AacsError> {
    let length = read_u16_be(buf, "REPORT_KEY Drive Cert header")?;
    if length != 0x005E {
        return Err(AacsError::InvalidValue {
            what: "REPORT_KEY Drive Cert length",
            value: length as u64,
        });
    }
    if buf.len() < 96 {
        return Err(AacsError::Truncated("REPORT_KEY Drive Cert payload"));
    }
    let mut drive_cert = [0u8; DRIVE_CERT_LEN];
    drive_cert.copy_from_slice(&buf[4..4 + DRIVE_CERT_LEN]);
    Ok(DriveCertResponse { drive_cert })
}

/// Parse the 36-byte response payload for `READ_DISC_STRUCTURE`
/// Format `0x80` (AACS Volume Identifier) per MMC-6 Table 384 /
/// AACS Common Table 4-15.
pub fn parse_volume_id_response(buf: &[u8]) -> Result<VolumeIdResponse, AacsError> {
    let length = read_u16_be(buf, "Volume ID response header")?;
    if length != 0x0022 {
        return Err(AacsError::InvalidValue {
            what: "Volume ID response length",
            value: length as u64,
        });
    }
    if buf.len() < 36 {
        return Err(AacsError::Truncated("Volume ID response payload"));
    }
    let mut volume_id = [0u8; VOLUME_ID_LEN];
    volume_id.copy_from_slice(&buf[4..4 + VOLUME_ID_LEN]);
    let mut mac = [0u8; ID_MAC_LEN];
    mac.copy_from_slice(&buf[20..20 + ID_MAC_LEN]);
    Ok(VolumeIdResponse { volume_id, mac })
}

/// Parse the 36-byte response payload for `READ_DISC_STRUCTURE`
/// Format `0x81` (AACS Pre-recorded Media Serial Number) per MMC-6
/// Table 384 / AACS Common §4.14.3.2 Table 4-16. The wire layout is
/// `[length:u16=0x0022][reserved:u16][PMSN:16][MAC:16]`.
pub fn parse_media_serial_response(buf: &[u8]) -> Result<MediaSerialNumberResponse, AacsError> {
    let length = read_u16_be(buf, "PMSN response header")?;
    if length != 0x0022 {
        return Err(AacsError::InvalidValue {
            what: "PMSN response length",
            value: length as u64,
        });
    }
    if buf.len() < 36 {
        return Err(AacsError::Truncated("PMSN response payload"));
    }
    let mut pmsn = [0u8; VOLUME_ID_LEN];
    pmsn.copy_from_slice(&buf[4..4 + VOLUME_ID_LEN]);
    let mut mac = [0u8; ID_MAC_LEN];
    mac.copy_from_slice(&buf[20..20 + ID_MAC_LEN]);
    Ok(MediaSerialNumberResponse { pmsn, mac })
}

/// Parse the 36-byte response payload for `READ_DISC_STRUCTURE`
/// Format `0x82` (AACS Media Identifier) per MMC-6 Table 384 / AACS
/// Common §4.14.3.3 Table 4-17. The wire layout is identical to
/// Volume ID and PMSN: `[length:u16=0x0022][reserved:u16]
/// [Media ID:16][MAC:16]`.
pub fn parse_media_id_response(buf: &[u8]) -> Result<MediaIdentifierResponse, AacsError> {
    let length = read_u16_be(buf, "Media ID response header")?;
    if length != 0x0022 {
        return Err(AacsError::InvalidValue {
            what: "Media ID response length",
            value: length as u64,
        });
    }
    if buf.len() < 36 {
        return Err(AacsError::Truncated("Media ID response payload"));
    }
    let mut media_id = [0u8; VOLUME_ID_LEN];
    media_id.copy_from_slice(&buf[4..4 + VOLUME_ID_LEN]);
    let mut mac = [0u8; ID_MAC_LEN];
    mac.copy_from_slice(&buf[20..20 + ID_MAC_LEN]);
    Ok(MediaIdentifierResponse { media_id, mac })
}

/// Parse the 36-byte response payload for `REPORT_KEY` Key Format
/// `0x20` (Binding Nonce — generated in drive) or Key Format `0x21`
/// (Binding Nonce — read from medium) per AACS Common §4.14.2.4
/// Table 4-10 and §4.14.2.5 Table 4-11 / MMC-6 §6.28.3.2.5 Table 529
/// and §6.28.3.2.6 Table 530.
///
/// Wire layout: `[length:u16=0x0022][reserved:u16][nonce:16][mac:16]`.
/// Both Key Formats share the same response layout, so a single parser
/// covers both. The 16-byte MAC is `Dm = CMAC(BK, Nonce)` per the
/// §4.7.1 / §4.7.2 transferred-binding-nonce protocol; the caller
/// validates it against its own `Hm = CMAC(BK, Nonce)` after deriving
/// the Bus Key.
pub fn parse_report_key_binding_nonce(buf: &[u8]) -> Result<BindingNonceResponse, AacsError> {
    let length = read_u16_be(buf, "Binding Nonce response header")?;
    if length != 0x0022 {
        return Err(AacsError::InvalidValue {
            what: "Binding Nonce response length",
            value: length as u64,
        });
    }
    if buf.len() < 36 {
        return Err(AacsError::Truncated("Binding Nonce response payload"));
    }
    let mut binding_nonce = [0u8; BINDING_NONCE_LEN];
    binding_nonce.copy_from_slice(&buf[4..4 + BINDING_NONCE_LEN]);
    let mut mac = [0u8; BINDING_NONCE_MAC_LEN];
    mac.copy_from_slice(&buf[20..20 + BINDING_NONCE_MAC_LEN]);
    Ok(BindingNonceResponse { binding_nonce, mac })
}

/// Parse the 40-byte response payload for `READ_DISC_STRUCTURE` Format
/// `0x84` (AACS Data Keys) per MMC-6 Table 384 / AACS Common §4.14.3.5
/// Table 4-19.
///
/// Wire layout: `[length:u16=0x0022][reserved:u16][Krd_enc:16][Kwd_enc:16]`.
/// The two 128-bit Data Keys are wrapped under the Bus Key with
/// AES-128E per §4.11; the caller recovers each plaintext key by
/// applying AES-128D under the same Bus Key (see
/// [`DataKeysResponse::decrypt_read_data_key`] /
/// [`DataKeysResponse::decrypt_write_data_key`]).
pub fn parse_data_keys_response(buf: &[u8]) -> Result<DataKeysResponse, AacsError> {
    let length = read_u16_be(buf, "Data Keys response header")?;
    if length != 0x0022 {
        return Err(AacsError::InvalidValue {
            what: "Data Keys response length",
            value: length as u64,
        });
    }
    if buf.len() < 36 {
        return Err(AacsError::Truncated("Data Keys response payload"));
    }
    let mut read_data_key_encrypted = [0u8; DATA_KEY_LEN];
    read_data_key_encrypted.copy_from_slice(&buf[4..4 + DATA_KEY_LEN]);
    let mut write_data_key_encrypted = [0u8; DATA_KEY_LEN];
    write_data_key_encrypted.copy_from_slice(&buf[20..20 + DATA_KEY_LEN]);
    Ok(DataKeysResponse {
        read_data_key_encrypted,
        write_data_key_encrypted,
    })
}

/// Parse the variable-length response payload for `READ_DISC_STRUCTURE`
/// Format `0x85` (AACS Bus-Encryption Sector Extents) per MMC-6 Table
/// 389 / AACS Common §4.14.3.6 Table 4-20.
///
/// Wire layout: `[length:u16][reserved:u8][maximum:u8][reserved:8]`
/// followed by `N` Bus-Encryption Sector Extent records of 16 bytes
/// each, where the `length` field equals `N * 16 + 2`. Each extent
/// record is `[reserved:8 || Start LBA:u32 || LBA Count:u32]`.
///
/// Returns the decoded maximum (`0` on the wire → `256` per the
/// §4.14.3.6 paragraph 3 sentinel; otherwise the literal byte value)
/// and the `Vec` of extents in wire order.
///
/// Errors:
/// * `AacsError::Truncated` — the buffer is shorter than the 4-byte
///   header, or shorter than `2 + length` bytes total (the length
///   field counts everything after itself), or `(length - 2)` is not a
///   multiple of 16 — a malformed table per the §4.14.3.6 Table 4-20
///   stride.
/// * `AacsError::InvalidValue` — the length field is below the
///   spec-mandated minimum of `2` (which would not even cover the
///   Reserved + Maximum + Reserved trailer).
pub fn parse_bus_encryption_sector_extents_response(
    buf: &[u8],
) -> Result<BusEncryptionSectorExtentsResponse, AacsError> {
    let length = read_u16_be(buf, "Bus-Encryption Sector Extents response header")? as usize;
    // Per §4.14.3.6 the length field equals `N * 16 + 2`, where `N` is
    // the number of currently-defined Bus-Encryption Sector Extents.
    // The `+2` accounts for the Reserved + Maximum trailer at bytes
    // 2..3; the `N * 16` segment accounts for the `N` extent records
    // that start at byte 4 with their leading 8-byte Reserved field.
    // The minimum legal value is `2` (an empty table; §4.14.3.6
    // paragraph 2: "If no Bus-Encryption Sector Extents are currently
    // defined, the Data Length field shall be 2.").
    if length < 2 {
        return Err(AacsError::InvalidValue {
            what: "Bus-Encryption Sector Extents response length",
            value: length as u64,
        });
    }
    if buf.len() < 2 + length {
        return Err(AacsError::Truncated(
            "Bus-Encryption Sector Extents response payload",
        ));
    }
    let extent_section_len = length - 2;
    if extent_section_len % BUS_ENCRYPTION_SECTOR_EXTENT_LEN != 0 {
        return Err(AacsError::Truncated(
            "Bus-Encryption Sector Extents response extent record stride",
        ));
    }
    // Byte 3 carries the maximum; the on-wire value 0 denotes 256 per
    // §4.14.3.6 paragraph 3.
    let wire_max = buf[3];
    let maximum = if wire_max == 0 { 256 } else { wire_max as u16 };
    let extent_count = extent_section_len / BUS_ENCRYPTION_SECTOR_EXTENT_LEN;
    let mut extents = Vec::with_capacity(extent_count);
    // Extent records start at byte 4 with their 8-byte Reserved field.
    // For record `i`: bytes 4+i*16..11+i*16 Reserved; bytes
    // 12+i*16..15+i*16 Start LBA (u32 big-endian); bytes
    // 16+i*16..19+i*16 LBA Count (u32 big-endian).
    for i in 0..extent_count {
        let base = 4 + i * BUS_ENCRYPTION_SECTOR_EXTENT_LEN;
        let start_lba = ((buf[base + 8] as u32) << 24)
            | ((buf[base + 9] as u32) << 16)
            | ((buf[base + 10] as u32) << 8)
            | (buf[base + 11] as u32);
        let lba_count = ((buf[base + 12] as u32) << 24)
            | ((buf[base + 13] as u32) << 16)
            | ((buf[base + 14] as u32) << 8)
            | (buf[base + 15] as u32);
        extents.push(BusEncryptionSectorExtent {
            start_lba,
            lba_count,
        });
    }
    Ok(BusEncryptionSectorExtentsResponse { maximum, extents })
}

/// Parse the variable-length response payload for `READ_DISC_STRUCTURE`
/// Format `0x83` (AACS Media Key Block Pack) per MMC-6 Table 384 /
/// AACS Common §4.14.3.4 Table 4-18.
///
/// Wire layout: `[length:u16][reserved:u8][total_packs:u8]
/// [pack_data: ≤32,768 bytes]`. The two-byte `length` field measures
/// everything after itself (the trailing `2 + length` bytes), per the
/// MMC-6 convention. `total_packs` is the ceiling of MKB total length
/// divided by 32,768.
pub fn parse_mkb_pack_response(buf: &[u8]) -> Result<MkbPackResponse, AacsError> {
    let length = read_u16_be(buf, "MKB pack response header")? as usize;
    if length < 2 {
        return Err(AacsError::InvalidValue {
            what: "MKB pack response length",
            value: length as u64,
        });
    }
    // 4-byte header (length:u16 + reserved:u8 + total_packs:u8); pack
    // body length = length - 2 (the two-byte `length` field counts the
    // remaining `reserved:u8 + total_packs:u8 + pack_data` bytes).
    let body_len = length - 2;
    if buf.len() < 4 + body_len {
        return Err(AacsError::Truncated("MKB pack response payload"));
    }
    let total_packs = buf[3];
    let pack_data = buf[4..4 + body_len].to_vec();
    Ok(MkbPackResponse {
        total_packs,
        pack_data,
    })
}

// ---------------------------------------------------------------------
// Outbound parameter-list builders (host -> drive)
// ---------------------------------------------------------------------

/// Build the 116-byte SEND KEY parameter-list payload for the Host
/// Certificate Challenge command (MMC-6 Table 606 / AACS Common
/// Table 4-24).
///
/// Wire layout: `[length:u16=0x0072][reserved:u16][Hn:20][Cert_h:92]`.
pub fn build_send_key_host_cert_chal(
    host_nonce: &[u8; HOST_NONCE_LEN],
    host_cert: &[u8; HOST_CERT_LEN],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + HOST_NONCE_LEN + HOST_CERT_LEN);
    out.extend_from_slice(&[0x00, 0x72, 0x00, 0x00]);
    out.extend_from_slice(host_nonce);
    out.extend_from_slice(host_cert);
    debug_assert_eq!(out.len(), 116);
    out
}

/// Build the 84-byte SEND KEY parameter-list payload for the Host Key
/// command (MMC-6 Table 607 / AACS Common Table 4-25).
///
/// Wire layout: `[length:u16=0x0052][reserved:u16][Hv:40][Hsig:40]`.
pub fn build_send_key_host_key(hv: &[u8; EC_POINT_LEN], hsig: &[u8; EC_SIG_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + EC_POINT_LEN + EC_SIG_LEN);
    out.extend_from_slice(&[0x00, 0x52, 0x00, 0x00]);
    out.extend_from_slice(hv);
    out.extend_from_slice(hsig);
    debug_assert_eq!(out.len(), 84);
    out
}

/// Parse the 116-byte SEND KEY Host Certificate Challenge parameter
/// list. Inverse of [`build_send_key_host_cert_chal`]; used by
/// [`MockDrive`] and tests.
pub fn parse_send_key_host_cert_chal(
    buf: &[u8],
) -> Result<([u8; HOST_NONCE_LEN], [u8; HOST_CERT_LEN]), AacsError> {
    let length = read_u16_be(buf, "SEND_KEY Host Cert Challenge header")?;
    if length != 0x0072 {
        return Err(AacsError::InvalidValue {
            what: "SEND_KEY Host Cert Challenge length",
            value: length as u64,
        });
    }
    if buf.len() < 116 {
        return Err(AacsError::Truncated("SEND_KEY Host Cert Challenge payload"));
    }
    let mut host_nonce = [0u8; HOST_NONCE_LEN];
    host_nonce.copy_from_slice(&buf[4..4 + HOST_NONCE_LEN]);
    let mut host_cert = [0u8; HOST_CERT_LEN];
    host_cert.copy_from_slice(&buf[24..24 + HOST_CERT_LEN]);
    Ok((host_nonce, host_cert))
}

/// Parse the 84-byte SEND KEY Host Key parameter list. Inverse of
/// [`build_send_key_host_key`].
pub fn parse_send_key_host_key(
    buf: &[u8],
) -> Result<([u8; EC_POINT_LEN], [u8; EC_SIG_LEN]), AacsError> {
    let length = read_u16_be(buf, "SEND_KEY Host Key header")?;
    if length != 0x0052 {
        return Err(AacsError::InvalidValue {
            what: "SEND_KEY Host Key length",
            value: length as u64,
        });
    }
    if buf.len() < 84 {
        return Err(AacsError::Truncated("SEND_KEY Host Key payload"));
    }
    let mut hv = [0u8; EC_POINT_LEN];
    hv.copy_from_slice(&buf[4..4 + EC_POINT_LEN]);
    let mut hsig = [0u8; EC_SIG_LEN];
    hsig.copy_from_slice(&buf[44..44 + EC_SIG_LEN]);
    Ok((hv, hsig))
}

/// Build the 20-byte SEND DISC STRUCTURE parameter list for the Write
/// Data Key send (Format `0x84`) per AACS Common §4.14.5.1 Table 4-28 /
/// MMC-6 §6.36.3.2.11 Table 591.
///
/// Wire layout: `[length:u16=0x0012][reserved:u16][Kwd:16]`. The
/// two-byte DISC STRUCTURE Data Length field does not count itself, so
/// its value is `0x0012` (= 18, covering bytes 2..19). Bytes 4..19
/// carry the replacement Write Data Key, encrypted by the Bus Key
/// using AES-128E (§4.14.5.1 paragraph 3) — the caller wraps the
/// plaintext `Kwd` with `aes_128_ecb_encrypt(bus_key, kwd)` before
/// building the parameter list.
pub fn build_send_disc_structure_write_data_key(
    write_data_key_encrypted: &[u8; DATA_KEY_LEN],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + DATA_KEY_LEN);
    out.extend_from_slice(&[0x00, 0x12, 0x00, 0x00]);
    out.extend_from_slice(write_data_key_encrypted);
    debug_assert_eq!(out.len(), 20);
    out
}

/// Parse the 20-byte SEND DISC STRUCTURE Write Data Key parameter
/// list. Inverse of [`build_send_disc_structure_write_data_key`]; used
/// by [`MockDrive`] and tests. Returns the 16-byte Write Data Key in
/// its on-the-wire (Bus-Key-encrypted) form. Rejects a length field
/// other than the Table 4-28 mandated `0x0012` and truncated buffers.
pub fn parse_send_disc_structure_write_data_key(
    buf: &[u8],
) -> Result<[u8; DATA_KEY_LEN], AacsError> {
    let length = read_u16_be(buf, "SEND_DISC_STRUCTURE Write Data Key header")?;
    if length != 0x0012 {
        return Err(AacsError::InvalidValue {
            what: "SEND_DISC_STRUCTURE Write Data Key length",
            value: length as u64,
        });
    }
    if buf.len() < 4 + DATA_KEY_LEN {
        return Err(AacsError::Truncated(
            "SEND_DISC_STRUCTURE Write Data Key payload",
        ));
    }
    let mut kwd = [0u8; DATA_KEY_LEN];
    kwd.copy_from_slice(&buf[4..4 + DATA_KEY_LEN]);
    Ok(kwd)
}

/// Build the SEND DISC STRUCTURE parameter list for the Bus-Encryption
/// Sector Extents send (Format `0x85`) per AACS Common §4.14.5.2
/// Table 4-29.
///
/// Wire layout: `[length:u16 = 2 + N*16][reserved:u16]` followed by `N`
/// 16-byte LBA Extent Structures, each
/// `[reserved:8 || Start LBA:u32 || LBA Count:u32]` (both 32-bit fields
/// big-endian). The two-byte DISC STRUCTURE Data Length field does not
/// count itself, so its value is `2 + N*16` (the leading `2` covers the
/// bytes-2..3 Reserved field). When `extents` is empty the length field
/// is `2` and no extent records follow — the host's request to clear the
/// drive's Bus-Encrypted Sector Extents (§4.14.5.2 paragraph 1).
///
/// The caller is responsible for sorting + validating the extents (see
/// [`validate_bus_encryption_sector_extents`]); this builder serialises
/// whatever it is given so a test can construct a deliberately malformed
/// list and assert the drive rejects it.
pub fn build_send_disc_structure_bus_encryption_sector_extents(
    extents: &[BusEncryptionSectorExtent],
) -> Vec<u8> {
    let length = 2 + extents.len() * BUS_ENCRYPTION_SECTOR_EXTENT_LEN;
    let mut out = Vec::with_capacity(2 + length);
    out.push((length >> 8) as u8);
    out.push(length as u8);
    // Bytes 2..3: Reserved.
    out.extend_from_slice(&[0u8, 0u8]);
    for extent in extents {
        // 8-byte Reserved leader (bytes 4..11 of the record).
        out.extend_from_slice(&[0u8; 8]);
        out.extend_from_slice(&extent.start_lba.to_be_bytes());
        out.extend_from_slice(&extent.lba_count.to_be_bytes());
    }
    debug_assert_eq!(
        out.len(),
        4 + extents.len() * BUS_ENCRYPTION_SECTOR_EXTENT_LEN
    );
    out
}

/// Parse the SEND DISC STRUCTURE Bus-Encryption Sector Extents parameter
/// list (Format `0x85`). Inverse of
/// [`build_send_disc_structure_bus_encryption_sector_extents`]; used by
/// [`MockDrive`] and tests. Returns the extents in their on-the-wire
/// order (no sort / overlap / capacity validation — that is
/// [`validate_bus_encryption_sector_extents`]'s job).
///
/// Errors:
/// * [`AacsError::InvalidValue`] — the length field is below the
///   spec-mandated minimum of `2` (which does not even cover the
///   bytes-2..3 Reserved field).
/// * [`AacsError::Truncated`] — the buffer is shorter than the 4-byte
///   header, shorter than `2 + length` total, or `(length - 2)` is not a
///   multiple of 16 (a malformed table per the Table 4-29 16-byte
///   stride).
pub fn parse_send_disc_structure_bus_encryption_sector_extents(
    buf: &[u8],
) -> Result<Vec<BusEncryptionSectorExtent>, AacsError> {
    let length = read_u16_be(
        buf,
        "SEND_DISC_STRUCTURE Bus-Encryption Sector Extents header",
    )? as usize;
    // Per §4.14.5.2 the length field equals `2 + N*16`. The `+2` covers
    // the bytes-2..3 Reserved field; the `N*16` segment covers the `N`
    // 16-byte LBA Extent Structures. The minimum legal value is `2`
    // (N = 0, the "clear current extents" request).
    if length < 2 {
        return Err(AacsError::InvalidValue {
            what: "SEND_DISC_STRUCTURE Bus-Encryption Sector Extents length",
            value: length as u64,
        });
    }
    if buf.len() < 2 + length {
        return Err(AacsError::Truncated(
            "SEND_DISC_STRUCTURE Bus-Encryption Sector Extents payload",
        ));
    }
    let extent_section_len = length - 2;
    if extent_section_len % BUS_ENCRYPTION_SECTOR_EXTENT_LEN != 0 {
        return Err(AacsError::Truncated(
            "SEND_DISC_STRUCTURE Bus-Encryption Sector Extents record stride",
        ));
    }
    let extent_count = extent_section_len / BUS_ENCRYPTION_SECTOR_EXTENT_LEN;
    let mut extents = Vec::with_capacity(extent_count);
    // Extent records start at byte 4 with their 8-byte Reserved field.
    for i in 0..extent_count {
        let base = 4 + i * BUS_ENCRYPTION_SECTOR_EXTENT_LEN;
        let start_lba =
            u32::from_be_bytes([buf[base + 8], buf[base + 9], buf[base + 10], buf[base + 11]]);
        let lba_count = u32::from_be_bytes([
            buf[base + 12],
            buf[base + 13],
            buf[base + 14],
            buf[base + 15],
        ]);
        extents.push(BusEncryptionSectorExtent {
            start_lba,
            lba_count,
        });
    }
    Ok(extents)
}

/// Validate a Bus-Encryption Sector Extents list against the AACS
/// Common §4.14.5.2 ingest rules a logical unit applies to a SEND DISC
/// STRUCTURE Format `0x85` parameter list.
///
/// Per §4.14.5.2 paragraph 4 the host shall sort the extents by Start
/// LBA and ensure they do not overlap; the logical unit returns
/// `5/26/00 INVALID FIELD IN PARAMETER LIST` if the extents overlap, are
/// not sorted, lie beyond the maximum capacity of the current media, or
/// carry a zero LBA Count. `media_capacity_lba` is the number of
/// addressable LBAs on the current media; an extent
/// `[start_lba, start_lba + lba_count)` must fall entirely within
/// `0..media_capacity_lba`. Pass `u32::MAX` to skip the capacity check
/// when the caller does not know the media geometry.
///
/// All four violations map to the single SCSI sense code in the spec, so
/// they surface as [`AacsError::InvalidValue`] with a `what` tag naming
/// the specific rule that failed (`"… LBA Count is zero"`, `"… not
/// sorted by Start LBA"`, `"… extents overlap"`, `"… extent beyond media
/// capacity"`). An empty list is always valid (the "clear extents"
/// request).
pub fn validate_bus_encryption_sector_extents(
    extents: &[BusEncryptionSectorExtent],
    media_capacity_lba: u32,
) -> Result<(), AacsError> {
    let capacity = media_capacity_lba as u64;
    let mut prev_end: Option<u64> = None;
    let mut prev_start: u64 = 0;
    for extent in extents {
        // "if an LBA Count is zero" → INVALID FIELD IN PARAMETER LIST.
        if extent.lba_count == 0 {
            return Err(AacsError::InvalidValue {
                what: "SEND_DISC_STRUCTURE Format 0x85 LBA Count is zero",
                value: extent.start_lba as u64,
            });
        }
        let start = extent.start_lba as u64;
        // One-past-the-last LBA. Both fields are u32, so the sum fits in
        // u64 without overflow.
        let end = start + extent.lba_count as u64;
        // "if any LBA Extent is located beyond the maximum capacity of
        // the current media" → INVALID FIELD IN PARAMETER LIST.
        if end > capacity {
            return Err(AacsError::InvalidValue {
                what: "SEND_DISC_STRUCTURE Format 0x85 extent beyond media capacity",
                value: start,
            });
        }
        if let Some(prev_end) = prev_end {
            // "if the LBA Extents are not sorted" — Start LBA must be
            // non-decreasing.
            if start < prev_start {
                return Err(AacsError::InvalidValue {
                    what: "SEND_DISC_STRUCTURE Format 0x85 extents not sorted by Start LBA",
                    value: start,
                });
            }
            // "if the LBA Extents contain overlapping regions" — this
            // extent must begin at or after the previous extent's end.
            if start < prev_end {
                return Err(AacsError::InvalidValue {
                    what: "SEND_DISC_STRUCTURE Format 0x85 extents overlap",
                    value: start,
                });
            }
        }
        prev_end = Some(end);
        prev_start = start;
    }
    Ok(())
}

// ---------------------------------------------------------------------
// GET CONFIGURATION (0x46) + AACS Feature Descriptor (Feature 0x010D)
// ---------------------------------------------------------------------

/// SCSI MMC `GET CONFIGURATION` opcode (MMC-6 §6.5.1.1 Table 256).
///
/// Unlike the four AACS Key-Class / Disc-Structure commands, GET
/// CONFIGURATION is a **10-byte** CDB (SPC-3 group-1 fixed CDB), so it
/// does not share the [`MMC_CDB_LEN`] (12-byte) frame used by REPORT KEY
/// / SEND KEY / READ DISC STRUCTURE / SEND DISC STRUCTURE.
pub const GET_CONFIGURATION_OPCODE: u8 = 0x46;

/// Fixed length of the GET CONFIGURATION CDB (MMC-6 §6.5.1.1 Table 256 —
/// a 10-byte SPC-3 group-1 CDB).
pub const GET_CONFIGURATION_CDB_LEN: usize = 10;

/// Feature Code `0x010D`: **AACS** — "Ability to perform AACS
/// authentication" (MMC-6 §5.2.3 Table 89; AACS Common §4.14.1 Table
/// 4-3). The descriptor body is defined by AACS Common Table 4-4.
pub const FEATURE_AACS: u16 = 0x010D;

/// GET CONFIGURATION RT field `00b`: return the Feature Header and **all**
/// Feature Descriptors the drive supports, regardless of currency (MMC-6
/// §6.5.1.2 Table 257).
pub const GET_CONFIG_RT_ALL: u8 = 0x00;
/// GET CONFIGURATION RT field `01b`: return only the Feature Descriptors
/// whose Current bit is set (MMC-6 §6.5.1.2 Table 257).
pub const GET_CONFIG_RT_CURRENT: u8 = 0x01;
/// GET CONFIGURATION RT field `10b`: return the Feature Header plus the
/// single Feature Descriptor named by Starting Feature Number (MMC-6
/// §6.5.1.2 Table 257). The host uses this with
/// `starting_feature = `[`FEATURE_AACS`] to fetch just the AACS
/// descriptor.
pub const GET_CONFIG_RT_ONE: u8 = 0x02;

/// 8-byte Feature Header preceding the Feature Descriptor list in a GET
/// CONFIGURATION response (MMC-6 §5.2.1 Table 87).
pub const FEATURE_HEADER_LEN: usize = 8;

/// Typed builder for the `GET CONFIGURATION` (`0x46`) CDB.
///
/// Per MMC-6 §6.5.1.1 Table 256 the CDB layout is:
///
/// ```text
///  Byte 0   : Operation Code (0x46)
///  Byte 1   : Reserved [7..2] | RT [1..0]
///  Bytes 2-3: Starting Feature Number (big-endian)
///  Bytes 4-6: Reserved
///  Bytes 7-8: Allocation Length (big-endian)
///  Byte 9   : Control
/// ```
///
/// The host discovers AACS support by issuing this command with
/// [`GetConfiguration::aacs_feature`] and parsing the returned descriptor
/// with [`parse_aacs_feature_descriptor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetConfiguration {
    /// RT field (low 2 bits of byte 1) — [`GET_CONFIG_RT_ALL`],
    /// [`GET_CONFIG_RT_CURRENT`], or [`GET_CONFIG_RT_ONE`].
    pub rt: u8,
    /// Starting Feature Number (bytes 2..3, big-endian).
    pub starting_feature: u16,
    /// Allocation length in bytes the host will accept (bytes 7..8,
    /// big-endian).
    pub allocation_length: u16,
    /// SAM-3 control byte (byte 9) — typically `0x00`.
    pub control: u8,
}

impl GetConfiguration {
    /// Constructor for the AACS Feature query: RT `10b` (return only the
    /// requested descriptor) with Starting Feature Number
    /// [`FEATURE_AACS`]. The allocation length is sized for the 8-byte
    /// Feature Header plus the 8-byte AACS Feature Descriptor (4-byte
    /// descriptor header + 4-byte Feature Dependent Data per AACS Common
    /// Table 4-4) = 16 bytes.
    pub fn aacs_feature() -> Self {
        Self {
            rt: GET_CONFIG_RT_ONE,
            starting_feature: FEATURE_AACS,
            allocation_length: (FEATURE_HEADER_LEN + AACS_FEATURE_DESCRIPTOR_LEN) as u16,
            control: 0,
        }
    }

    /// Serialize this CDB into 10 bytes per MMC-6 Table 256.
    pub fn cdb(&self) -> [u8; GET_CONFIGURATION_CDB_LEN] {
        let mut cdb = [0u8; GET_CONFIGURATION_CDB_LEN];
        cdb[0] = GET_CONFIGURATION_OPCODE;
        cdb[1] = self.rt & 0x03;
        cdb[2] = (self.starting_feature >> 8) as u8;
        cdb[3] = self.starting_feature as u8;
        // bytes 4..6 Reserved.
        cdb[7] = (self.allocation_length >> 8) as u8;
        cdb[8] = self.allocation_length as u8;
        cdb[9] = self.control;
        cdb
    }

    /// Inverse of [`GetConfiguration::cdb`]. Returns
    /// [`AacsError::InvalidValue`] when the opcode byte is not `0x46`.
    pub fn parse_cdb(cdb: &[u8; GET_CONFIGURATION_CDB_LEN]) -> Result<Self, AacsError> {
        if cdb[0] != GET_CONFIGURATION_OPCODE {
            return Err(AacsError::InvalidValue {
                what: "GET_CONFIGURATION opcode",
                value: cdb[0] as u64,
            });
        }
        Ok(Self {
            rt: cdb[1] & 0x03,
            starting_feature: ((cdb[2] as u16) << 8) | (cdb[3] as u16),
            allocation_length: ((cdb[7] as u16) << 8) | (cdb[8] as u16),
            control: cdb[9],
        })
    }
}

/// Total on-wire length of the AACS Feature Descriptor: the 4-byte
/// generic Feature Descriptor header (Feature Code + Version/Persistent/
/// Current + Additional Length) plus the 4-byte AACS Feature Dependent
/// Data (AACS Common §4.14.1 Table 4-4, bytes 0..7).
pub const AACS_FEATURE_DESCRIPTOR_LEN: usize = 8;

/// The fixed `Additional Length` value of the AACS Feature Descriptor —
/// 4 bytes of Feature Dependent Data follow the generic 4-byte header
/// (AACS Common §4.14.1 Table 4-4: `Additional Length = 04h`).
pub const AACS_FEATURE_ADDITIONAL_LENGTH: u8 = 0x04;

/// The Version field value of the AACS Feature Descriptor. AACS Common
/// §4.14.1 mandates `Version = 0010b`, occupying bits 5..2 of the generic
/// Feature Descriptor byte 2.
pub const AACS_FEATURE_VERSION: u8 = 0b0010;

/// The AACS version field value (Table 4-4 byte 7): AACS Common §4.14.1
/// mandates `AACS version = 01h`.
pub const AACS_FEATURE_AACS_VERSION: u8 = 0x01;

/// Decoded **AACS Feature Descriptor** (AACS Common §4.14.1 Table 4-4 /
/// MMC-6 §5.2.2 Feature Descriptor generic format).
///
/// A logical unit that supports AACS authentication advertises this
/// descriptor in its GET CONFIGURATION response. The capability bits
/// live in the Feature Dependent Data (Table 4-4 byte 4).
///
/// > **Trust note.** AACS Common §4.14.1 instructs the PC Host **not** to
/// > trust the [`bus_encryption_capable`](Self::bus_encryption_capable)
/// > (BEC) or [`write_bus_encryption`](Self::write_bus_encryption) (WBE)
/// > bits from this descriptor — the host must instead read the BEC bit
/// > from the signed Drive Certificate. These fields are surfaced for
/// > completeness, not as an authorisation source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AacsFeatureDescriptor {
    /// `Current` bit (generic descriptor byte 2 bit 0). When set, AACS
    /// is currently active (an AACS-compliant medium is loaded) and the
    /// Feature Dependent Data is valid (MMC-6 §5.2.2.4; AACS Common
    /// §4.14.1).
    pub current: bool,
    /// `Persistent` bit (generic descriptor byte 2 bit 1) — when set the
    /// Feature is always active (MMC-6 §5.2.2.3).
    pub persistent: bool,
    /// `Version` field (generic descriptor byte 2 bits 5..2). AACS Common
    /// §4.14.1 mandates [`AACS_FEATURE_VERSION`] (`0010b`).
    pub version: u8,
    /// **RDC** — Read Drive Certificate (Table 4-4 byte 4 bit 7). Set
    /// when the drive supports reading its Drive Certificate via REPORT
    /// KEY Key Format `111000b`.
    pub read_drive_certificate: bool,
    /// **RMC** — Return MKB of CPRM (Table 4-4 byte 4 bit 6). Set when
    /// the drive can transfer the CPRM Media Key Block via READ DISC
    /// STRUCTURE Format Code `0x86`.
    pub return_mkb_of_cprm: bool,
    /// **WBE** — Write Bus Encryption (Table 4-4 byte 4 bit 5). Set when
    /// the drive supports Bus Encryption and supports writing. Not to be
    /// trusted by the host (see the struct-level note).
    pub write_bus_encryption: bool,
    /// **BEC** — Bus Encryption Capable (Table 4-4 byte 4 bit 4). Set
    /// when the drive supports Bus Encryption. Not to be trusted by the
    /// host (see the struct-level note).
    pub bus_encryption_capable: bool,
    /// **BNG** — Binding Nonce Generation (Table 4-4 byte 4 bit 0). Set
    /// when Binding Nonce generation is supported (REPORT KEY Key Format
    /// `100000b` is then also supported).
    pub binding_nonce_generation: bool,
    /// Block Count for Binding Nonce (Table 4-4 byte 5) — how many blocks
    /// are required to store the Binding Nonce for the media.
    pub block_count_for_binding_nonce: u8,
    /// Number of AGIDs (Table 4-4 byte 6 bits 2..0) — the maximum number
    /// of AGIDs the logical unit supports concurrently.
    pub number_of_agids: u8,
    /// AACS version (Table 4-4 byte 7). AACS Common §4.14.1 mandates
    /// [`AACS_FEATURE_AACS_VERSION`] (`01h`).
    pub aacs_version: u8,
}

impl AacsFeatureDescriptor {
    /// Serialize this descriptor into its 8-byte on-wire form (AACS
    /// Common §4.14.1 Table 4-4 / MMC-6 §5.2.2 generic format). Bytes
    /// 0..1 carry the Feature Code [`FEATURE_AACS`] (big-endian); byte 2
    /// packs `Version` (bits 5..2), `Persistent` (bit 1), `Current`
    /// (bit 0); byte 3 is the `Additional Length`
    /// ([`AACS_FEATURE_ADDITIONAL_LENGTH`]); bytes 4..7 are the Feature
    /// Dependent Data.
    pub fn to_bytes(&self) -> [u8; AACS_FEATURE_DESCRIPTOR_LEN] {
        let mut out = [0u8; AACS_FEATURE_DESCRIPTOR_LEN];
        out[0] = (FEATURE_AACS >> 8) as u8;
        out[1] = FEATURE_AACS as u8;
        out[2] =
            ((self.version & 0x0F) << 2) | ((self.persistent as u8) << 1) | (self.current as u8);
        out[3] = AACS_FEATURE_ADDITIONAL_LENGTH;
        out[4] = ((self.read_drive_certificate as u8) << 7)
            | ((self.return_mkb_of_cprm as u8) << 6)
            | ((self.write_bus_encryption as u8) << 5)
            | ((self.bus_encryption_capable as u8) << 4)
            | (self.binding_nonce_generation as u8);
        out[5] = self.block_count_for_binding_nonce;
        out[6] = self.number_of_agids & 0x07;
        out[7] = self.aacs_version;
        out
    }
}

/// Parse one **AACS Feature Descriptor** out of an 8-byte slice (the
/// generic 4-byte Feature Descriptor header + the 4-byte AACS Feature
/// Dependent Data, AACS Common §4.14.1 Table 4-4).
///
/// Returns [`AacsError::Truncated`] when fewer than
/// [`AACS_FEATURE_DESCRIPTOR_LEN`] bytes are present, and
/// [`AacsError::InvalidValue`] when the Feature Code is not
/// [`FEATURE_AACS`] or the Additional Length is not
/// [`AACS_FEATURE_ADDITIONAL_LENGTH`] (`04h`, which the spec fixes for
/// this descriptor). The `Version` and `AACS version` fields are decoded
/// verbatim rather than validated, since a forward-compatible drive may
/// report values the host should tolerate.
pub fn parse_aacs_feature_descriptor(buf: &[u8]) -> Result<AacsFeatureDescriptor, AacsError> {
    if buf.len() < AACS_FEATURE_DESCRIPTOR_LEN {
        return Err(AacsError::Truncated("AACS Feature Descriptor"));
    }
    let feature_code = ((buf[0] as u16) << 8) | (buf[1] as u16);
    if feature_code != FEATURE_AACS {
        return Err(AacsError::InvalidValue {
            what: "AACS Feature Descriptor Feature Code",
            value: feature_code as u64,
        });
    }
    if buf[3] != AACS_FEATURE_ADDITIONAL_LENGTH {
        return Err(AacsError::InvalidValue {
            what: "AACS Feature Descriptor Additional Length",
            value: buf[3] as u64,
        });
    }
    Ok(AacsFeatureDescriptor {
        current: buf[2] & 0x01 != 0,
        persistent: buf[2] & 0x02 != 0,
        version: (buf[2] >> 2) & 0x0F,
        read_drive_certificate: buf[4] & 0x80 != 0,
        return_mkb_of_cprm: buf[4] & 0x40 != 0,
        write_bus_encryption: buf[4] & 0x20 != 0,
        bus_encryption_capable: buf[4] & 0x10 != 0,
        binding_nonce_generation: buf[4] & 0x01 != 0,
        block_count_for_binding_nonce: buf[5],
        number_of_agids: buf[6] & 0x07,
        aacs_version: buf[7],
    })
}

/// Locate and parse the AACS Feature Descriptor inside a full GET
/// CONFIGURATION response (the 8-byte Feature Header followed by zero or
/// more variable-length Feature Descriptors, MMC-6 §5.2.1 Table 86).
///
/// The function skips the Feature Header, then walks the descriptor list
/// — each descriptor is `4 + Additional Length` bytes (MMC-6 §5.2.2,
/// `Additional Length` an integral multiple of 4) — until it finds the
/// one whose Feature Code is [`FEATURE_AACS`], which it parses with
/// [`parse_aacs_feature_descriptor`].
///
/// Returns:
/// - `Ok(Some(descriptor))` when an AACS Feature Descriptor is present,
/// - `Ok(None)` when the response is well-formed but carries no AACS
///   descriptor (a non-AACS drive),
/// - [`AacsError::Truncated`] when the Feature Header or a descriptor
///   header runs past the end of the buffer.
pub fn find_aacs_feature_descriptor(
    response: &[u8],
) -> Result<Option<AacsFeatureDescriptor>, AacsError> {
    if response.len() < FEATURE_HEADER_LEN {
        return Err(AacsError::Truncated("GET CONFIGURATION Feature Header"));
    }
    let mut offset = FEATURE_HEADER_LEN;
    while offset + 4 <= response.len() {
        let feature_code = ((response[offset] as u16) << 8) | (response[offset + 1] as u16);
        let additional_length = response[offset + 3] as usize;
        let descriptor_len = 4 + additional_length;
        if offset + descriptor_len > response.len() {
            return Err(AacsError::Truncated("GET CONFIGURATION Feature Descriptor"));
        }
        if feature_code == FEATURE_AACS {
            return Ok(Some(parse_aacs_feature_descriptor(
                &response[offset..offset + descriptor_len],
            )?));
        }
        offset += descriptor_len;
    }
    Ok(None)
}

/// Build a complete minimal GET CONFIGURATION response (8-byte Feature
/// Header + one AACS Feature Descriptor) for a synthetic drive or for
/// `find_aacs_feature_descriptor` round-trip tests.
///
/// The Feature Header's Data Length (MMC-6 §5.2.1 Table 87, bytes 0..3
/// big-endian) counts everything **after** the Data Length field itself —
/// i.e. `4 (rest of header) + 8 (descriptor) = 12`. The Current Profile
/// field (bytes 6..7) is set to `current_profile`.
pub fn build_get_configuration_aacs_response(
    descriptor: &AacsFeatureDescriptor,
    current_profile: u16,
) -> Vec<u8> {
    let body = descriptor.to_bytes();
    // Data Length counts the 4 trailing header bytes + the descriptor.
    let data_length = (FEATURE_HEADER_LEN - 4 + body.len()) as u32;
    let mut out = Vec::with_capacity(FEATURE_HEADER_LEN + body.len());
    out.extend_from_slice(&data_length.to_be_bytes());
    out.push(0); // byte 4 Reserved
    out.push(0); // byte 5 Reserved
    out.extend_from_slice(&current_profile.to_be_bytes());
    out.extend_from_slice(&body);
    out
}

// ---------------------------------------------------------------------
// DriveCommand trait + mock drive
// ---------------------------------------------------------------------

/// Direction of the SCSI data phase for an MMC CDB. Set by callers when
/// dispatching through the [`DriveCommand`] trait. The opcode itself
/// determines the direction (REPORT KEY + READ DISC STRUCTURE are
/// drive→host; SEND KEY + SEND DISC STRUCTURE are host→drive), but the
/// explicit enum makes
/// platform back-ends easier to wire up since each OS surface
/// (`SG_IO`'s `dxfer_direction`, `IOSCSITaskDeviceInterface`'s
/// transfer-direction, Windows' `SCSI_PASS_THROUGH_DIRECT::DataIn`)
/// carries this as a separate field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataDirection {
    /// No data phase (e.g. Invalidate AGID).
    None,
    /// Data flows from drive to host (READ).
    FromDevice,
    /// Data flows from host to drive (WRITE).
    ToDevice,
}

/// Result of a SCSI pass-through command. Phase B does not model
/// sense-data parsing; callers that need richer diagnostics can wrap
/// this trait in their own platform-specific adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScsiResponse {
    /// SCSI status byte (`0x00` GOOD, `0x02` CHECK CONDITION, etc.).
    pub status: u8,
    /// Returned data on a `FromDevice` operation, or any sense-data
    /// excerpt the back-end captured.
    pub data: Vec<u8>,
}

impl ScsiResponse {
    /// Convenience constructor for a successful response carrying
    /// `data`.
    pub fn good(data: Vec<u8>) -> Self {
        Self { status: 0x00, data }
    }
}

/// Trait implemented by platform-specific SCSI pass-through back-ends.
///
/// Phase B defines only the surface; concrete back-ends (macOS IOKit,
/// Linux `SG_IO`, Windows `IOCTL_SCSI_PASS_THROUGH_DIRECT`) will live
/// either as feature-gated submodules of this crate or as separate
/// integrating crates, dispatched once Phase C lands the higher-level
/// AKE state machine.
pub trait DriveCommand {
    /// Issue a 12-byte MMC CDB and exchange `data_out` (for
    /// host→drive) for response bytes (for drive→host). The
    /// `allocation_length` is the expected response size — back-ends
    /// may honour or ignore it depending on platform conventions.
    fn execute(
        &mut self,
        cdb: &[u8; MMC_CDB_LEN],
        direction: DataDirection,
        data_out: &[u8],
        allocation_length: u16,
    ) -> Result<ScsiResponse, AacsError>;
}

/// In-process synthetic-fixture implementation of [`DriveCommand`].
///
/// A `test-util`-gated fixture: it is reachable from the crate's own
/// tests and from the `test-util`-gated AKE self-checks
/// ([`crate::ake_full_self_check`] / [`crate::all_self_checks`]), but is
/// not part of the default public API. The mock honours the dispatch
/// path a real drive would follow: it inspects the CDB,
/// recognises the AACS Key Format / Format Code, and returns a
/// hand-stuffed payload (or stores the incoming SEND KEY parameter
/// list for later inspection by the test).
///
/// Manual `Default` implementation rather than `#[derive(Default)]`
/// because `Default` is only auto-derived for arrays up to length 32;
/// the 40-byte ECDSA-secp160r1 point/signature fields and the 92-byte
/// certificate field exceed that bound.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Clone)]
pub struct MockDrive {
    /// AGID the mock will return when REPORT KEY Key Format `0x00` is
    /// invoked. Defaults to `1`.
    pub agid_to_return: u8,
    /// 160-bit Drive Nonce the mock returns when REPORT KEY Key
    /// Format `0x01` is invoked.
    pub drive_nonce: [u8; DRIVE_NONCE_LEN],
    /// 92-byte Drive Certificate the mock returns for both Key Format
    /// `0x01` (challenge) and `0x38` (read).
    pub drive_cert: [u8; DRIVE_CERT_LEN],
    /// `Dv` the mock returns for REPORT KEY Key Format `0x02`.
    pub drive_dv: [u8; EC_POINT_LEN],
    /// `Dsig` the mock returns for REPORT KEY Key Format `0x02`.
    pub drive_dsig: [u8; EC_SIG_LEN],
    /// 128-bit Volume ID the mock returns for READ DISC STRUCTURE
    /// Format `0x80`.
    pub volume_id: [u8; VOLUME_ID_LEN],
    /// 128-bit MAC accompanying the Volume ID.
    pub volume_id_mac: [u8; ID_MAC_LEN],
    /// 128-bit Pre-recorded Media Serial Number returned for Format
    /// `0x81`. (§4.14.3.2)
    pub media_serial_number: [u8; VOLUME_ID_LEN],
    /// 128-bit MAC over the PMSN. In `auth` mode the mock recomputes
    /// it from the Bus Key per §4.5; this field is the fallback.
    pub media_serial_mac: [u8; ID_MAC_LEN],
    /// 128-bit Media Identifier returned for Format `0x82`.
    /// (§4.14.3.3)
    pub media_identifier: [u8; VOLUME_ID_LEN],
    /// 128-bit MAC over the Media Identifier; in `auth` mode the mock
    /// recomputes it from the Bus Key per §4.6.
    pub media_id_mac: [u8; ID_MAC_LEN],
    /// 128-bit Binding Nonce the mock returns for REPORT KEY Key
    /// Format `0x20` (generate-and-store) and `0x21` (read). The same
    /// value is returned by both formats: the mock does not model a
    /// persistent per-LBA-Extent nonce store; tests that need the
    /// generate-vs-read distinction inspect [`Self::last_binding_nonce_op`]
    /// directly. (AACS Common §4.14.2.4 Table 4-10 / §4.14.2.5
    /// Table 4-11.)
    pub binding_nonce: [u8; BINDING_NONCE_LEN],
    /// 128-bit MAC over the Binding Nonce. In `auth` mode the mock
    /// recomputes it from the Bus Key per §4.7.1 / §4.7.2; otherwise
    /// this field is returned verbatim.
    pub binding_nonce_mac: [u8; BINDING_NONCE_MAC_LEN],
    /// Captured `(key_format, starting_lba, block_count)` from the last
    /// Binding Nonce REPORT KEY the mock dispatched. `key_format` is
    /// either [`KF_REPORT_AACS_BINDING_NONCE_GEN`] (`0x20`) or
    /// [`KF_REPORT_AACS_BINDING_NONCE_READ`] (`0x21`); the LBA Extent
    /// triple is taken from CDB bytes 2..5 / byte 6 per AACS Common
    /// §4.14.2 final paragraph. `None` until the host issues a Binding
    /// Nonce command.
    pub last_binding_nonce_op: Option<(u8, u32, u8)>,
    /// Plaintext Read Data Key `Krd` (§4.11) the mock returns when the
    /// host issues READ DISC STRUCTURE Format `0x84`. In `auth` mode
    /// the mock wraps this value as `AES-128E(BK, Krd)` under the Bus
    /// Key before sending; in static mode the bytes are returned
    /// verbatim. (AACS Common §4.14.3.5 Table 4-19.)
    pub read_data_key: [u8; DATA_KEY_LEN],
    /// Plaintext Write Data Key `Kwd` (§4.11). Same treatment as
    /// [`Self::read_data_key`] when responding to Format `0x84`.
    pub write_data_key: [u8; DATA_KEY_LEN],
    /// Set to `true` after a successful READ DISC STRUCTURE Format
    /// `0x84` dispatch, so tests can assert the mock walked the §4.11
    /// branch. Reset by [`Self::with_test_fixture`] / [`Default`].
    pub last_data_keys_read: bool,
    /// The on-the-wire 16-byte Write Data Key field captured from the
    /// last SEND DISC STRUCTURE Format `0x84` parameter list the mock
    /// accepted (§4.14.5.1 Table 4-28 bytes 4..19 — still in its
    /// Bus-Key-encrypted form when the `auth` slot carries a Bus Key).
    /// The decrypted (or, in static mode, verbatim) value lands in
    /// [`Self::write_data_key`]. `None` until the host sends one.
    pub last_write_data_key_sent: Option<[u8; DATA_KEY_LEN]>,
    /// Maximum number of Bus-Encryption Sector Extents the synthetic
    /// logical unit advertises in response to READ DISC STRUCTURE
    /// Format `0x85` (§4.14.3.6 Table 4-20 byte 3). Set to a value in
    /// `1..=256`; the dispatcher encodes `256` as the on-wire byte
    /// value `0` per the §4.14.3.6 paragraph 3 sentinel. `Default`
    /// initialises this to `1`.
    pub max_bus_encryption_sector_extents: u16,
    /// The currently-defined Bus-Encryption Sector Extents the mock
    /// returns for Format `0x85`. Stored in wire order (sorted by
    /// `start_lba` ascending per §4.14.3.6 paragraph 3); the
    /// dispatcher does not re-sort. The list may be empty, in which
    /// case the on-wire Data Length is `2` and no extent records are
    /// emitted.
    pub bus_encryption_sector_extents: Vec<BusEncryptionSectorExtent>,
    /// Number of addressable LBAs on the synthetic media. Used by the
    /// SEND DISC STRUCTURE Format `0x85` ingest path to enforce the
    /// §4.14.5.2 "beyond the maximum capacity of the current media"
    /// rule: an incoming extent `[start_lba, start_lba + lba_count)`
    /// must fall entirely within `0..media_capacity_lba`. `Default`
    /// initialises this to `u32::MAX` (no effective capacity limit).
    pub media_capacity_lba: u32,
    /// SEND KEY Host Certificate Challenge payload captured from the
    /// last `aacs_host_cert_challenge` issued. `None` until the host
    /// pushes one.
    pub last_host_cert_chal: Option<Vec<u8>>,
    /// SEND KEY Host Key payload captured from the last
    /// `aacs_host_key` issued.
    pub last_host_key: Option<Vec<u8>>,
    /// Set to `true` after the host pushes `Invalidate AGID`.
    pub agid_invalidated: bool,
    /// Optional authenticating drive identity. When `Some`, the mock
    /// performs the §4.3 drive side properly: it verifies the host's
    /// certificate + `Hsig`, generates a real `Dv = Dk·G`, signs
    /// `Dsig = AACS_Sign(Drive_priv, Hn || Dv)`, and derives the Bus
    /// Key `Dk·Hv`. When `None`, the mock returns the static fixture
    /// bytes (Phase B behaviour) for byte-layout tests.
    pub auth: Option<crate::ake::DriveAuthState>,
}

#[cfg(any(test, feature = "test-util"))]
impl Default for MockDrive {
    fn default() -> Self {
        Self {
            agid_to_return: 0,
            drive_nonce: [0u8; DRIVE_NONCE_LEN],
            drive_cert: [0u8; DRIVE_CERT_LEN],
            drive_dv: [0u8; EC_POINT_LEN],
            drive_dsig: [0u8; EC_SIG_LEN],
            volume_id: [0u8; VOLUME_ID_LEN],
            volume_id_mac: [0u8; ID_MAC_LEN],
            media_serial_number: [0u8; VOLUME_ID_LEN],
            media_serial_mac: [0u8; ID_MAC_LEN],
            media_identifier: [0u8; VOLUME_ID_LEN],
            media_id_mac: [0u8; ID_MAC_LEN],
            binding_nonce: [0u8; BINDING_NONCE_LEN],
            binding_nonce_mac: [0u8; BINDING_NONCE_MAC_LEN],
            last_binding_nonce_op: None,
            read_data_key: [0u8; DATA_KEY_LEN],
            write_data_key: [0u8; DATA_KEY_LEN],
            last_data_keys_read: false,
            last_write_data_key_sent: None,
            max_bus_encryption_sector_extents: 1,
            bus_encryption_sector_extents: Vec::new(),
            media_capacity_lba: u32::MAX,
            last_host_cert_chal: None,
            last_host_key: None,
            agid_invalidated: false,
            auth: None,
        }
    }
}

#[cfg(any(test, feature = "test-util"))]
impl MockDrive {
    /// Construct a `MockDrive` populated with a deterministic
    /// non-zero fixture so tests can pattern-match on returned bytes.
    pub fn with_test_fixture() -> Self {
        let mut drive_cert = [0u8; DRIVE_CERT_LEN];
        // Tag the cert with an obvious pattern so a test can spot
        // ordering errors. Byte 0 is `Certificate Type = 0x01`
        // (Licensed Drive) per AACS Common §4.1 Table 4-1, byte 1
        // upper bits reserved, BEC bit clear. Bytes 2..3 are the
        // length (0x005C = 92).
        drive_cert[0] = 0x01;
        drive_cert[2] = 0x00;
        drive_cert[3] = 0x5C;
        // Drive ID = 0x010203040506
        drive_cert[4] = 0x01;
        drive_cert[5] = 0x02;
        drive_cert[6] = 0x03;
        drive_cert[7] = 0x04;
        drive_cert[8] = 0x05;
        drive_cert[9] = 0x06;
        // Tag remaining bytes with their index so off-by-ones in the
        // parser show up as obviously wrong payloads.
        for (i, b) in drive_cert.iter_mut().enumerate().skip(10) {
            *b = i as u8;
        }
        let mut drive_nonce = [0u8; DRIVE_NONCE_LEN];
        for (i, b) in drive_nonce.iter_mut().enumerate() {
            *b = 0xA0 | (i as u8);
        }
        let mut drive_dv = [0u8; EC_POINT_LEN];
        for (i, b) in drive_dv.iter_mut().enumerate() {
            *b = 0xC0 ^ (i as u8);
        }
        let mut drive_dsig = [0u8; EC_SIG_LEN];
        for (i, b) in drive_dsig.iter_mut().enumerate() {
            *b = 0xE0 ^ (i as u8);
        }
        let mut volume_id = [0u8; VOLUME_ID_LEN];
        for (i, b) in volume_id.iter_mut().enumerate() {
            *b = 0xB0 | (i as u8);
        }
        let mut volume_id_mac = [0u8; ID_MAC_LEN];
        for (i, b) in volume_id_mac.iter_mut().enumerate() {
            *b = 0x40 ^ (i as u8);
        }
        let mut media_serial_number = [0u8; VOLUME_ID_LEN];
        for (i, b) in media_serial_number.iter_mut().enumerate() {
            *b = 0x70 | (i as u8);
        }
        let mut media_serial_mac = [0u8; ID_MAC_LEN];
        for (i, b) in media_serial_mac.iter_mut().enumerate() {
            *b = 0x50 ^ (i as u8);
        }
        let mut media_identifier = [0u8; VOLUME_ID_LEN];
        for (i, b) in media_identifier.iter_mut().enumerate() {
            *b = 0x30 | (i as u8);
        }
        let mut media_id_mac = [0u8; ID_MAC_LEN];
        for (i, b) in media_id_mac.iter_mut().enumerate() {
            *b = 0x60 ^ (i as u8);
        }
        let mut binding_nonce = [0u8; BINDING_NONCE_LEN];
        for (i, b) in binding_nonce.iter_mut().enumerate() {
            *b = 0x20 | (i as u8);
        }
        let mut binding_nonce_mac = [0u8; BINDING_NONCE_MAC_LEN];
        for (i, b) in binding_nonce_mac.iter_mut().enumerate() {
            *b = 0x10 ^ (i as u8);
        }
        let mut read_data_key = [0u8; DATA_KEY_LEN];
        for (i, b) in read_data_key.iter_mut().enumerate() {
            *b = 0x80 | (i as u8);
        }
        let mut write_data_key = [0u8; DATA_KEY_LEN];
        for (i, b) in write_data_key.iter_mut().enumerate() {
            *b = 0x90 | (i as u8);
        }
        Self {
            agid_to_return: 1,
            drive_nonce,
            drive_cert,
            drive_dv,
            drive_dsig,
            volume_id,
            volume_id_mac,
            media_serial_number,
            media_serial_mac,
            media_identifier,
            media_id_mac,
            binding_nonce,
            binding_nonce_mac,
            last_binding_nonce_op: None,
            read_data_key,
            write_data_key,
            last_data_keys_read: false,
            last_write_data_key_sent: None,
            // Deterministic fixture: advertise capacity for 4 extents
            // and pre-populate two non-overlapping extents in wire
            // order. Each extent value is patterned so any byte-order
            // slip in the parser surfaces as an obvious diff.
            max_bus_encryption_sector_extents: 4,
            bus_encryption_sector_extents: vec![
                BusEncryptionSectorExtent {
                    start_lba: 0x0001_0000,
                    lba_count: 0x0000_2000,
                },
                BusEncryptionSectorExtent {
                    start_lba: 0x0080_0000,
                    lba_count: 0x0000_4000,
                },
            ],
            // Synthetic media large enough to admit the fixture extents
            // plus headroom for ingest-path tests.
            media_capacity_lba: 0x0100_0000,
            last_host_cert_chal: None,
            last_host_key: None,
            agid_invalidated: false,
            auth: None,
        }
    }
}

#[cfg(any(test, feature = "test-util"))]
impl DriveCommand for MockDrive {
    fn execute(
        &mut self,
        cdb: &[u8; MMC_CDB_LEN],
        direction: DataDirection,
        data_out: &[u8],
        _allocation_length: u16,
    ) -> Result<ScsiResponse, AacsError> {
        match cdb[0] {
            REPORT_KEY_OPCODE => {
                let rk = ReportKey::parse_cdb(cdb)?;
                if rk.key_class != KEY_CLASS_AACS {
                    return Err(AacsError::InvalidValue {
                        what: "MockDrive REPORT_KEY Key Class",
                        value: rk.key_class as u64,
                    });
                }
                match rk.key_format {
                    KF_REPORT_AACS_AGID => {
                        // Table 526: 4 header bytes + 4 payload bytes.
                        // Length field = 0x0006; AGID lives in bits
                        // 7..6 of payload byte 3.
                        let mut out = vec![0u8; 8];
                        out[0] = 0x00;
                        out[1] = 0x06;
                        out[7] = (self.agid_to_return & 0x03) << 6;
                        Ok(ScsiResponse::good(out))
                    }
                    KF_REPORT_AACS_DRIVE_CERT_CHAL => {
                        // Authenticating mode returns the real signed
                        // Drive Certificate + the drive nonce; static
                        // mode returns the fixture bytes.
                        let (nonce, cert): ([u8; DRIVE_NONCE_LEN], [u8; DRIVE_CERT_LEN]) =
                            match &self.auth {
                                Some(a) => (a.drive_nonce, a.drive_cert),
                                None => (self.drive_nonce, self.drive_cert),
                            };
                        let mut out = Vec::with_capacity(116);
                        out.extend_from_slice(&[0x00, 0x72, 0x00, 0x00]);
                        out.extend_from_slice(&nonce);
                        out.extend_from_slice(&cert);
                        Ok(ScsiResponse::good(out))
                    }
                    KF_REPORT_AACS_DRIVE_KEY => {
                        let (dv, dsig): ([u8; EC_POINT_LEN], [u8; EC_SIG_LEN]) = match &self.auth {
                            Some(a) => a.drive_key_response()?,
                            None => (self.drive_dv, self.drive_dsig),
                        };
                        let mut out = Vec::with_capacity(84);
                        out.extend_from_slice(&[0x00, 0x52, 0x00, 0x00]);
                        out.extend_from_slice(&dv);
                        out.extend_from_slice(&dsig);
                        Ok(ScsiResponse::good(out))
                    }
                    KF_REPORT_AACS_DRIVE_CERT => {
                        let mut out = Vec::with_capacity(96);
                        out.extend_from_slice(&[0x00, 0x5E, 0x00, 0x00]);
                        out.extend_from_slice(&self.drive_cert);
                        Ok(ScsiResponse::good(out))
                    }
                    KF_REPORT_AACS_BINDING_NONCE_GEN | KF_REPORT_AACS_BINDING_NONCE_READ => {
                        // Record the LBA Extent the host targeted so a
                        // test can confirm the CDB byte 2..5 / byte 6
                        // packing per AACS Common §4.14.2 final
                        // paragraph. Both generate (`0x20`) and read
                        // (`0x21`) use the same wire response (Table
                        // 4-10 / Table 4-11); the mock returns the
                        // stored fixture nonce + a §4.7-style MAC.
                        self.last_binding_nonce_op = Some((
                            rk.key_format,
                            rk.lba_or_starting_offset,
                            rk.block_count_function,
                        ));
                        let mac: [u8; BINDING_NONCE_MAC_LEN] = match &self.auth {
                            Some(a) if a.bus_key.is_some() => {
                                crate::aes::aes_128_cmac(&a.bus_key.unwrap(), &self.binding_nonce)
                            }
                            _ => self.binding_nonce_mac,
                        };
                        let mut out = Vec::with_capacity(36);
                        out.extend_from_slice(&[0x00, 0x22, 0x00, 0x00]);
                        out.extend_from_slice(&self.binding_nonce);
                        out.extend_from_slice(&mac);
                        Ok(ScsiResponse::good(out))
                    }
                    KF_REPORT_AACS_INVALIDATE_AGID => {
                        self.agid_invalidated = true;
                        Ok(ScsiResponse::good(Vec::new()))
                    }
                    other => Err(AacsError::InvalidValue {
                        what: "MockDrive REPORT_KEY Key Format",
                        value: other as u64,
                    }),
                }
            }
            SEND_KEY_OPCODE => {
                let sk = SendKey::parse_cdb(cdb)?;
                if sk.key_class != KEY_CLASS_AACS {
                    return Err(AacsError::InvalidValue {
                        what: "MockDrive SEND_KEY Key Class",
                        value: sk.key_class as u64,
                    });
                }
                if direction != DataDirection::ToDevice
                    && sk.key_format != KF_SEND_AACS_INVALIDATE_AGID
                {
                    return Err(AacsError::InvalidValue {
                        what: "MockDrive SEND_KEY data direction",
                        value: 0,
                    });
                }
                match sk.key_format {
                    KF_SEND_AACS_HOST_CERT_CHAL => {
                        // Validate the parameter list before accepting.
                        let (hn, hcert) = parse_send_key_host_cert_chal(data_out)?;
                        if let Some(auth) = self.auth.as_mut() {
                            auth.accept_host_cert_challenge(&hn, &hcert)?;
                        }
                        self.last_host_cert_chal = Some(data_out.to_vec());
                        Ok(ScsiResponse::good(Vec::new()))
                    }
                    KF_SEND_AACS_HOST_KEY => {
                        let (hv, hsig) = parse_send_key_host_key(data_out)?;
                        if let Some(auth) = self.auth.as_mut() {
                            auth.accept_host_key(&hv, &hsig)?;
                        }
                        self.last_host_key = Some(data_out.to_vec());
                        Ok(ScsiResponse::good(Vec::new()))
                    }
                    KF_SEND_AACS_INVALIDATE_AGID => {
                        self.agid_invalidated = true;
                        Ok(ScsiResponse::good(Vec::new()))
                    }
                    other => Err(AacsError::InvalidValue {
                        what: "MockDrive SEND_KEY Key Format",
                        value: other as u64,
                    }),
                }
            }
            READ_DISC_STRUCTURE_OPCODE => {
                let rds = ReadDiscStructure::parse_cdb(cdb)?;
                match rds.format {
                    FORMAT_AACS_VOLUME_ID => {
                        // Authenticating mode computes the real
                        // Dm = CMAC(BK, Volume_ID) (§4.4 step 3); static
                        // mode returns the fixture MAC bytes.
                        let mac: [u8; ID_MAC_LEN] = match &self.auth {
                            Some(a) if a.bus_key.is_some() => {
                                crate::aes::aes_128_cmac(&a.bus_key.unwrap(), &self.volume_id)
                            }
                            _ => self.volume_id_mac,
                        };
                        let mut out = Vec::with_capacity(36);
                        out.extend_from_slice(&[0x00, 0x22, 0x00, 0x00]);
                        out.extend_from_slice(&self.volume_id);
                        out.extend_from_slice(&mac);
                        Ok(ScsiResponse::good(out))
                    }
                    FORMAT_AACS_MEDIA_SERIAL => {
                        // §4.5 step 3: Dm = CMAC(BK, PMSN).
                        let mac: [u8; ID_MAC_LEN] = match &self.auth {
                            Some(a) if a.bus_key.is_some() => crate::aes::aes_128_cmac(
                                &a.bus_key.unwrap(),
                                &self.media_serial_number,
                            ),
                            _ => self.media_serial_mac,
                        };
                        let mut out = Vec::with_capacity(36);
                        out.extend_from_slice(&[0x00, 0x22, 0x00, 0x00]);
                        out.extend_from_slice(&self.media_serial_number);
                        out.extend_from_slice(&mac);
                        Ok(ScsiResponse::good(out))
                    }
                    FORMAT_AACS_MEDIA_ID => {
                        // §4.6 step 3: Dm = CMAC(BK, MediaID).
                        let mac: [u8; ID_MAC_LEN] = match &self.auth {
                            Some(a) if a.bus_key.is_some() => crate::aes::aes_128_cmac(
                                &a.bus_key.unwrap(),
                                &self.media_identifier,
                            ),
                            _ => self.media_id_mac,
                        };
                        let mut out = Vec::with_capacity(36);
                        out.extend_from_slice(&[0x00, 0x22, 0x00, 0x00]);
                        out.extend_from_slice(&self.media_identifier);
                        out.extend_from_slice(&mac);
                        Ok(ScsiResponse::good(out))
                    }
                    FORMAT_AACS_DATA_KEYS => {
                        // §4.14.3.5 final paragraph: when the Bus Key is
                        // not established, the drive shall terminate the
                        // command with COPY PROTECTION KEY EXCHANGE
                        // FAILURE – KEY NOT ESTABLISHED. In `auth` mode
                        // we enforce this by requiring `bus_key`; in
                        // static-fixture mode the response is returned
                        // verbatim (callers that want the error path
                        // arm `auth` without completing the AKE).
                        let (krd_wrapped, kwd_wrapped) = match &self.auth {
                            Some(a) if a.bus_key.is_some() => {
                                let bk = a.bus_key.unwrap();
                                // §4.11: wrap each Data Key under the
                                // Bus Key with AES-128E.
                                let krd = crate::aes::aes_128_ecb_encrypt(&bk, &self.read_data_key);
                                let kwd =
                                    crate::aes::aes_128_ecb_encrypt(&bk, &self.write_data_key);
                                (krd, kwd)
                            }
                            Some(_) => {
                                // Auth started but Bus Key not yet
                                // derived: spec-mandated error path.
                                return Err(AacsError::InvalidValue {
                                    what: "READ_DISC_STRUCTURE Format 0x84 without Bus Key",
                                    value: 0,
                                });
                            }
                            None => (self.read_data_key, self.write_data_key),
                        };
                        self.last_data_keys_read = true;
                        let mut out = Vec::with_capacity(36);
                        out.extend_from_slice(&[0x00, 0x22, 0x00, 0x00]);
                        out.extend_from_slice(&krd_wrapped);
                        out.extend_from_slice(&kwd_wrapped);
                        Ok(ScsiResponse::good(out))
                    }
                    FORMAT_AACS_BUS_ENCRYPTION_SECTOR_EXTENTS => {
                        // §4.14.3.6 Table 4-20: length = N*16 + 2;
                        // byte 2 Reserved, byte 3 Maximum (0 ⇒ 256);
                        // each extent record is 16 bytes
                        // `[reserved:8 || Start LBA:u32 || LBA Count:u32]`.
                        // Does **not** require AACS authentication.
                        let extent_count = self.bus_encryption_sector_extents.len();
                        let length = (extent_count * BUS_ENCRYPTION_SECTOR_EXTENT_LEN) + 2;
                        let mut out = Vec::with_capacity(2 + length);
                        out.push((length >> 8) as u8);
                        out.push(length as u8);
                        // Byte 2: Reserved.
                        out.push(0);
                        // Byte 3: encode 256 as the sentinel byte 0,
                        // else the literal byte value. Clamp to the
                        // u8 range; values outside 1..=256 are a
                        // construction error caught by debug_assert.
                        debug_assert!(
                            (1..=256).contains(&self.max_bus_encryption_sector_extents),
                            "Maximum Number of Bus-Encryption Sector Extents must be 1..=256"
                        );
                        let wire_max = if self.max_bus_encryption_sector_extents == 256 {
                            0u8
                        } else {
                            self.max_bus_encryption_sector_extents as u8
                        };
                        out.push(wire_max);
                        for extent in &self.bus_encryption_sector_extents {
                            // 8-byte Reserved leader (bytes 4..11 of
                            // the record).
                            out.extend_from_slice(&[0u8; 8]);
                            out.push((extent.start_lba >> 24) as u8);
                            out.push((extent.start_lba >> 16) as u8);
                            out.push((extent.start_lba >> 8) as u8);
                            out.push(extent.start_lba as u8);
                            out.push((extent.lba_count >> 24) as u8);
                            out.push((extent.lba_count >> 16) as u8);
                            out.push((extent.lba_count >> 8) as u8);
                            out.push(extent.lba_count as u8);
                        }
                        Ok(ScsiResponse::good(out))
                    }
                    other => Err(AacsError::InvalidValue {
                        what: "MockDrive READ_DISC_STRUCTURE Format",
                        value: other as u64,
                    }),
                }
            }
            SEND_DISC_STRUCTURE_OPCODE => {
                let sds = SendDiscStructure::parse_cdb(cdb)?;
                if direction != DataDirection::ToDevice {
                    return Err(AacsError::InvalidValue {
                        what: "MockDrive SEND_DISC_STRUCTURE data direction",
                        value: 0,
                    });
                }
                match sds.format {
                    FORMAT_AACS_WRITE_DATA_KEY => {
                        // §4.14.5.1: the parameter list carries the
                        // replacement Write Data Key, encrypted by the
                        // Bus Key using AES-128E. In `auth` mode the
                        // mock unwraps it under the established Bus Key
                        // (and enforces the spec's KEY NOT ESTABLISHED
                        // error when the AKE has not completed); in
                        // static-fixture mode the wire bytes are
                        // adopted verbatim, mirroring the READ-side
                        // Format 0x84 behaviour. The §4.14.5.1
                        // INSUFFICIENT PERMISSION branch (host not
                        // authorized to send the Write Data Key) is not
                        // modelled — the mock treats every caller as
                        // authorized.
                        let wire_kwd = parse_send_disc_structure_write_data_key(data_out)?;
                        let kwd_plain = match &self.auth {
                            Some(a) if a.bus_key.is_some() => {
                                crate::aes::aes_128_ecb_decrypt(&a.bus_key.unwrap(), &wire_kwd)
                            }
                            Some(_) => {
                                // Auth started but Bus Key not yet
                                // derived: spec-mandated error path.
                                return Err(AacsError::InvalidValue {
                                    what: "SEND_DISC_STRUCTURE Format 0x84 without Bus Key",
                                    value: 0,
                                });
                            }
                            None => wire_kwd,
                        };
                        self.write_data_key = kwd_plain;
                        self.last_write_data_key_sent = Some(wire_kwd);
                        Ok(ScsiResponse::good(Vec::new()))
                    }
                    FORMAT_AACS_BUS_ENCRYPTION_SECTOR_EXTENTS => {
                        // §4.14.5.2 Table 4-29: the parameter list carries
                        // `N` LBA Extent Structures. This command does
                        // not require AACS authentication, so the `auth`
                        // slot is not consulted. The ingest rules:
                        //   * N exceeding the drive's storable maximum →
                        //     5/55/00 SYSTEM RESOURCE FAILURE.
                        //   * overlapping / unsorted / zero-count /
                        //     beyond-capacity extents → 5/26/00 INVALID
                        //     FIELD IN PARAMETER LIST.
                        //   * N == 0 → clear the current extents.
                        let new_extents =
                            parse_send_disc_structure_bus_encryption_sector_extents(data_out)?;
                        if new_extents.len() as u64 > self.max_bus_encryption_sector_extents as u64
                        {
                            // SYSTEM RESOURCE FAILURE — the host asked the
                            // drive to store more extents than it can hold.
                            return Err(AacsError::InvalidValue {
                                what: "SEND_DISC_STRUCTURE Format 0x85 extent count exceeds drive capacity",
                                value: new_extents.len() as u64,
                            });
                        }
                        validate_bus_encryption_sector_extents(
                            &new_extents,
                            self.media_capacity_lba,
                        )?;
                        // Accepted: replace the current set (an empty list
                        // clears it per §4.14.5.2 paragraph 1).
                        self.bus_encryption_sector_extents = new_extents;
                        Ok(ScsiResponse::good(Vec::new()))
                    }
                    other => Err(AacsError::InvalidValue {
                        what: "MockDrive SEND_DISC_STRUCTURE Format",
                        value: other as u64,
                    }),
                }
            }
            other => Err(AacsError::InvalidValue {
                what: "MockDrive unsupported opcode",
                value: other as u64,
            }),
        }
    }
}

// ---------------------------------------------------------------------
// Unit tests (CDB round-trips + length-field invariants)
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_key_cdb_layout_matches_mmc6_table_513() {
        let rk = ReportKey::aacs_drive_cert_challenge(2);
        let cdb = rk.cdb();
        assert_eq!(cdb[0], 0xA4, "opcode must be 0xA4");
        assert_eq!(cdb[7], 0x02, "Key Class AACS");
        // 116-byte allocation length = 0x0074 big-endian.
        assert_eq!(cdb[8], 0x00);
        assert_eq!(cdb[9], 0x74);
        // AGID=2 (binary 10) goes into bits 7..6 of byte 10; Key
        // Format 0x01 in bits 5..0. (2 << 6) | 0x01 = 0x81.
        assert_eq!(cdb[10], 0x81);
        assert_eq!(cdb[11], 0x00, "default Control byte");

        let parsed = ReportKey::parse_cdb(&cdb).unwrap();
        assert_eq!(parsed, rk);
    }

    #[test]
    fn send_key_cdb_layout_matches_mmc6_table_599() {
        let sk = SendKey::aacs_host_cert_challenge(3);
        let cdb = sk.cdb();
        assert_eq!(cdb[0], 0xA3);
        assert_eq!(cdb[7], 0x02);
        // Parameter list length 116 = 0x0074.
        assert_eq!(cdb[8], 0x00);
        assert_eq!(cdb[9], 0x74);
        // AGID=3, Key Format=0x01 → (3 << 6) | 0x01 = 0xC1.
        assert_eq!(cdb[10], 0xC1);

        let parsed = SendKey::parse_cdb(&cdb).unwrap();
        assert_eq!(parsed, sk);
    }

    #[test]
    fn read_disc_structure_cdb_layout_matches_mmc6_table_381() {
        let rds = ReadDiscStructure::aacs_volume_id(1);
        let cdb = rds.cdb();
        assert_eq!(cdb[0], 0xAD);
        // Media Type = BD (0x01) in low nibble of byte 1.
        assert_eq!(cdb[1] & 0x0F, 0x01);
        // Format = 0x80.
        assert_eq!(cdb[7], 0x80);
        // Allocation length 36 = 0x0024.
        assert_eq!(cdb[8], 0x00);
        assert_eq!(cdb[9], 0x24);
        // AGID=1 in bits 7..6 of byte 10. (1 << 6) = 0x40.
        assert_eq!(cdb[10], 0x40);

        let parsed = ReadDiscStructure::parse_cdb(&cdb).unwrap();
        assert_eq!(parsed, rds);
    }

    #[test]
    fn rejects_wrong_opcode_in_parse_cdb() {
        let mut cdb = [0u8; MMC_CDB_LEN];
        cdb[0] = 0xFF;
        assert!(ReportKey::parse_cdb(&cdb).is_err());
        assert!(SendKey::parse_cdb(&cdb).is_err());
        assert!(ReadDiscStructure::parse_cdb(&cdb).is_err());
    }

    #[test]
    fn agid_field_packing_round_trip() {
        for agid in 0..=3u8 {
            let rk = ReportKey {
                key_class: KEY_CLASS_AACS,
                key_format: KF_REPORT_AACS_DRIVE_KEY,
                agid,
                lba_or_starting_offset: 0,
                block_count_function: 0,
                allocation_length: 84,
                control: 0,
            };
            let cdb = rk.cdb();
            assert_eq!(cdb[10] >> 6, agid);
            let parsed = ReportKey::parse_cdb(&cdb).unwrap();
            assert_eq!(parsed.agid, agid);
        }
    }

    #[test]
    fn media_serial_cdb_uses_format_0x81() {
        let rds = ReadDiscStructure::aacs_media_serial(2);
        let cdb = rds.cdb();
        assert_eq!(cdb[0], READ_DISC_STRUCTURE_OPCODE);
        assert_eq!(cdb[7], FORMAT_AACS_MEDIA_SERIAL);
        // 36-byte allocation length = 0x0024.
        assert_eq!(cdb[8], 0x00);
        assert_eq!(cdb[9], 0x24);
        // AGID=2 occupies bits 7..6.
        assert_eq!(cdb[10] >> 6, 2);
    }

    #[test]
    fn media_id_cdb_uses_format_0x82() {
        let rds = ReadDiscStructure::aacs_media_id(3);
        let cdb = rds.cdb();
        assert_eq!(cdb[0], READ_DISC_STRUCTURE_OPCODE);
        assert_eq!(cdb[7], FORMAT_AACS_MEDIA_ID);
        assert_eq!(cdb[8], 0x00);
        assert_eq!(cdb[9], 0x24);
        assert_eq!(cdb[10] >> 6, 3);
    }

    #[test]
    fn media_serial_response_parser_round_trip() {
        let pmsn = [0xAA; VOLUME_ID_LEN];
        let mac = [0x55; ID_MAC_LEN];
        let mut wire = Vec::with_capacity(36);
        wire.extend_from_slice(&[0x00, 0x22, 0x00, 0x00]);
        wire.extend_from_slice(&pmsn);
        wire.extend_from_slice(&mac);
        let parsed = parse_media_serial_response(&wire).unwrap();
        assert_eq!(parsed.pmsn, pmsn);
        assert_eq!(parsed.mac, mac);
    }

    #[test]
    fn media_id_response_parser_round_trip() {
        let mid = [0x33; VOLUME_ID_LEN];
        let mac = [0xCC; ID_MAC_LEN];
        let mut wire = Vec::with_capacity(36);
        wire.extend_from_slice(&[0x00, 0x22, 0x00, 0x00]);
        wire.extend_from_slice(&mid);
        wire.extend_from_slice(&mac);
        let parsed = parse_media_id_response(&wire).unwrap();
        assert_eq!(parsed.media_id, mid);
        assert_eq!(parsed.mac, mac);
    }

    #[test]
    fn media_serial_parser_rejects_wrong_length_field() {
        let mut wire = vec![0x00, 0x10, 0x00, 0x00];
        wire.resize(36, 0);
        assert!(parse_media_serial_response(&wire).is_err());
    }

    #[test]
    fn media_id_parser_rejects_truncated_payload() {
        let wire = [0x00, 0x22, 0x00, 0x00, 0xAA, 0xBB];
        assert!(parse_media_id_response(&wire).is_err());
    }

    #[test]
    fn mkb_pack_response_parser_round_trip() {
        // Synthetic 32-byte MKB pack body. Per Table 4-18 the length
        // field counts the trailing reserved(1) + total_packs(1) +
        // pack_data(N) bytes — i.e. length = 2 + N.
        let pack_data: Vec<u8> = (0..32u8).collect();
        let total_packs = 5u8;
        let length: u16 = (2 + pack_data.len()) as u16;
        let mut wire = vec![
            (length >> 8) as u8,
            (length & 0xFF) as u8,
            0x00, // reserved
            total_packs,
        ];
        wire.extend_from_slice(&pack_data);
        let parsed = parse_mkb_pack_response(&wire).unwrap();
        assert_eq!(parsed.total_packs, total_packs);
        assert_eq!(parsed.pack_data, pack_data);
    }

    #[test]
    fn mkb_pack_parser_rejects_truncated_payload() {
        // Claims 100 bytes of pack data but the buffer is empty after
        // the 4-byte header.
        let wire = [0x00, 0x66, 0x00, 0x01];
        assert!(parse_mkb_pack_response(&wire).is_err());
    }

    #[test]
    fn binding_nonce_gen_cdb_encodes_lba_extent_per_4_14_2() {
        // Generate variant: Key Format 0x20, AGID=2, starting LBA
        // 0x01020304, block count 0x40. Bytes 2..5 must carry the LBA
        // big-endian per AACS Common §4.14.2 (final paragraph) and
        // byte 6 must carry the block count.
        let rk = ReportKey::aacs_binding_nonce_gen(2, 0x0102_0304, 0x40);
        let cdb = rk.cdb();
        assert_eq!(cdb[0], REPORT_KEY_OPCODE);
        assert_eq!(cdb[2], 0x01);
        assert_eq!(cdb[3], 0x02);
        assert_eq!(cdb[4], 0x03);
        assert_eq!(cdb[5], 0x04);
        assert_eq!(cdb[6], 0x40);
        assert_eq!(cdb[7], KEY_CLASS_AACS);
        // 36-byte allocation length = 0x0024.
        assert_eq!(cdb[8], 0x00);
        assert_eq!(cdb[9], 0x24);
        // AGID=2 in bits 7..6, Key Format 0x20 in bits 5..0.
        // (2 << 6) | 0x20 = 0xA0.
        assert_eq!(cdb[10], 0xA0);
        // Round-trip through parse_cdb preserves every field.
        let parsed = ReportKey::parse_cdb(&cdb).unwrap();
        assert_eq!(parsed, rk);
        assert_eq!(parsed.key_format, KF_REPORT_AACS_BINDING_NONCE_GEN);
        assert_eq!(parsed.lba_or_starting_offset, 0x0102_0304);
        assert_eq!(parsed.block_count_function, 0x40);
    }

    #[test]
    fn binding_nonce_read_cdb_uses_key_format_0x21() {
        // Read variant: Key Format 0x21, AGID=3, starting LBA 0, block
        // count 1.
        let rk = ReportKey::aacs_binding_nonce_read(3, 0, 1);
        let cdb = rk.cdb();
        assert_eq!(cdb[7], KEY_CLASS_AACS);
        // Same allocation length as the generate variant (Table 4-11
        // is identical to Table 4-10).
        assert_eq!(cdb[8], 0x00);
        assert_eq!(cdb[9], 0x24);
        // (3 << 6) | 0x21 = 0xE1.
        assert_eq!(cdb[10], 0xE1);
        assert_eq!(cdb[6], 0x01);
        let parsed = ReportKey::parse_cdb(&cdb).unwrap();
        assert_eq!(parsed.key_format, KF_REPORT_AACS_BINDING_NONCE_READ);
    }

    #[test]
    fn binding_nonce_response_parser_round_trip() {
        let nonce = [0xA5; BINDING_NONCE_LEN];
        let mac = [0x5A; BINDING_NONCE_MAC_LEN];
        let mut wire = Vec::with_capacity(36);
        wire.extend_from_slice(&[0x00, 0x22, 0x00, 0x00]);
        wire.extend_from_slice(&nonce);
        wire.extend_from_slice(&mac);
        let parsed = parse_report_key_binding_nonce(&wire).unwrap();
        assert_eq!(parsed.binding_nonce, nonce);
        assert_eq!(parsed.mac, mac);
    }

    #[test]
    fn binding_nonce_parser_rejects_wrong_length_field() {
        // Length field 0x0010 != 0x0022.
        let mut wire = vec![0x00, 0x10, 0x00, 0x00];
        wire.resize(36, 0);
        assert!(parse_report_key_binding_nonce(&wire).is_err());
    }

    #[test]
    fn binding_nonce_parser_rejects_truncated_payload() {
        // Length field is correct but payload is short.
        let wire = [0x00, 0x22, 0x00, 0x00, 0xAA, 0xBB];
        assert!(parse_report_key_binding_nonce(&wire).is_err());
    }

    #[test]
    fn data_keys_cdb_uses_format_0x84() {
        let rds = ReadDiscStructure::aacs_data_keys(2);
        let cdb = rds.cdb();
        assert_eq!(cdb[0], READ_DISC_STRUCTURE_OPCODE);
        assert_eq!(cdb[1] & 0x0F, MEDIA_TYPE_BD);
        assert_eq!(cdb[7], FORMAT_AACS_DATA_KEYS);
        // 36-byte allocation length = 0x0024.
        assert_eq!(cdb[8], 0x00);
        assert_eq!(cdb[9], 0x24);
        // AGID=2 occupies bits 7..6 of byte 10.
        assert_eq!(cdb[10] >> 6, 2);
        // Format `0x84` does not address an LBA / layer.
        assert_eq!(cdb[2..6], [0u8; 4]);
        assert_eq!(cdb[6], 0);

        let parsed = ReadDiscStructure::parse_cdb(&cdb).unwrap();
        assert_eq!(parsed, rds);
    }

    #[test]
    fn data_keys_response_parser_round_trip() {
        // Synthesize a Table 4-19 payload by hand:
        // [length:0x0022][reserved:u16][Krd:16][Kwd:16] = 36 bytes.
        let mut wire = vec![0x00, 0x22, 0x00, 0x00];
        let krd = [0xA5u8; DATA_KEY_LEN];
        let kwd = [0x5Au8; DATA_KEY_LEN];
        wire.extend_from_slice(&krd);
        wire.extend_from_slice(&kwd);
        assert_eq!(wire.len(), 36);

        let parsed = parse_data_keys_response(&wire).unwrap();
        assert_eq!(parsed.read_data_key_encrypted, krd);
        assert_eq!(parsed.write_data_key_encrypted, kwd);
    }

    #[test]
    fn data_keys_parser_rejects_wrong_length_field() {
        // Length field 0x0020 != 0x0022.
        let mut wire = vec![0x00, 0x20, 0x00, 0x00];
        wire.resize(36, 0);
        assert!(parse_data_keys_response(&wire).is_err());
    }

    #[test]
    fn data_keys_parser_rejects_truncated_payload() {
        let wire = [0x00, 0x22, 0x00, 0x00, 0xAA, 0xBB];
        assert!(parse_data_keys_response(&wire).is_err());
    }

    #[test]
    fn data_keys_response_decrypts_under_bus_key() {
        // Round-trip property: wrapping plaintext Krd / Kwd under a Bus
        // Key with AES-128E and unwrapping with AES-128D recovers the
        // plaintext bytes verbatim (AACS Common §2.1.1, §4.11).
        let bus_key = [0x12u8; 16];
        let krd_pt = [0x33u8; DATA_KEY_LEN];
        let kwd_pt = [0x44u8; DATA_KEY_LEN];

        let krd_enc = crate::aes::aes_128_ecb_encrypt(&bus_key, &krd_pt);
        let kwd_enc = crate::aes::aes_128_ecb_encrypt(&bus_key, &kwd_pt);

        let resp = DataKeysResponse {
            read_data_key_encrypted: krd_enc,
            write_data_key_encrypted: kwd_enc,
        };
        assert_eq!(resp.decrypt_read_data_key(&bus_key), krd_pt);
        assert_eq!(resp.decrypt_write_data_key(&bus_key), kwd_pt);
    }

    #[test]
    fn bus_encryption_sector_extents_cdb_uses_format_0x85() {
        let rds = ReadDiscStructure::aacs_bus_encryption_sector_extents();
        let cdb = rds.cdb();
        assert_eq!(cdb[0], READ_DISC_STRUCTURE_OPCODE);
        assert_eq!(cdb[1] & 0x0F, MEDIA_TYPE_BD);
        assert_eq!(cdb[7], FORMAT_AACS_BUS_ENCRYPTION_SECTOR_EXTENTS);
        // Allocation length = 12 + 256*16 = 4108 = 0x100C.
        assert_eq!(cdb[8], 0x10);
        assert_eq!(cdb[9], 0x0C);
        // §4.14.3.6: no AGID required; bits 7..6 of byte 10 left zero.
        assert_eq!(cdb[10], 0x00);
        // Address (bytes 2..5) and Layer Number (byte 6) reserved.
        assert_eq!(cdb[2..6], [0u8; 4]);
        assert_eq!(cdb[6], 0);
        let parsed = ReadDiscStructure::parse_cdb(&cdb).unwrap();
        assert_eq!(parsed, rds);
    }

    #[test]
    fn bus_encryption_sector_extents_empty_table_round_trip() {
        // §4.14.3.6 paragraph 2: empty table ⇒ Data Length = 2.
        let wire = [0x00, 0x02, 0x00, 0x40];
        let parsed = parse_bus_encryption_sector_extents_response(&wire).unwrap();
        assert_eq!(parsed.maximum, 0x40);
        assert!(parsed.extents.is_empty());
    }

    #[test]
    fn bus_encryption_sector_extents_two_extents_round_trip() {
        // length = 2*16 + 2 = 34 = 0x0022. Maximum = 4.
        // Extent 0: Start LBA = 0x0000_0100, LBA Count = 0x0000_0080.
        // Extent 1: Start LBA = 0x0000_1000, LBA Count = 0x0000_0040.
        let mut wire = vec![0x00, 0x22, 0x00, 0x04];
        // Extent 0 record (bytes 4..19): 8 Reserved + Start LBA + Count.
        wire.extend_from_slice(&[0u8; 8]);
        wire.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]);
        wire.extend_from_slice(&[0x00, 0x00, 0x00, 0x80]);
        // Extent 1 record (bytes 20..35).
        wire.extend_from_slice(&[0u8; 8]);
        wire.extend_from_slice(&[0x00, 0x00, 0x10, 0x00]);
        wire.extend_from_slice(&[0x00, 0x00, 0x00, 0x40]);
        assert_eq!(wire.len(), 36);
        let parsed = parse_bus_encryption_sector_extents_response(&wire).unwrap();
        assert_eq!(parsed.maximum, 4);
        assert_eq!(parsed.extents.len(), 2);
        assert_eq!(parsed.extents[0].start_lba, 0x0000_0100);
        assert_eq!(parsed.extents[0].lba_count, 0x0000_0080);
        assert_eq!(parsed.extents[1].start_lba, 0x0000_1000);
        assert_eq!(parsed.extents[1].lba_count, 0x0000_0040);
    }

    #[test]
    fn bus_encryption_sector_extents_maximum_zero_decodes_as_256() {
        // §4.14.3.6 paragraph 3: the on-wire value 0 denotes 256.
        let wire = [0x00, 0x02, 0x00, 0x00];
        let parsed = parse_bus_encryption_sector_extents_response(&wire).unwrap();
        assert_eq!(parsed.maximum, 256);
        assert!(parsed.extents.is_empty());
    }

    #[test]
    fn bus_encryption_sector_extents_parser_rejects_misaligned_stride() {
        // length = 17 → (17 - 2) = 15 bytes for extents; 15 is not a
        // multiple of 16, so the parser rejects.
        let mut wire = vec![0x00, 0x11, 0x00, 0x01];
        wire.resize(2 + 17, 0);
        assert!(parse_bus_encryption_sector_extents_response(&wire).is_err());
    }

    #[test]
    fn bus_encryption_sector_extents_parser_rejects_truncated_payload() {
        // Claims length 0x0022 (one extent + trailer), but the buffer
        // is much shorter.
        let wire = [0x00, 0x22, 0x00, 0x01, 0xAA, 0xBB];
        assert!(parse_bus_encryption_sector_extents_response(&wire).is_err());
    }

    #[test]
    fn bus_encryption_sector_extents_parser_rejects_truncated_header() {
        // Single byte: cannot even read the length field.
        let wire = [0x00];
        assert!(parse_bus_encryption_sector_extents_response(&wire).is_err());
    }

    #[test]
    fn mock_drive_bus_encryption_sector_extents_round_trip() {
        let mut drive = MockDrive::with_test_fixture();
        let cdb = ReadDiscStructure::aacs_bus_encryption_sector_extents().cdb();
        let response = drive
            .execute(&cdb, DataDirection::FromDevice, &[], 4108)
            .unwrap();
        assert_eq!(response.status, 0x00);
        // length = 2 + 2 * 16 = 34 = 0x0022.
        assert_eq!(response.data[0], 0x00);
        assert_eq!(response.data[1], 0x22);
        // byte 2 Reserved, byte 3 Maximum (fixture = 4).
        assert_eq!(response.data[2], 0x00);
        assert_eq!(response.data[3], 0x04);
        let parsed = parse_bus_encryption_sector_extents_response(&response.data).unwrap();
        assert_eq!(parsed.maximum, 4);
        assert_eq!(parsed.extents, drive.bus_encryption_sector_extents);
    }

    #[test]
    fn mock_drive_bus_encryption_sector_extents_empty_table_encodes_length_2() {
        // Empty extent list → Data Length field shall be 2 per
        // §4.14.3.6 paragraph 2.
        let mut drive = MockDrive::with_test_fixture();
        drive.bus_encryption_sector_extents.clear();
        drive.max_bus_encryption_sector_extents = 7;
        let cdb = ReadDiscStructure::aacs_bus_encryption_sector_extents().cdb();
        let response = drive
            .execute(&cdb, DataDirection::FromDevice, &[], 4108)
            .unwrap();
        assert_eq!(response.data[0], 0x00);
        assert_eq!(response.data[1], 0x02);
        assert_eq!(response.data[2], 0x00);
        assert_eq!(response.data[3], 0x07);
        assert_eq!(response.data.len(), 4);
        let parsed = parse_bus_encryption_sector_extents_response(&response.data).unwrap();
        assert_eq!(parsed.maximum, 7);
        assert!(parsed.extents.is_empty());
    }

    #[test]
    fn mock_drive_bus_encryption_sector_extents_max_256_encodes_as_zero() {
        let mut drive = MockDrive::with_test_fixture();
        drive.bus_encryption_sector_extents.clear();
        drive.max_bus_encryption_sector_extents = 256;
        let cdb = ReadDiscStructure::aacs_bus_encryption_sector_extents().cdb();
        let response = drive
            .execute(&cdb, DataDirection::FromDevice, &[], 4108)
            .unwrap();
        // Wire-level sentinel: 256 → byte 0x00 per §4.14.3.6.
        assert_eq!(response.data[3], 0x00);
        let parsed = parse_bus_encryption_sector_extents_response(&response.data).unwrap();
        assert_eq!(parsed.maximum, 256);
    }

    #[test]
    fn mock_drive_data_keys_format_static_mode_returns_plaintext_bytes() {
        // Without `auth` set, the mock returns the plaintext Data Keys
        // verbatim. Useful for byte-layout tests that do not want to
        // pull in the AKE state.
        let mut drive = MockDrive::with_test_fixture();
        let rds = ReadDiscStructure::aacs_data_keys(1);
        let cdb = rds.cdb();
        let resp = drive
            .execute(&cdb, DataDirection::FromDevice, &[], 36)
            .unwrap();
        let parsed = parse_data_keys_response(&resp.data).unwrap();
        assert_eq!(parsed.read_data_key_encrypted, drive.read_data_key);
        assert_eq!(parsed.write_data_key_encrypted, drive.write_data_key);
        assert!(drive.last_data_keys_read);
    }

    #[test]
    fn send_disc_structure_cdb_layout_matches_table_4_26() {
        // AACS Common §4.14.5 Table 4-26 / MMC-6 Table 572: opcode
        // 0xBF, Media Type in the low nibble of byte 1, bytes 2..6
        // Reserved, Format Code at byte 7, Parameter List Length at
        // bytes 8..9 big-endian, AGID in bits 7..6 of byte 10.
        let sds = SendDiscStructure::aacs_write_data_key(2);
        let cdb = sds.cdb();
        assert_eq!(cdb[0], 0xBF);
        assert_eq!(cdb[1] & 0x0F, MEDIA_TYPE_BD);
        assert_eq!(cdb[2..7], [0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(cdb[7], 0x84);
        // Parameter list length 20 = 0x0014 big-endian.
        assert_eq!(cdb[8], 0x00);
        assert_eq!(cdb[9], 0x14);
        // AGID=2 in bits 7..6 of byte 10; low 6 bits reserved.
        assert_eq!(cdb[10], 0x80);
        assert_eq!(cdb[11], 0x00);

        let parsed = SendDiscStructure::parse_cdb(&cdb).unwrap();
        assert_eq!(parsed, sds);
    }

    #[test]
    fn send_disc_structure_parse_cdb_rejects_wrong_opcode() {
        let mut cdb = [0u8; MMC_CDB_LEN];
        cdb[0] = 0xAD;
        assert!(SendDiscStructure::parse_cdb(&cdb).is_err());
    }

    #[test]
    fn write_data_key_parameter_list_round_trip_matches_table_4_28() {
        // Table 4-28: [length:u16=0x0012][reserved:u16][Kwd:16]; the
        // key field occupies bytes 4..19. Index-tag the key bytes so a
        // positional slip surfaces as a wrong value.
        let mut kwd = [0u8; DATA_KEY_LEN];
        for (i, b) in kwd.iter_mut().enumerate() {
            *b = 0xE0 | (i as u8);
        }
        let wire = build_send_disc_structure_write_data_key(&kwd);
        assert_eq!(wire.len(), 20);
        assert_eq!(wire[..4], [0x00, 0x12, 0x00, 0x00]);
        assert_eq!(wire[4..], kwd);
        assert_eq!(
            parse_send_disc_structure_write_data_key(&wire).unwrap(),
            kwd
        );
    }

    #[test]
    fn write_data_key_parameter_list_rejects_wrong_length_field() {
        // Table 4-28 mandates the length field value 0x0012 for Format
        // 0x84; any other value is a malformed parameter list.
        let mut wire = vec![0x00, 0x22, 0x00, 0x00];
        wire.resize(20, 0);
        assert!(parse_send_disc_structure_write_data_key(&wire).is_err());
    }

    #[test]
    fn write_data_key_parameter_list_rejects_truncated_payload() {
        // Correct length field, but fewer than 20 total bytes.
        let wire = [0x00, 0x12, 0x00, 0x00, 0xAA, 0xBB];
        assert!(parse_send_disc_structure_write_data_key(&wire).is_err());
    }

    #[test]
    fn mock_drive_send_write_data_key_static_mode_stores_wire_bytes() {
        // Without `auth`, the wire bytes are adopted verbatim as the
        // new Write Data Key; the Read Data Key is untouched.
        let mut drive = MockDrive::with_test_fixture();
        let old_krd = drive.read_data_key;
        let mut new_kwd = [0u8; DATA_KEY_LEN];
        for (i, b) in new_kwd.iter_mut().enumerate() {
            *b = 0xF0 | (i as u8);
        }
        let cdb = SendDiscStructure::aacs_write_data_key(1).cdb();
        let wire = build_send_disc_structure_write_data_key(&new_kwd);
        let resp = drive
            .execute(&cdb, DataDirection::ToDevice, &wire, 0)
            .unwrap();
        assert_eq!(resp.status, 0x00);
        assert!(resp.data.is_empty());
        assert_eq!(drive.write_data_key, new_kwd);
        assert_eq!(drive.last_write_data_key_sent, Some(new_kwd));
        assert_eq!(drive.read_data_key, old_krd);
    }

    #[test]
    fn mock_drive_send_disc_structure_rejects_unknown_format() {
        let mut drive = MockDrive::with_test_fixture();
        let mut sds = SendDiscStructure::aacs_write_data_key(0);
        sds.format = 0x87;
        let wire = build_send_disc_structure_write_data_key(&[0u8; DATA_KEY_LEN]);
        assert!(drive
            .execute(&sds.cdb(), DataDirection::ToDevice, &wire, 0)
            .is_err());
    }

    #[test]
    fn mock_drive_send_disc_structure_rejects_wrong_direction() {
        // A SEND DISC STRUCTURE dispatched as a FromDevice transfer is
        // a caller bug; the drive state must remain untouched.
        let mut drive = MockDrive::with_test_fixture();
        let before = drive.write_data_key;
        let cdb = SendDiscStructure::aacs_write_data_key(0).cdb();
        let wire = build_send_disc_structure_write_data_key(&[0x55u8; DATA_KEY_LEN]);
        assert!(drive
            .execute(&cdb, DataDirection::FromDevice, &wire, 0)
            .is_err());
        assert_eq!(drive.write_data_key, before);
        assert_eq!(drive.last_write_data_key_sent, None);
    }
}
