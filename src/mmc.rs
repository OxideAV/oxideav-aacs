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

// ---------------------------------------------------------------------
// DriveCommand trait + mock drive
// ---------------------------------------------------------------------

/// Direction of the SCSI data phase for an MMC CDB. Set by callers when
/// dispatching through the [`DriveCommand`] trait. The opcode itself
/// determines the direction (REPORT KEY + READ DISC STRUCTURE are
/// drive→host; SEND KEY is host→drive), but the explicit enum makes
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
/// Used exclusively by the Phase B test suite. The mock honours the
/// dispatch path a real drive would follow: it inspects the CDB,
/// recognises the AACS Key Format / Format Code, and returns a
/// hand-stuffed payload (or stores the incoming SEND KEY parameter
/// list for later inspection by the test).
///
/// Manual `Default` implementation rather than `#[derive(Default)]`
/// because `Default` is only auto-derived for arrays up to length 32;
/// the 40-byte ECDSA-secp160r1 point/signature fields and the 92-byte
/// certificate field exceed that bound.
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
            last_host_cert_chal: None,
            last_host_key: None,
            agid_invalidated: false,
            auth: None,
        }
    }
}

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
            last_host_cert_chal: None,
            last_host_key: None,
            agid_invalidated: false,
            auth: None,
        }
    }
}

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
                    other => Err(AacsError::InvalidValue {
                        what: "MockDrive READ_DISC_STRUCTURE Format",
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
}
