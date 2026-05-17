//! Unit_Key_RO.inf parser per BD-Prerecorded spec §3.9.3.
//!
//! Layout (Table 3-12):
//!
//! ```text
//! +----------------------------------------+
//! | Unit_Key_Block_start_address (32 bits) | offset 0
//! +----------------------------------------+
//! | Reserved (96 bits)                     |
//! +----------------------------------------+
//! | Unit_Key_File_Header()                 | (Table 3-13)
//! +----------------------------------------+
//! | padding (16-byte aligned)              |
//! +----------------------------------------+
//! | Unit_Key_Block()                       | (Table 3-15)
//! +----------------------------------------+
//! | padding to 65536-byte boundary         |
//! +----------------------------------------+
//! ```
//!
//! The Unit_Key_Block() per Table 3-15 holds, for each CPS Unit, the
//! 16-byte `MAC of PMSN`, the 16-byte `MAC of Device Binding Nonce`,
//! and the 16-byte `Encrypted CPS Unit Key`.

use crate::error::AacsError;

/// Parsed `Unit_Key_File_Header()` per BD-Prerecorded §3.9.3 Table 3-13.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitKeyFileHeader {
    /// `Application_Type` — `0x01` for BDMV (the only value the spec
    /// currently defines).
    pub application_type: u8,
    /// `Num_of_BD_Directory` — `0x01` for BDMV.
    pub num_of_bd_directory: u8,
    /// `Use_SKB_Unified_MKB_Flag` — `true` if Sequence Key Blocks
    /// and Unified MKBs are used on the disc.
    pub use_skb_unified_mkb: bool,
    /// Per BD-directory listings of CPS unit numbers for First
    /// Playback / Top Menu / Titles.
    pub bd_directories: Vec<BdDirectoryHeader>,
}

/// Per BD-Application-directory listing inside `Unit_Key_File_Header()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BdDirectoryHeader {
    /// CPS_Unit_number that First Playback maps to (0 if none).
    pub cps_unit_number_for_first_playback: u16,
    /// CPS_Unit_number that Top Menu maps to (0 if none).
    pub cps_unit_number_for_top_menu: u16,
    /// CPS_Unit_number assigned to each Title in this directory.
    /// Note: spec Table 3-13 indexes titles from `J=1`, so this list
    /// is 1-indexed in the *spec* but stored 0-indexed here.
    pub cps_unit_numbers_for_titles: Vec<u16>,
}

/// One per-CPS-Unit record from `Unit_Key_Block()` per BD-Prerecorded
/// §3.9.3 Table 3-15.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpsUnitRecord {
    /// `MAC of Pre-recorded Media Serial Number` per spec text:
    /// `CMAC(K_cu, PMSN)`. All-zero when this CPS Unit is not bound
    /// to the PMSN.
    pub mac_of_pmsn: [u8; 16],
    /// `MAC of Device Binding Nonce` per spec: `CMAC(K_cu, DBN)`.
    /// All-zero when this CPS Unit is not bound to the player.
    pub mac_of_device_binding_nonce: [u8; 16],
    /// `Encrypted CPS Unit Key` = `AES-128E(K_vu, K_cu)` per spec.
    pub encrypted_cps_unit_key: [u8; 16],
}

/// A parsed `Unit_Key_RO.inf` file.
#[derive(Debug, Clone)]
pub struct UnitKeyFile {
    /// `Unit_Key_Block_start_address` field — byte offset from the
    /// start of the file at which `Unit_Key_Block()` begins. Always
    /// a multiple of 16.
    pub unit_key_block_start_address: u32,
    /// Parsed file header.
    pub header: UnitKeyFileHeader,
    /// Per-CPS-Unit records from `Unit_Key_Block()`.
    pub cps_units: Vec<CpsUnitRecord>,
}

impl UnitKeyFile {
    /// Parse a `Unit_Key_RO.inf` byte stream per BD-Prerecorded spec
    /// §3.9.3.
    pub fn parse(bytes: &[u8]) -> Result<Self, AacsError> {
        if bytes.len() < 16 {
            return Err(AacsError::Truncated("Unit_Key_RO.inf"));
        }
        let unit_key_block_start_address =
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        // Bytes [4..16] are 96 reserved bits.

        // Header starts at byte 16.
        let header = parse_header(&bytes[16..])?;

        let kbs = unit_key_block_start_address as usize;
        if kbs >= bytes.len() {
            return Err(AacsError::OversizedRecord {
                what: "Unit_Key_Block",
                declared: kbs,
                available: bytes.len(),
            });
        }
        if kbs % 16 != 0 {
            return Err(AacsError::InvalidValue {
                what: "Unit_Key_Block_start_address (not 16-byte aligned)",
                value: kbs as u64,
            });
        }
        let cps_units = parse_unit_key_block(&bytes[kbs..])?;

        Ok(Self {
            unit_key_block_start_address,
            header,
            cps_units,
        })
    }
}

fn parse_header(slice: &[u8]) -> Result<UnitKeyFileHeader, AacsError> {
    // Layout per Table 3-13:
    //   Application_Type            (8 bits)
    //   Num_of_BD_Directory         (8 bits)
    //   Use_SKB_Unified_MKB_Flag    (1 bit)
    //   reserved                    (15 bits)
    //   For each BD directory:
    //     CPS_Unit_number for First Playback#I  (16 bits)
    //     CPS_Unit_number for Top Menu#I        (16 bits)
    //     Num_of_Title#I                        (16 bits)
    //     For J=1..Num_of_Title:
    //       reserved                            (16 bits)
    //       CPS_Unit_number for Title#J         (16 bits)
    if slice.len() < 4 {
        return Err(AacsError::Truncated("Unit_Key_File_Header"));
    }
    let application_type = slice[0];
    let num_of_bd_directory = slice[1];
    let use_skb_unified_mkb = (slice[2] & 0x80) != 0;
    // slice[2] low 7 bits + slice[3] are reserved.
    let mut cursor = 4;
    let mut bd_directories = Vec::with_capacity(num_of_bd_directory as usize);
    for _ in 0..num_of_bd_directory {
        if cursor + 6 > slice.len() {
            return Err(AacsError::Truncated("Unit_Key_File_Header (per-BD)"));
        }
        let cps_first = u16::from_be_bytes([slice[cursor], slice[cursor + 1]]);
        let cps_topmenu = u16::from_be_bytes([slice[cursor + 2], slice[cursor + 3]]);
        let num_titles = u16::from_be_bytes([slice[cursor + 4], slice[cursor + 5]]);
        cursor += 6;
        let mut titles = Vec::with_capacity(num_titles as usize);
        for _ in 0..num_titles {
            if cursor + 4 > slice.len() {
                return Err(AacsError::Truncated("Unit_Key_File_Header (per-Title)"));
            }
            // 16-bit reserved then 16-bit CPS_Unit_number
            let _ = u16::from_be_bytes([slice[cursor], slice[cursor + 1]]);
            let cps = u16::from_be_bytes([slice[cursor + 2], slice[cursor + 3]]);
            titles.push(cps);
            cursor += 4;
        }
        bd_directories.push(BdDirectoryHeader {
            cps_unit_number_for_first_playback: cps_first,
            cps_unit_number_for_top_menu: cps_topmenu,
            cps_unit_numbers_for_titles: titles,
        });
    }
    Ok(UnitKeyFileHeader {
        application_type,
        num_of_bd_directory,
        use_skb_unified_mkb,
        bd_directories,
    })
}

fn parse_unit_key_block(slice: &[u8]) -> Result<Vec<CpsUnitRecord>, AacsError> {
    // Layout per Table 3-15:
    //   Num_of_CPS_Unit (16 bits)
    //   reserved        (112 bits = 14 bytes)
    //   for I=1..Num_of_CPS_Unit:
    //     MAC of PMSN                  (128 bits)
    //     MAC of Device Binding Nonce  (128 bits)
    //     Encrypted CPS Unit Key       (128 bits)
    if slice.len() < 16 {
        return Err(AacsError::Truncated("Unit_Key_Block header"));
    }
    let n = u16::from_be_bytes([slice[0], slice[1]]) as usize;
    let mut cursor: usize = 16; // 2 + 14
    let need = n
        .checked_mul(48)
        .and_then(|n| cursor.checked_add(n))
        .ok_or(AacsError::InvalidValue {
            what: "Num_of_CPS_Unit (overflow)",
            value: n as u64,
        })?;
    if need > slice.len() {
        return Err(AacsError::OversizedRecord {
            what: "Unit_Key_Block entries",
            declared: need,
            available: slice.len(),
        });
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let mut mac_pmsn = [0u8; 16];
        let mut mac_dbn = [0u8; 16];
        let mut enc_cuk = [0u8; 16];
        mac_pmsn.copy_from_slice(&slice[cursor..cursor + 16]);
        mac_dbn.copy_from_slice(&slice[cursor + 16..cursor + 32]);
        enc_cuk.copy_from_slice(&slice[cursor + 32..cursor + 48]);
        cursor += 48;
        out.push(CpsUnitRecord {
            mac_of_pmsn: mac_pmsn,
            mac_of_device_binding_nonce: mac_dbn,
            encrypted_cps_unit_key: enc_cuk,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal Unit_Key_RO.inf with `n` CPS units, each
    /// initialised to per-unit deterministic 16-byte patterns.
    pub(crate) fn build_minimal(n: u16) -> (Vec<u8>, Vec<[u8; 16]>) {
        // Header layout: 4-byte start address + 12 reserved + header
        // bytes. We'll put the Unit_Key_Block at offset 0x80 (128) for
        // simplicity (16-aligned, comfortably past the header).
        let kbs = 0x80u32;
        let mut out = vec![0u8; kbs as usize];
        // start address big-endian
        out[0..4].copy_from_slice(&kbs.to_be_bytes());
        // bytes 4..16 reserved zero (already)
        // header bytes start at 16
        out[16] = 0x01; // Application_Type = BDMV
        out[17] = 0x01; // Num_of_BD_Directory = 1
        out[18] = 0x00; // use_skb_unified_mkb = 0, reserved 0
        out[19] = 0x00;
        // per-BD: 6 bytes (first 16b, top menu 16b, num_titles 16b)
        out[20..22].copy_from_slice(&1u16.to_be_bytes()); // First Playback -> unit 1
        out[22..24].copy_from_slice(&1u16.to_be_bytes()); // Top Menu -> unit 1
        out[24..26].copy_from_slice(&0u16.to_be_bytes()); // Num_of_Title = 0 (titles aren't required for our parser tests)

        // Unit_Key_Block: 2-byte n, 14 reserved, then n*48 entries.
        out.extend_from_slice(&n.to_be_bytes());
        out.extend_from_slice(&[0u8; 14]);
        let mut encrypted_keys = Vec::with_capacity(n as usize);
        for i in 0..n {
            out.extend_from_slice(&[0u8; 16]); // MAC of PMSN
            out.extend_from_slice(&[0u8; 16]); // MAC of DBN
            let mut k = [0u8; 16];
            for (j, byte) in k.iter_mut().enumerate() {
                *byte = ((i as u8).wrapping_add(j as u8)).wrapping_add(0x10);
            }
            out.extend_from_slice(&k);
            encrypted_keys.push(k);
        }
        (out, encrypted_keys)
    }

    #[test]
    fn parses_minimal_unit_key_file() {
        let (bytes, keys) = build_minimal(2);
        let parsed = UnitKeyFile::parse(&bytes).unwrap();
        assert_eq!(parsed.unit_key_block_start_address, 0x80);
        assert_eq!(parsed.header.application_type, 0x01);
        assert_eq!(parsed.header.num_of_bd_directory, 1);
        assert_eq!(parsed.cps_units.len(), 2);
        assert_eq!(parsed.cps_units[0].encrypted_cps_unit_key, keys[0]);
        assert_eq!(parsed.cps_units[1].encrypted_cps_unit_key, keys[1]);
    }

    #[test]
    fn rejects_truncated_file() {
        let bytes = vec![0u8; 4];
        assert!(matches!(
            UnitKeyFile::parse(&bytes),
            Err(AacsError::Truncated(_))
        ));
    }

    #[test]
    fn rejects_misaligned_start_address() {
        let mut bytes = vec![0u8; 64];
        // start address = 33 (not 16-aligned)
        bytes[0..4].copy_from_slice(&33u32.to_be_bytes());
        // give it a minimal valid header at offset 16
        bytes[16] = 1;
        bytes[17] = 1;
        assert!(matches!(
            UnitKeyFile::parse(&bytes),
            Err(AacsError::InvalidValue { .. })
        ));
    }
}
