//! `CCI_and_other_info()` — the Copy Control Information and title-usage
//! structures carried in the CPS Unit Usage File, per the Blu-ray Disc
//! Pre-recorded Book §3.9.4 (Tables 3-17 through 3-33).
//!
//! The **CPS Unit Usage File** ([`CpsUnitUsageFile`], Table 3-17) is the
//! per-CPS-Unit file whose SHA-1 the Content Certificate binds
//! (`Hash_Value_of_CPS_Unit_Usage_File`). It holds a **Primary CCI
//! Area** and an optional **Secondary CCI Area**, each a run of
//! [`CciAndOtherInfo`] blocks (Table 3-18). Four block types are
//! defined (Table 3-19):
//!
//! | `CCI_and_other_info_type` | Structure | Table |
//! |---------------------------|-----------|-------|
//! | `0x0101` | [`BasicCci`] — the copy-control bits (EPN/CCI, ICT, DOT, APSTB) + per-Title Basic/Enhanced flags | 3-20 |
//! | `0x0111` | [`EnhancedTitleUsage`] — per-Title cacheable-permission window (`After`/`Before`) | 3-27 |
//! | `0x0112` | [`KeyManagementOnline`] — Unit-Key status + on-line Binding Type | 3-30 |
//! | `0x0113` | [`ContentOwnerAuthorizedOutputs`] — 128-bit Output Control Bits | 3-33 |
//!
//! Every structure round-trips: `parse(&to_bytes()) == self`. This
//! module carries no key material — the Usage File is public,
//! integrity-protected on-disc data.

use crate::error::AacsError;

/// `CCI_and_other_info_type` for [`BasicCci`] (Table 3-19).
pub const CCI_TYPE_BASIC: u16 = 0x0101;
/// `CCI_and_other_info_type` for [`EnhancedTitleUsage`] (Table 3-19).
pub const CCI_TYPE_ENHANCED_TITLE_USAGE: u16 = 0x0111;
/// `CCI_and_other_info_type` for [`KeyManagementOnline`] (Table 3-19).
pub const CCI_TYPE_KEY_MANAGEMENT_ONLINE: u16 = 0x0112;
/// `CCI_and_other_info_type` for [`ContentOwnerAuthorizedOutputs`]
/// (Table 3-19).
pub const CCI_TYPE_CONTENT_OWNER_OUTPUTS: u16 = 0x0113;

/// The `CCI_and_other_info_version` shared by every §3.9.4 structure in
/// revision 0.953 (`0x0100`).
pub const CCI_VERSION_0100: u16 = 0x0100;

/// Fixed header size of a `CCI_and_other_info()` block: `type` (2) +
/// `version` (2) + `data_length` (2).
pub const CCI_HEADER_LEN: usize = 6;

/// `data_length` of [`BasicCci`] (`0x0084`, Table 3-20).
pub const BASIC_CCI_DATA_LEN: usize = 0x0084;
/// `data_length` of [`EnhancedTitleUsage`] (`0x0020`, Table 3-27).
pub const ENHANCED_TITLE_USAGE_DATA_LEN: usize = 0x0020;
/// `data_length` of [`KeyManagementOnline`] (`0x0010`, Table 3-30).
pub const KEY_MANAGEMENT_ONLINE_DATA_LEN: usize = 0x0010;
/// `data_length` of [`ContentOwnerAuthorizedOutputs`] (`0x0010`,
/// Table 3-33).
pub const CONTENT_OWNER_OUTPUTS_DATA_LEN: usize = 0x0010;

/// The Basic CCI title-type bitmap occupies a fixed 1024 bits
/// (128 bytes); the first `Num_of_Title` bits are meaningful.
const BASIC_CCI_TITLE_BITMAP_BITS: usize = 1024;

/// A raw `CCI_and_other_info()` block (BD-Prerecorded Table 3-18).
///
/// The `data` field holds exactly `data_length` bytes — the type-
/// specific payload, decoded by the typed accessors ([`as_basic_cci`]
/// etc.). Unknown / reserved types are preserved verbatim so a
/// round-trip is lossless.
///
/// [`as_basic_cci`]: CciAndOtherInfo::as_basic_cci
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CciAndOtherInfo {
    /// `CCI_and_other_info_type` (Table 3-19).
    pub info_type: u16,
    /// `CCI_and_other_info_version`.
    pub version: u16,
    /// `CCI_and_other_info_data()` — `data_length` bytes.
    pub data: Vec<u8>,
}

impl CciAndOtherInfo {
    /// Parse one block from the front of `bytes`, returning the block
    /// and the number of bytes it consumed (`6 + data_length`).
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize), AacsError> {
        if bytes.len() < CCI_HEADER_LEN {
            return Err(AacsError::Truncated("CCI_and_other_info header"));
        }
        let info_type = u16::from_be_bytes([bytes[0], bytes[1]]);
        let version = u16::from_be_bytes([bytes[2], bytes[3]]);
        let data_length = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
        let total = CCI_HEADER_LEN + data_length;
        if bytes.len() < total {
            return Err(AacsError::Truncated("CCI_and_other_info data"));
        }
        Ok((
            CciAndOtherInfo {
                info_type,
                version,
                data: bytes[CCI_HEADER_LEN..total].to_vec(),
            },
            total,
        ))
    }

    /// Serialize the block (Table 3-18).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CCI_HEADER_LEN + self.data.len());
        out.extend_from_slice(&self.info_type.to_be_bytes());
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    /// Decode as a [`BasicCci`] if `info_type == 0x0101`.
    pub fn as_basic_cci(&self) -> Option<Result<BasicCci, AacsError>> {
        (self.info_type == CCI_TYPE_BASIC).then(|| BasicCci::parse_data(&self.data))
    }

    /// Decode as an [`EnhancedTitleUsage`] if `info_type == 0x0111`.
    pub fn as_enhanced_title_usage(&self) -> Option<Result<EnhancedTitleUsage, AacsError>> {
        (self.info_type == CCI_TYPE_ENHANCED_TITLE_USAGE)
            .then(|| EnhancedTitleUsage::parse_data(&self.data))
    }

    /// Decode as a [`KeyManagementOnline`] if `info_type == 0x0112`.
    pub fn as_key_management_online(&self) -> Option<Result<KeyManagementOnline, AacsError>> {
        (self.info_type == CCI_TYPE_KEY_MANAGEMENT_ONLINE)
            .then(|| KeyManagementOnline::parse_data(&self.data))
    }

    /// Decode as a [`ContentOwnerAuthorizedOutputs`] if
    /// `info_type == 0x0113`.
    pub fn as_content_owner_outputs(
        &self,
    ) -> Option<Result<ContentOwnerAuthorizedOutputs, AacsError>> {
        (self.info_type == CCI_TYPE_CONTENT_OWNER_OUTPUTS)
            .then(|| ContentOwnerAuthorizedOutputs::parse_data(&self.data))
    }
}

/// Copy Control Information field (Table 3-22).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cci {
    /// `00` — Copy Control Not Asserted.
    CopyControlNotAsserted,
    /// `01` — Reserved for "No More Copy".
    ReservedNoMoreCopy,
    /// `10` — Copy One Generation.
    CopyOneGeneration,
    /// `11` — Never Copy.
    NeverCopy,
}

impl Cci {
    fn from_bits(bits: u8) -> Self {
        match bits & 0x03 {
            0b00 => Cci::CopyControlNotAsserted,
            0b01 => Cci::ReservedNoMoreCopy,
            0b10 => Cci::CopyOneGeneration,
            _ => Cci::NeverCopy,
        }
    }
    fn to_bits(self) -> u8 {
        match self {
            Cci::CopyControlNotAsserted => 0b00,
            Cci::ReservedNoMoreCopy => 0b01,
            Cci::CopyOneGeneration => 0b10,
            Cci::NeverCopy => 0b11,
        }
    }
}

/// Whether a given Title requires on-line Permission (Table 3-26).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeOfTitle {
    /// `0` — Basic Title (no Permission required).
    Basic,
    /// `1` — Enhanced Title (requires Remote-Server Permission).
    Enhanced,
}

/// Basic CCI for AACS (Table 3-20) — `CCI_and_other_info_type = 0x0101`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicCci {
    /// `EPN` — Encryption Plus Non-assertion. Meaningful only when
    /// `cci == CopyControlNotAsserted` (Table 3-21): `false` =
    /// EPN-asserted, `true` = EPN-unasserted.
    pub epn_unasserted: bool,
    /// Copy control (Table 3-22).
    pub cci: Cci,
    /// `Image_Constraint_Token` (Table 3-23): `false` = constrained
    /// image, `true` = full High-Definition analog output.
    pub image_constraint_token: bool,
    /// `Digital_Only_Token` (Table 3-24): `false` = analog+digital
    /// output allowed, `true` = digital-only.
    pub digital_only_token: bool,
    /// `APSTB` — analog copy-protection type, low 3 bits (Table 3-25).
    pub apstb: u8,
    /// Per-Title Basic/Enhanced flags. `len()` equals `Num_of_Title`;
    /// entry `I` is `Type_of_Title#I`.
    pub title_types: Vec<TypeOfTitle>,
}

impl BasicCci {
    /// Parse the `data()` payload of a `0x0101` block (Table 3-20).
    pub fn parse_data(data: &[u8]) -> Result<Self, AacsError> {
        if data.len() != BASIC_CCI_DATA_LEN {
            return Err(AacsError::InvalidValue {
                what: "Basic CCI data_length",
                value: data.len() as u64,
            });
        }
        let epn_unasserted = (data[0] & 0x04) != 0;
        let cci = Cci::from_bits(data[0]);
        let image_constraint_token = (data[1] & 0x10) != 0;
        let digital_only_token = (data[1] & 0x08) != 0;
        let apstb = data[1] & 0x07;
        let num_of_title = u16::from_be_bytes([data[2], data[3]]) as usize;
        if num_of_title > BASIC_CCI_TITLE_BITMAP_BITS {
            return Err(AacsError::InvalidValue {
                what: "Basic CCI Num_of_Title",
                value: num_of_title as u64,
            });
        }
        let bitmap = &data[4..];
        let mut title_types = Vec::with_capacity(num_of_title);
        for i in 0..num_of_title {
            let byte = bitmap[i / 8];
            let bit = (byte >> (7 - (i % 8))) & 1;
            title_types.push(if bit == 1 {
                TypeOfTitle::Enhanced
            } else {
                TypeOfTitle::Basic
            });
        }
        Ok(BasicCci {
            epn_unasserted,
            cci,
            image_constraint_token,
            digital_only_token,
            apstb,
            title_types,
        })
    }

    /// Serialize as a full `CCI_and_other_info()` block.
    pub fn to_block(&self) -> CciAndOtherInfo {
        let mut data = vec![0u8; BASIC_CCI_DATA_LEN];
        data[0] = ((self.epn_unasserted as u8) << 2) | self.cci.to_bits();
        data[1] = ((self.image_constraint_token as u8) << 4)
            | ((self.digital_only_token as u8) << 3)
            | (self.apstb & 0x07);
        let num = self.title_types.len() as u16;
        data[2..4].copy_from_slice(&num.to_be_bytes());
        for (i, t) in self.title_types.iter().enumerate() {
            if *t == TypeOfTitle::Enhanced {
                data[4 + i / 8] |= 1 << (7 - (i % 8));
            }
        }
        CciAndOtherInfo {
            info_type: CCI_TYPE_BASIC,
            version: CCI_VERSION_0100,
            data,
        }
    }
}

/// A BCD `After()` / `Before()` date-time (Table 3-29).
///
/// All fields are stored as their decoded decimal values. The
/// specification represents each digit as a 4-bit BCD nibble; a value
/// where every field is zero means "undefined".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TitleDate {
    /// Four-digit year (e.g. `2026`).
    pub year: u16,
    /// Month `1..=12` (BCD).
    pub month: u8,
    /// Day of month `1..=31` (BCD).
    pub day: u8,
    /// Hour `0..=23` (BCD).
    pub hour: u8,
    /// Minute `0..=59` (BCD).
    pub minute: u8,
    /// `Timezone` byte — reserved (shall be 0, interpreted as UTC).
    pub timezone: u8,
}

impl TitleDate {
    /// `true` when every field is zero — the spec's "undefined" marker.
    pub fn is_undefined(&self) -> bool {
        *self == TitleDate::default()
    }

    fn parse(seven: &[u8]) -> Result<Self, AacsError> {
        // 7 bytes: YYYY (2 bytes BCD) MM (1) DD (1) hh (1) mm (1) TZ (1).
        let nib = |b: u8, hi: bool| -> u8 {
            if hi {
                b >> 4
            } else {
                b & 0x0F
            }
        };
        let bcd2 = |b: u8| -> u8 { nib(b, true) * 10 + nib(b, false) };
        let year = (nib(seven[0], true) as u16) * 1000
            + (nib(seven[0], false) as u16) * 100
            + (nib(seven[1], true) as u16) * 10
            + (nib(seven[1], false) as u16);
        Ok(TitleDate {
            year,
            month: bcd2(seven[2]),
            day: bcd2(seven[3]),
            hour: bcd2(seven[4]),
            minute: bcd2(seven[5]),
            timezone: seven[6],
        })
    }

    fn to_bytes(self) -> [u8; 7] {
        let bcd2 = |v: u8| -> u8 { ((v / 10) << 4) | (v % 10) };
        let y = self.year % 10000;
        [
            (((y / 1000) as u8) << 4) | (((y / 100) % 10) as u8),
            ((((y / 10) % 10) as u8) << 4) | ((y % 10) as u8),
            bcd2(self.month),
            bcd2(self.day),
            bcd2(self.hour),
            bcd2(self.minute),
            self.timezone,
        ]
    }
}

/// Whether an obtained Permission may be cached (Table 3-28).
///
/// The spec's encoding is inverted from intuition: bit value `0` means
/// the Permission **is** cacheable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cacheable {
    /// `0` — Cacheable Permission.
    Cacheable,
    /// `1` — Instant Permission (not cacheable).
    Instant,
}

/// Enhanced Title Usage for AACS (Table 3-27) —
/// `CCI_and_other_info_type = 0x0111`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnhancedTitleUsage {
    /// `Title_id` this usage record covers.
    pub title_id: u16,
    /// Whether the Permission may be cached (Table 3-28).
    pub cacheable: Cacheable,
    /// `Period` — integer hours a Cacheable Permission stays valid
    /// (`0` = undefined). Meaningful only for `Cacheable::Cacheable`.
    pub period: u16,
    /// `After()` — playback allowed only on/after this date; `None`
    /// when the field is all-zero (undefined).
    pub after: Option<TitleDate>,
    /// `Before()` — playback allowed only on/before this date; `None`
    /// when the field is all-zero (undefined).
    pub before: Option<TitleDate>,
}

impl EnhancedTitleUsage {
    /// Parse the `data()` payload of a `0x0111` block (Table 3-27).
    pub fn parse_data(data: &[u8]) -> Result<Self, AacsError> {
        if data.len() != ENHANCED_TITLE_USAGE_DATA_LEN {
            return Err(AacsError::InvalidValue {
                what: "Enhanced Title Usage data_length",
                value: data.len() as u64,
            });
        }
        let title_id = u16::from_be_bytes([data[0], data[1]]);
        let cacheable = if (data[2] & 0x01) == 0 {
            Cacheable::Cacheable
        } else {
            Cacheable::Instant
        };
        let period = u16::from_be_bytes([data[3], data[4]]);
        let after = TitleDate::parse(&data[5..12])?;
        let before = TitleDate::parse(&data[12..19])?;
        Ok(EnhancedTitleUsage {
            title_id,
            cacheable,
            period,
            after: (!after.is_undefined()).then_some(after),
            before: (!before.is_undefined()).then_some(before),
        })
    }

    /// Serialize as a full `CCI_and_other_info()` block.
    pub fn to_block(&self) -> CciAndOtherInfo {
        let mut data = vec![0u8; ENHANCED_TITLE_USAGE_DATA_LEN];
        data[0..2].copy_from_slice(&self.title_id.to_be_bytes());
        data[2] = match self.cacheable {
            Cacheable::Cacheable => 0,
            Cacheable::Instant => 1,
        };
        data[3..5].copy_from_slice(&self.period.to_be_bytes());
        data[5..12].copy_from_slice(&self.after.unwrap_or_default().to_bytes());
        data[12..19].copy_from_slice(&self.before.unwrap_or_default().to_bytes());
        CciAndOtherInfo {
            info_type: CCI_TYPE_ENHANCED_TITLE_USAGE,
            version: CCI_VERSION_0100,
            data,
        }
    }
}

/// On-line Binding Type (Table 3-32).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingType {
    /// `0x01` — Media Binding.
    Media,
    /// `0x02` — Content Binding.
    Content,
    /// `0x03` — Device/Content Binding.
    DeviceContent,
    /// `0x04` — Device/Media Binding.
    DeviceMedia,
    /// `0x00` or `>= 0x05` — Reserved. Carries the raw byte.
    Reserved(u8),
}

impl BindingType {
    fn from_u8(v: u8) -> Self {
        match v {
            0x01 => BindingType::Media,
            0x02 => BindingType::Content,
            0x03 => BindingType::DeviceContent,
            0x04 => BindingType::DeviceMedia,
            other => BindingType::Reserved(other),
        }
    }
    fn to_u8(self) -> u8 {
        match self {
            BindingType::Media => 0x01,
            BindingType::Content => 0x02,
            BindingType::DeviceContent => 0x03,
            BindingType::DeviceMedia => 0x04,
            BindingType::Reserved(v) => v,
        }
    }
}

/// Key Management Information for On-line Function (Table 3-30) —
/// `CCI_and_other_info_type = 0x0112`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyManagementOnline {
    /// `Unit Key Status` (Table 3-31): `0x01` = Unit Key on media,
    /// `0x02` = not on media (network transaction needed).
    pub unit_key_status: u8,
    /// `Binding Type` applied to downloaded Content (Table 3-32).
    pub binding_type: BindingType,
}

impl KeyManagementOnline {
    /// Parse the `data()` payload of a `0x0112` block (Table 3-30).
    pub fn parse_data(data: &[u8]) -> Result<Self, AacsError> {
        if data.len() != KEY_MANAGEMENT_ONLINE_DATA_LEN {
            return Err(AacsError::InvalidValue {
                what: "Key Management Online data_length",
                value: data.len() as u64,
            });
        }
        Ok(KeyManagementOnline {
            unit_key_status: data[0],
            binding_type: BindingType::from_u8(data[1]),
        })
    }

    /// Serialize as a full `CCI_and_other_info()` block.
    pub fn to_block(&self) -> CciAndOtherInfo {
        let mut data = vec![0u8; KEY_MANAGEMENT_ONLINE_DATA_LEN];
        data[0] = self.unit_key_status;
        data[1] = self.binding_type.to_u8();
        CciAndOtherInfo {
            info_type: CCI_TYPE_KEY_MANAGEMENT_ONLINE,
            version: CCI_VERSION_0100,
            data,
        }
    }
}

/// Content Owner Authorized Outputs Information (Table 3-33) —
/// `CCI_and_other_info_type = 0x0113`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentOwnerAuthorizedOutputs {
    /// 128-bit `Output Control Bits` blob (16 bytes).
    pub output_control_bits: [u8; 16],
}

impl ContentOwnerAuthorizedOutputs {
    /// Parse the `data()` payload of a `0x0113` block (Table 3-33).
    pub fn parse_data(data: &[u8]) -> Result<Self, AacsError> {
        if data.len() != CONTENT_OWNER_OUTPUTS_DATA_LEN {
            return Err(AacsError::InvalidValue {
                what: "Content Owner Outputs data_length",
                value: data.len() as u64,
            });
        }
        let mut output_control_bits = [0u8; 16];
        output_control_bits.copy_from_slice(&data[..16]);
        Ok(ContentOwnerAuthorizedOutputs {
            output_control_bits,
        })
    }

    /// Serialize as a full `CCI_and_other_info()` block.
    pub fn to_block(&self) -> CciAndOtherInfo {
        CciAndOtherInfo {
            info_type: CCI_TYPE_CONTENT_OWNER_OUTPUTS,
            version: CCI_VERSION_0100,
            data: self.output_control_bits.to_vec(),
        }
    }
}

/// Size of one CCI-Area header (Primary or Secondary): a `u16` loop
/// count plus 14 reserved bytes (Table 3-17).
pub const CCI_AREA_HEADER_LEN: usize = 16;
/// Size of the Primary CCI Area's block region (Table 3-17): the
/// Primary Header + Primary CCI Area together fill 2048 bytes.
pub const PRIMARY_CCI_AREA_LEN: usize = 2032;

/// The CPS Unit Usage File (Table 3-17).
///
/// The on-disc file is at least 2048 bytes: a 16-byte Primary Header
/// followed by the 2032-byte Primary CCI Area. If a Secondary CCI Area
/// is present it follows as a 16-byte Secondary Header plus a
/// `2048·N − 16`-byte block region. Trailing reserved padding in each
/// area is ignored on parse and re-emitted as zeros.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CpsUnitUsageFile {
    /// `CCI_and_other_info()` blocks of the Primary CCI Area.
    pub primary: Vec<CciAndOtherInfo>,
    /// `CCI_and_other_info()` blocks of the Secondary CCI Area (empty
    /// when the file has no Secondary Area).
    pub secondary: Vec<CciAndOtherInfo>,
    /// Whether a Secondary CCI Area was present on parse (distinguishes
    /// "present but empty" from "absent").
    pub has_secondary: bool,
}

impl CpsUnitUsageFile {
    /// Parse a CPS Unit Usage File (Table 3-17).
    pub fn parse(bytes: &[u8]) -> Result<Self, AacsError> {
        if bytes.len() < CCI_AREA_HEADER_LEN + PRIMARY_CCI_AREA_LEN {
            return Err(AacsError::Truncated("CPS Unit Usage File Primary Area"));
        }
        let primary_loops = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        let primary_area = &bytes[CCI_AREA_HEADER_LEN..CCI_AREA_HEADER_LEN + PRIMARY_CCI_AREA_LEN];
        let primary = parse_area(primary_area, primary_loops, "Primary")?;

        let mut secondary = Vec::new();
        let mut has_secondary = false;
        let secondary_start = CCI_AREA_HEADER_LEN + PRIMARY_CCI_AREA_LEN;
        if bytes.len() > secondary_start {
            has_secondary = true;
            if bytes.len() < secondary_start + CCI_AREA_HEADER_LEN {
                return Err(AacsError::Truncated("CPS Unit Usage File Secondary Header"));
            }
            let secondary_loops =
                u16::from_be_bytes([bytes[secondary_start], bytes[secondary_start + 1]]) as usize;
            let secondary_area = &bytes[secondary_start + CCI_AREA_HEADER_LEN..];
            secondary = parse_area(secondary_area, secondary_loops, "Secondary")?;
        }

        Ok(CpsUnitUsageFile {
            primary,
            secondary,
            has_secondary,
        })
    }

    /// Serialize the file, filling each area with trailing zero padding
    /// to its fixed size (the Secondary Area is padded to the next
    /// 2048-byte boundary).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CCI_AREA_HEADER_LEN + PRIMARY_CCI_AREA_LEN);
        out.extend_from_slice(&(self.primary.len() as u16).to_be_bytes());
        out.extend_from_slice(&[0u8; CCI_AREA_HEADER_LEN - 2]);
        let mut primary_bytes = Vec::new();
        for b in &self.primary {
            primary_bytes.extend_from_slice(&b.to_bytes());
        }
        primary_bytes.resize(PRIMARY_CCI_AREA_LEN, 0);
        out.extend_from_slice(&primary_bytes);

        if self.has_secondary {
            out.extend_from_slice(&(self.secondary.len() as u16).to_be_bytes());
            out.extend_from_slice(&[0u8; CCI_AREA_HEADER_LEN - 2]);
            let mut secondary_bytes = Vec::new();
            for b in &self.secondary {
                secondary_bytes.extend_from_slice(&b.to_bytes());
            }
            // Pad the Secondary Area to fill `2048·N − 16` bytes.
            let area_min = 2048 - CCI_AREA_HEADER_LEN;
            let target = secondary_bytes.len().max(area_min);
            let target = target.div_ceil(area_min) * area_min;
            secondary_bytes.resize(target, 0);
            out.extend_from_slice(&secondary_bytes);
        }
        out
    }
}

/// Parse exactly `loops` `CCI_and_other_info()` blocks from an area
/// buffer, stopping on trailing zero padding.
fn parse_area(
    area: &[u8],
    loops: usize,
    which: &'static str,
) -> Result<Vec<CciAndOtherInfo>, AacsError> {
    let _ = which;
    let mut out = Vec::with_capacity(loops);
    let mut cursor = 0usize;
    for _ in 0..loops {
        if cursor + CCI_HEADER_LEN > area.len() {
            return Err(AacsError::Truncated("CPS Unit Usage File CCI loop"));
        }
        let (block, consumed) = CciAndOtherInfo::parse(&area[cursor..])?;
        cursor += consumed;
        out.push(block);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_cci_roundtrip() {
        let b = BasicCci {
            epn_unasserted: true,
            cci: Cci::CopyOneGeneration,
            image_constraint_token: true,
            digital_only_token: false,
            apstb: 0b110,
            title_types: vec![
                TypeOfTitle::Basic,
                TypeOfTitle::Enhanced,
                TypeOfTitle::Enhanced,
                TypeOfTitle::Basic,
            ],
        };
        let block = b.to_block();
        assert_eq!(block.info_type, CCI_TYPE_BASIC);
        assert_eq!(block.data.len(), BASIC_CCI_DATA_LEN);
        let round = block.as_basic_cci().unwrap().unwrap();
        assert_eq!(round, b);
        // Byte-level: EPN bit, CCI bits, ICT/APSTB.
        assert_eq!(block.data[0] & 0x04, 0x04);
        assert_eq!(block.data[0] & 0x03, 0b10);
        assert_eq!(block.data[1] & 0x10, 0x10);
        assert_eq!(block.data[1] & 0x07, 0b110);
    }

    #[test]
    fn basic_cci_title_bitmap_msb_first() {
        let mut tt = vec![TypeOfTitle::Basic; 10];
        tt[0] = TypeOfTitle::Enhanced; // bit 7 of byte 0
        tt[8] = TypeOfTitle::Enhanced; // bit 7 of byte 1
        let b = BasicCci {
            epn_unasserted: false,
            cci: Cci::NeverCopy,
            image_constraint_token: false,
            digital_only_token: true,
            apstb: 0,
            title_types: tt,
        };
        let block = b.to_block();
        assert_eq!(block.data[4], 0x80);
        assert_eq!(block.data[5], 0x80);
        assert_eq!(block.as_basic_cci().unwrap().unwrap(), b);
    }

    #[test]
    fn enhanced_title_usage_roundtrip_with_dates() {
        let e = EnhancedTitleUsage {
            title_id: 0x1234,
            cacheable: Cacheable::Cacheable,
            period: 72,
            after: Some(TitleDate {
                year: 2026,
                month: 7,
                day: 9,
                hour: 13,
                minute: 45,
                timezone: 0,
            }),
            before: Some(TitleDate {
                year: 2030,
                month: 12,
                day: 31,
                hour: 23,
                minute: 59,
                timezone: 0,
            }),
        };
        let block = e.to_block();
        assert_eq!(block.data.len(), ENHANCED_TITLE_USAGE_DATA_LEN);
        // BCD encoding check for the "after" year 2026.
        assert_eq!(&block.data[5..7], &[0x20, 0x26]);
        assert_eq!(block.as_enhanced_title_usage().unwrap().unwrap(), e);
    }

    #[test]
    fn enhanced_title_usage_undefined_dates() {
        let e = EnhancedTitleUsage {
            title_id: 1,
            cacheable: Cacheable::Instant,
            period: 0,
            after: None,
            before: None,
        };
        let block = e.to_block();
        let round = block.as_enhanced_title_usage().unwrap().unwrap();
        assert_eq!(round, e);
        assert!(round.after.is_none() && round.before.is_none());
    }

    #[test]
    fn key_management_and_outputs_roundtrip() {
        let k = KeyManagementOnline {
            unit_key_status: 0x02,
            binding_type: BindingType::DeviceMedia,
        };
        let kb = k.to_block();
        assert_eq!(kb.as_key_management_online().unwrap().unwrap(), k);

        let o = ContentOwnerAuthorizedOutputs {
            output_control_bits: [0xA5; 16],
        };
        let ob = o.to_block();
        assert_eq!(ob.as_content_owner_outputs().unwrap().unwrap(), o);
    }

    #[test]
    fn cps_unit_usage_file_roundtrip_primary_only() {
        let file = CpsUnitUsageFile {
            primary: vec![
                BasicCci {
                    epn_unasserted: false,
                    cci: Cci::CopyControlNotAsserted,
                    image_constraint_token: false,
                    digital_only_token: false,
                    apstb: 0,
                    title_types: vec![TypeOfTitle::Enhanced],
                }
                .to_block(),
                EnhancedTitleUsage {
                    title_id: 1,
                    cacheable: Cacheable::Instant,
                    period: 0,
                    after: None,
                    before: None,
                }
                .to_block(),
            ],
            secondary: Vec::new(),
            has_secondary: false,
        };
        let bytes = file.to_bytes();
        assert_eq!(bytes.len(), CCI_AREA_HEADER_LEN + PRIMARY_CCI_AREA_LEN);
        let round = CpsUnitUsageFile::parse(&bytes).unwrap();
        assert_eq!(round, file);
    }

    #[test]
    fn cps_unit_usage_file_roundtrip_with_secondary() {
        let big_block = CciAndOtherInfo {
            info_type: CCI_TYPE_CONTENT_OWNER_OUTPUTS,
            version: CCI_VERSION_0100,
            data: vec![0x11; CONTENT_OWNER_OUTPUTS_DATA_LEN],
        };
        let file = CpsUnitUsageFile {
            primary: vec![KeyManagementOnline {
                unit_key_status: 1,
                binding_type: BindingType::Content,
            }
            .to_block()],
            secondary: vec![big_block],
            has_secondary: true,
        };
        let bytes = file.to_bytes();
        // Primary area (2048) + a full Secondary area (2048).
        assert_eq!(bytes.len() % 2048, 0);
        let round = CpsUnitUsageFile::parse(&bytes).unwrap();
        assert_eq!(round, file);
    }

    #[test]
    fn wrong_data_length_rejected() {
        assert!(BasicCci::parse_data(&[0u8; 10]).is_err());
        assert!(EnhancedTitleUsage::parse_data(&[0u8; 10]).is_err());
        assert!(KeyManagementOnline::parse_data(&[0u8; 4]).is_err());
        assert!(ContentOwnerAuthorizedOutputs::parse_data(&[0u8; 4]).is_err());
    }

    #[test]
    fn truncated_and_short_files_rejected() {
        assert!(CpsUnitUsageFile::parse(&[]).is_err());
        assert!(CpsUnitUsageFile::parse(&[0u8; 100]).is_err());
        assert!(CciAndOtherInfo::parse(&[0u8; 3]).is_err());
        // header claims 0x20 data but buffer too short
        let mut hdr = vec![0x01, 0x11, 0x01, 0x00, 0x00, 0x20];
        hdr.extend_from_slice(&[0u8; 4]);
        assert!(CciAndOtherInfo::parse(&hdr).is_err());
    }
}
