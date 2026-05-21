//! KEYDB.cfg parser — the de-facto community AACS key-material database
//! file used by libaacs / libbluray / makemkv and similar tools.
//!
//! Two on-disk shapes are accepted:
//!
//! 1. **Per-disc legacy form** (`<DISC_ID>=V <VUK> | label`), the
//!    original libbluray syntax. See [`KeyDbEntry`].
//! 2. **`|`-leader record form** introduced in libaacs and documented
//!    in `docs/container/aacs/keydb-cfg-format.md`. Lines of the form
//!
//!    ```text
//!    | <TYPE> | <FIELDS...> ; <comment>
//!    ```
//!
//!    where `<TYPE>` is one of `DK`, `PK`, `HC`, `DC`, `VID`, `VUK`,
//!    `MEK`, `TK`, `KCD`, `DISCID`. See the format-doc for the full
//!    syntax of each record type.
//!
//! `;` introduces a comment to end-of-line. Empty lines are ignored.
//!
//! The implementation here was written *from the format-doc + the AACS
//! LA Common Final 0.953 PDF* alone. No libaacs / aacskeys / libbluray
//! / makemkv source was consulted.

use crate::error::AacsError;
use crate::vuk::Vuk;
use std::collections::BTreeMap;
use std::path::Path;

/// One parsed legacy `<DISC_ID>=V <VUK>` KEYDB.cfg entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDbEntry {
    /// 20-byte (40-hex) BD-ROM disc ID.
    pub disc_id: [u8; 20],
    /// 16-byte Volume Unique Key.
    pub vuk: Vuk,
    /// Optional free-form label.
    pub label: Option<String>,
    /// Optional pre-unwrapped CPS Unit Title Keys, indexed by CPS
    /// Unit number (1-based). Present when the source KEYDB.cfg
    /// line was in the extended libbluray/aacskeys format with
    /// `U | 1-0x<key> | 2-0x<key> | ...` tokens — lets the consumer
    /// skip the VUK→title-key AES-ECB unwrap step entirely.
    pub unit_keys: Vec<(u16, [u8; 16])>,
}

/// A `| DK |` Device Key record per AACS Common Final 0.953 §3.2.1
/// (Subset-Difference tree) and the format doc's "DK" section.
///
/// Each Device Key issued by AACS LA to a player carries the
/// `(device_key, device_node, key_uv, key_u_mask_shift)` tuple that
/// pins the key into one node of the Subset-Difference tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceKeyRecord {
    /// 16-byte AES-128 Device Key.
    pub device_key: [u8; 16],
    /// 2-byte node index in the Subset-Difference tree.
    pub device_node: [u8; 2],
    /// 4-byte UV value identifying the `(u, v)` coordinate.
    pub key_uv: [u8; 4],
    /// 1-byte `u`-mask bit-shift count.
    pub key_u_mask_shift: u8,
    /// Trailing free-form comment (typically the MKB version range
    /// the key is valid for).
    pub comment: Option<String>,
}

/// A `| PK |` Processing Key record. 16-byte AES-128 value, the output
/// of running the Subset-Difference walk against a particular MKB, plus
/// the trailing free-form comment that typically records the MKB
/// version range the key applies to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessingKey {
    /// 16-byte AES-128 Processing Key.
    pub processing_key: [u8; 16],
    /// Trailing free-form comment.
    pub comment: Option<String>,
}

/// A `| HC |` Host Certificate + private key record per AACS Common
/// Final 0.953 §A.1 / §A.3 and the format doc's "HC" section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCertRecord {
    /// 20-byte ECDSA-secp160r1 private-key scalar.
    pub host_priv_key: [u8; 20],
    /// Variable-length host certificate. The standard layout is 92
    /// bytes (= 0x005C); the parser keeps the raw bytes verbatim and
    /// only validates that the embedded length field (offset 2,
    /// big-endian u16) matches the buffer length.
    pub host_cert: Vec<u8>,
    /// Trailing free-form comment.
    pub comment: Option<String>,
}

impl HostCertRecord {
    /// Host ID — bytes 8..14 of the certificate (Common Final 0.953
    /// §A.1 host certificate layout). Returns `None` if the buffer
    /// is shorter than 14 bytes.
    pub fn host_id(&self) -> Option<[u8; 6]> {
        if self.host_cert.len() < 14 {
            return None;
        }
        let mut out = [0u8; 6];
        out.copy_from_slice(&self.host_cert[8..14]);
        Some(out)
    }

    /// Certificate type byte — should be `0x02` for a host cert.
    pub fn cert_type(&self) -> Option<u8> {
        self.host_cert.first().copied()
    }

    /// Total certificate length encoded in the cert header at offset
    /// 2..4 (big-endian).
    pub fn declared_length(&self) -> Option<u16> {
        if self.host_cert.len() < 4 {
            return None;
        }
        Some(u16::from_be_bytes([self.host_cert[2], self.host_cert[3]]))
    }
}

/// A `| DC |` Drive Certificate + private key record (drive side of
/// the BD-AACS Drive-Host authentication).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveCertRecord {
    /// 20-byte ECDSA-secp160r1 private-key scalar.
    pub drive_priv_key: [u8; 20],
    /// Variable-length drive certificate, raw bytes.
    pub drive_cert: Vec<u8>,
    /// Trailing free-form comment.
    pub comment: Option<String>,
}

/// A per-disc record set scoped under a `| DISCID |` row. Holds any
/// VID / VUK / MEK / TK / KCD rows that follow until the next
/// `DISCID` row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiscRecords {
    /// 20-byte disc identifier (from the `| DISCID |` row).
    pub disc_id: [u8; 20],
    /// 16-byte Volume ID — `| VID |`.
    pub vid: Option<[u8; 16]>,
    /// 16-byte Volume Unique Key — `| VUK |`.
    pub vuk: Option<Vuk>,
    /// 16-byte Media Encryption Key — `| MEK |`.
    pub mek: Option<[u8; 16]>,
    /// Title Keys — `| TK |`. Multiple rows are accumulated.
    pub title_keys: Vec<[u8; 16]>,
    /// Key Conversion Data — `| KCD |`. Raw bytes (variable length).
    pub kcd: Option<Vec<u8>>,
    /// Free-form label / comments associated with the `DISCID` row.
    pub label: Option<String>,
}

/// In-memory KEYDB.cfg database.
///
/// Holds the legacy per-disc `<DISC_ID>=V <VUK>` entries plus the
/// extended `|`-leader header records (DK / PK / HC / DC / per-disc
/// VID/VUK/MEK/TK/KCD groups). Use the accessors to read each
/// collection back.
#[derive(Debug, Default, Clone)]
pub struct KeyDb {
    by_disc_id: BTreeMap<[u8; 20], KeyDbEntry>,
    device_keys: Vec<DeviceKeyRecord>,
    processing_keys: Vec<ProcessingKey>,
    host_certs: Vec<HostCertRecord>,
    drive_certs: Vec<DriveCertRecord>,
    disc_records: BTreeMap<[u8; 20], DiscRecords>,
}

impl KeyDb {
    /// Parse a KEYDB.cfg byte stream from a `&str`.
    ///
    /// Real-world KEYDB.cfg files mix many ad-hoc line forms — banner
    /// comments, Processing Key records, custom header lines from
    /// AnyDVD/MakeMKV exports, etc. The parser dispatches on the
    /// first non-whitespace character:
    ///
    /// - `|` → `|`-leader record (DK / PK / HC / DC / VID / VUK / MEK
    ///   / TK / KCD / DISCID), parsed per
    ///   `docs/container/aacs/keydb-cfg-format.md`.
    /// - hex → legacy per-disc `<DISC_ID>=V <VUK> | label` line.
    /// - anything else → skip with diagnostic.
    ///
    /// Lines we can't parse are skipped rather than failing the whole
    /// load. Set `OXIDEAV_AACS_DEBUG=1` to surface each skip on
    /// stderr.
    pub fn parse(text: &str) -> Result<Self, AacsError> {
        let debug = std::env::var_os("OXIDEAV_AACS_DEBUG").is_some();
        let mut out = Self::default();
        let mut skipped = 0usize;
        // `| DISCID |` sets the current disc-scope; subsequent VID /
        // VUK / MEK / TK / KCD rows are attributed to it.
        let mut current_discid: Option<[u8; 20]> = None;
        for raw in text.lines() {
            // Split body / trailing-comment on the first `;`.
            let (body, comment) = match raw.find(';') {
                Some(i) => (&raw[..i], Some(raw[i + 1..].trim().to_string())),
                None => (raw, None),
            };
            let body = body.trim();
            if body.is_empty() {
                continue;
            }
            let comment_owned = comment.filter(|s| !s.is_empty());
            // Dispatch on first non-whitespace char.
            let res = if body.starts_with('|') {
                parse_pipe_record(
                    body,
                    comment_owned.as_deref(),
                    &mut out,
                    &mut current_discid,
                )
            } else {
                parse_legacy_line(body).map(|entry| {
                    out.by_disc_id.insert(entry.disc_id, entry);
                })
            };
            if let Err(e) = res {
                skipped += 1;
                if debug {
                    eprintln!("oxideav-aacs: KEYDB.cfg skipped line — {e}");
                }
            }
        }
        if debug {
            eprintln!(
                "oxideav-aacs: KEYDB.cfg parse — kept {} per-disc + {} DK + {} PK + {} HC + {} DC + {} DISCID-scoped, skipped {} unparseable lines",
                out.by_disc_id.len(),
                out.device_keys.len(),
                out.processing_keys.len(),
                out.host_certs.len(),
                out.drive_certs.len(),
                out.disc_records.len(),
                skipped
            );
        }
        Ok(out)
    }

    /// Load KEYDB.cfg from a filesystem path.
    pub fn load_from(path: impl AsRef<Path>) -> Result<Self, AacsError> {
        let text = std::fs::read_to_string(path.as_ref())?;
        Self::parse(&text)
    }

    /// Load KEYDB.cfg from the default per-platform search path.
    ///
    /// Search order:
    /// 1. `$OXIDEAV_AACS_KEYDB` if set.
    /// 2. macOS only: `$HOME/Library/Preferences/aacs/KEYDB.cfg` —
    ///    the native macOS user-defaults location libbluray + similar
    ///    tools use on Apple platforms.
    /// 3. `$XDG_CONFIG_HOME/aacs/KEYDB.cfg`.
    /// 4. Each entry in `$XDG_CONFIG_DIRS` (`:`-split) +
    ///    `aacs/KEYDB.cfg`.
    /// 5. `$HOME/.config/aacs/KEYDB.cfg`.
    ///
    /// Returns `Err(MissingDiscFile)` if no candidate exists.
    pub fn load_default() -> Result<Self, AacsError> {
        for path in default_search_paths() {
            if path.exists() {
                return Self::load_from(path);
            }
        }
        Err(AacsError::MissingDiscFile("KEYDB.cfg"))
    }

    /// Look up a VUK by disc ID. Returns `None` if no entry matches.
    ///
    /// Checks the legacy `<DISC_ID>=V<VUK>` map first, then falls back
    /// to any `| DISCID |` / `| VUK |` scoped record set carrying the
    /// same disc ID.
    pub fn vuk_for_disc(&self, disc_id: &[u8; 20]) -> Option<Vuk> {
        if let Some(e) = self.by_disc_id.get(disc_id) {
            return Some(e.vuk);
        }
        self.disc_records.get(disc_id).and_then(|r| r.vuk)
    }

    /// Look up the full parsed entry by disc ID.
    pub fn entry_for_disc(&self, disc_id: &[u8; 20]) -> Option<&KeyDbEntry> {
        self.by_disc_id.get(disc_id)
    }

    /// Iterate legacy `<DISC_ID>=V<VUK>` entries.
    pub fn entries(&self) -> impl Iterator<Item = &KeyDbEntry> {
        self.by_disc_id.values()
    }

    /// All parsed `| DK |` Device Key rows.
    pub fn device_keys(&self) -> &[DeviceKeyRecord] {
        &self.device_keys
    }

    /// All parsed `| PK |` Processing Key rows.
    pub fn processing_keys(&self) -> &[ProcessingKey] {
        &self.processing_keys
    }

    /// All parsed `| HC |` Host Certificate rows.
    pub fn host_certs(&self) -> &[HostCertRecord] {
        &self.host_certs
    }

    /// All parsed `| DC |` Drive Certificate rows.
    pub fn drive_certs(&self) -> &[DriveCertRecord] {
        &self.drive_certs
    }

    /// All `| DISCID |`-scoped record sets (VID / VUK / MEK / TK /
    /// KCD), keyed by disc ID.
    pub fn disc_records(&self) -> &BTreeMap<[u8; 20], DiscRecords> {
        &self.disc_records
    }

    /// Look up a `| DISCID |`-scoped record set for the given disc.
    pub fn disc_record(&self, disc_id: &[u8; 20]) -> Option<&DiscRecords> {
        self.disc_records.get(disc_id)
    }

    /// Number of legacy entries (back-compat helper; new code should
    /// usually use the more specific accessors).
    pub fn len(&self) -> usize {
        self.by_disc_id.len()
    }

    /// Whether the database is empty (legacy entries only).
    pub fn is_empty(&self) -> bool {
        self.by_disc_id.is_empty()
            && self.device_keys.is_empty()
            && self.processing_keys.is_empty()
            && self.host_certs.is_empty()
            && self.drive_certs.is_empty()
            && self.disc_records.is_empty()
    }
}

fn default_search_paths() -> Vec<std::path::PathBuf> {
    use std::path::PathBuf;
    let mut out = Vec::new();
    if let Ok(p) = std::env::var("OXIDEAV_AACS_KEYDB") {
        if !p.is_empty() {
            out.push(PathBuf::from(p));
        }
    }
    #[cfg(target_os = "macos")]
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            out.push(
                PathBuf::from(&home)
                    .join("Library")
                    .join("Preferences")
                    .join("aacs")
                    .join("KEYDB.cfg"),
            );
        }
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            out.push(PathBuf::from(xdg).join("aacs").join("KEYDB.cfg"));
        }
    }
    if let Ok(dirs) = std::env::var("XDG_CONFIG_DIRS") {
        for d in dirs.split(':') {
            if !d.is_empty() {
                out.push(PathBuf::from(d).join("aacs").join("KEYDB.cfg"));
            }
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            out.push(
                PathBuf::from(home)
                    .join(".config")
                    .join("aacs")
                    .join("KEYDB.cfg"),
            );
        }
    }
    out
}

// ---- legacy `<DISC_ID>=V<VUK>` parser -----------------------------------

/// Parse one legacy `<DISC_ID>=V<VUK>` (or extended libbluray-form)
/// line. Returns `KeyDbParseError` on failure.
fn parse_legacy_line(line: &str) -> Result<KeyDbEntry, AacsError> {
    let (disc_id_text, rhs) = match line.split_once('=') {
        Some(parts) => parts,
        None => return Err(make_legacy_err(line)),
    };
    let disc_id_text = strip_hex_prefix(disc_id_text.trim());
    let disc_id = parse_hex_array_20_legacy(disc_id_text)?;

    let pipe_tokens: Vec<&str> = rhs.split('|').map(str::trim).collect();
    let mut vuk_bytes: Option<[u8; 16]> = None;
    let mut unit_keys: Vec<(u16, [u8; 16])> = Vec::new();
    let mut label_parts: Vec<String> = Vec::new();
    let mut current_flag: Option<char> = None;
    for ptok in pipe_tokens {
        if ptok.is_empty() {
            continue;
        }
        fn is_flag_word(s: &str) -> bool {
            s.len() == 1
                && matches!(
                    s.as_bytes()[0],
                    b'D' | b'M' | b'I' | b'V' | b'U' | b'd' | b'm' | b'i' | b'v' | b'u'
                )
        }
        let (head, value): (&str, &str) = if let Some(idx) = ptok.find(char::is_whitespace) {
            let candidate = &ptok[..idx];
            if is_flag_word(candidate) {
                (candidate, ptok[idx..].trim())
            } else {
                ("", ptok)
            }
        } else if is_flag_word(ptok) {
            (ptok, "")
        } else {
            ("", ptok)
        };
        if !head.is_empty() {
            current_flag = head.chars().next().map(|c| c.to_ascii_uppercase());
        }
        if value.is_empty() {
            continue;
        }
        match current_flag {
            Some('V') => {
                let raw = strip_hex_prefix(value);
                if raw.len() == 32 {
                    vuk_bytes = Some(parse_hex_array_16_legacy(raw)?);
                }
                current_flag = None;
            }
            Some('U') => {
                if let Some((id_str, key_str)) = value.split_once('-') {
                    let key_str = strip_hex_prefix(key_str.trim());
                    if let (Ok(id), Ok(key)) = (
                        id_str.trim().parse::<u16>(),
                        parse_hex_array_16_legacy(key_str),
                    ) {
                        unit_keys.push((id, key));
                    }
                }
            }
            Some(_) => {
                current_flag = None;
            }
            None => {
                label_parts.push(value.to_string());
            }
        }
    }

    let vuk_bytes = vuk_bytes.ok_or_else(|| make_legacy_err(line))?;
    let label = if label_parts.is_empty() {
        None
    } else {
        Some(label_parts.join(" | "))
    };

    Ok(KeyDbEntry {
        disc_id,
        vuk: Vuk::from_bytes(vuk_bytes),
        label,
        unit_keys,
    })
}

// ---- `|`-leader record parser -------------------------------------------

/// Tokenise a `|`-leader record line into its non-empty `|`-segments.
///
/// A well-formed line per the format-doc starts and ends with `|`, so
/// splitting on `|` yields a leading and trailing empty string we
/// discard. Anything else is returned as a trimmed slice.
fn pipe_tokenize(body: &str) -> Vec<&str> {
    body.split('|').map(str::trim).collect()
}

/// Split a `|`-segment into `(NAME, VALUE)` per the format-doc §
/// "Lexical syntax": `NAME 0xHEXVALUE` if a space exists and the part
/// before it is non-empty + non-hex, else `("", VALUE)` for positional.
fn split_named(field: &str) -> (&str, &str) {
    if let Some(idx) = field.find(char::is_whitespace) {
        let head = field[..idx].trim();
        let rest = field[idx..].trim();
        // Heuristic: if the head starts with `0x`, treat the whole
        // thing as a positional value (defensive — names never start
        // with `0x`).
        if head.starts_with("0x") || head.starts_with("0X") {
            ("", field.trim())
        } else {
            (head, rest)
        }
    } else {
        ("", field.trim())
    }
}

/// Parse a hex literal of exactly `expected_len` characters into an
/// owned `Vec<u8>` of `expected_len / 2` bytes. The literal MUST be
/// `0x`-prefixed per the format-doc.
fn parse_hex_fixed(value: &str, expected_len: usize, field_name: &str) -> Result<Vec<u8>, String> {
    let v = value.trim();
    let stripped = v
        .strip_prefix("0x")
        .or_else(|| v.strip_prefix("0X"))
        .ok_or_else(|| format!("{field_name}: missing 0x prefix"))?;
    if stripped.len() != expected_len {
        return Err(format!(
            "{field_name}: expected {expected_len} hex chars, got {}",
            stripped.len()
        ));
    }
    parse_hex_bytes(stripped).ok_or_else(|| format!("{field_name}: non-hex character"))
}

/// Parse a `0x…` hex literal of *any* even length into an owned
/// `Vec<u8>`. Used for variable-length fields (`HOST_CERT`,
/// `DRIVE_CERT`, `KCD`).
fn parse_hex_var(value: &str, field_name: &str) -> Result<Vec<u8>, String> {
    let v = value.trim();
    let stripped = v
        .strip_prefix("0x")
        .or_else(|| v.strip_prefix("0X"))
        .ok_or_else(|| format!("{field_name}: missing 0x prefix"))?;
    if stripped.is_empty() || stripped.len() % 2 != 0 {
        return Err(format!(
            "{field_name}: hex length must be a positive even number, got {}",
            stripped.len()
        ));
    }
    parse_hex_bytes(stripped).ok_or_else(|| format!("{field_name}: non-hex character"))
}

fn parse_hex_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let b = hex.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = hex_digit(b[i])?;
        let lo = hex_digit(b[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Look up a named field in a `|`-tokenised record. Per the format-doc
/// the parser accepts both `NAME 0xVALUE` (named) and bare `0xVALUE`
/// (positional). Named fields may appear in any order. This helper
/// returns the value associated with `name` (case-insensitive) if
/// present.
fn find_named<'a>(tokens: &'a [&'a str], name: &str) -> Option<&'a str> {
    for tok in tokens {
        let (n, v) = split_named(tok);
        if !n.is_empty() && n.eq_ignore_ascii_case(name) {
            return Some(v);
        }
    }
    None
}

/// Return all bare-positional values (no `NAME` prefix) from a
/// `|`-tokenised record, skipping the leader.
fn positional_values<'a>(tokens: &'a [&'a str]) -> Vec<&'a str> {
    tokens
        .iter()
        .filter_map(|tok| {
            let (n, v) = split_named(tok);
            if n.is_empty() && !v.is_empty() {
                Some(v)
            } else {
                None
            }
        })
        .collect()
}

/// Parse a `|`-leader record. Mutates `db` and `current_discid` in
/// place. Returns `Err(AacsError::HeaderParseError)` on a malformed
/// record.
fn parse_pipe_record(
    body: &str,
    comment: Option<&str>,
    db: &mut KeyDb,
    current_discid: &mut Option<[u8; 20]>,
) -> Result<(), AacsError> {
    let tokens_full = pipe_tokenize(body);
    // Format-doc: outer `|` is mandatory at line start. Splitting on
    // `|` therefore produces an empty leading token. A trailing `|`
    // is also tolerated; if the user wrote `| FOO | BAR` without one
    // we still parse it. We require the FIRST non-empty token to be
    // the leader.
    if tokens_full.first().copied() != Some("") {
        return Err(header_err(
            body,
            "line must start with `|` (no leader `|` found)",
        ));
    }
    // Drop leading/trailing empties.
    let mut tokens: Vec<&str> = tokens_full
        .iter()
        .filter(|t| !t.is_empty())
        .copied()
        .collect();
    if tokens.is_empty() {
        return Err(header_err(body, "empty record"));
    }
    let leader = tokens.remove(0);
    // Field tokens passed to the per-record handlers.
    let fields: Vec<&str> = tokens;

    match leader.to_ascii_uppercase().as_str() {
        "DK" => parse_dk(&fields, comment, body, db),
        "PK" => parse_pk(&fields, comment, body, db),
        "HC" => parse_hc(&fields, comment, body, db),
        "DC" => parse_dc(&fields, comment, body, db),
        "DISCID" => parse_discid(&fields, comment, body, db, current_discid),
        "VID" => parse_vid(&fields, body, db, current_discid),
        "VUK" => parse_vuk(&fields, body, db, current_discid),
        "MEK" => parse_mek(&fields, body, db, current_discid),
        "TK" => parse_tk(&fields, body, db, current_discid),
        "KCD" => parse_kcd(&fields, body, db, current_discid),
        other => Err(header_err(
            body,
            &format!("unrecognised record leader `{other}`"),
        )),
    }
}

fn parse_dk(
    fields: &[&str],
    comment: Option<&str>,
    body: &str,
    db: &mut KeyDb,
) -> Result<(), AacsError> {
    let dk_hex = find_named(fields, "DEVICE_KEY")
        .ok_or_else(|| header_err(body, "DK: missing DEVICE_KEY field"))?;
    let node_hex = find_named(fields, "DEVICE_NODE")
        .ok_or_else(|| header_err(body, "DK: missing DEVICE_NODE field"))?;
    let uv_hex =
        find_named(fields, "KEY_UV").ok_or_else(|| header_err(body, "DK: missing KEY_UV field"))?;
    let shift_hex = find_named(fields, "KEY_U_MASK_SHIFT")
        .ok_or_else(|| header_err(body, "DK: missing KEY_U_MASK_SHIFT field"))?;

    let dk = parse_hex_fixed(dk_hex, 32, "DEVICE_KEY").map_err(|m| header_err(body, &m))?;
    let node = parse_hex_fixed(node_hex, 4, "DEVICE_NODE").map_err(|m| header_err(body, &m))?;
    let uv = parse_hex_fixed(uv_hex, 8, "KEY_UV").map_err(|m| header_err(body, &m))?;
    let shift =
        parse_hex_fixed(shift_hex, 2, "KEY_U_MASK_SHIFT").map_err(|m| header_err(body, &m))?;

    let mut device_key = [0u8; 16];
    device_key.copy_from_slice(&dk);
    let mut device_node = [0u8; 2];
    device_node.copy_from_slice(&node);
    let mut key_uv = [0u8; 4];
    key_uv.copy_from_slice(&uv);

    db.device_keys.push(DeviceKeyRecord {
        device_key,
        device_node,
        key_uv,
        key_u_mask_shift: shift[0],
        comment: comment.map(str::to_string),
    });
    Ok(())
}

fn parse_pk(
    fields: &[&str],
    comment: Option<&str>,
    body: &str,
    db: &mut KeyDb,
) -> Result<(), AacsError> {
    // PK is purely positional: `| PK | 0x<32 hex chars>`.
    let positionals = positional_values(fields);
    if positionals.len() != 1 {
        return Err(header_err(
            body,
            &format!(
                "PK: expected exactly 1 positional value, got {}",
                positionals.len()
            ),
        ));
    }
    let pk =
        parse_hex_fixed(positionals[0], 32, "PROCESSING_KEY").map_err(|m| header_err(body, &m))?;
    let mut processing_key = [0u8; 16];
    processing_key.copy_from_slice(&pk);
    db.processing_keys.push(ProcessingKey {
        processing_key,
        comment: comment.map(str::to_string),
    });
    Ok(())
}

fn parse_hc(
    fields: &[&str],
    comment: Option<&str>,
    body: &str,
    db: &mut KeyDb,
) -> Result<(), AacsError> {
    let priv_hex = find_named(fields, "HOST_PRIV_KEY")
        .ok_or_else(|| header_err(body, "HC: missing HOST_PRIV_KEY field"))?;
    let cert_hex = find_named(fields, "HOST_CERT")
        .ok_or_else(|| header_err(body, "HC: missing HOST_CERT field"))?;

    let priv_bytes =
        parse_hex_fixed(priv_hex, 40, "HOST_PRIV_KEY").map_err(|m| header_err(body, &m))?;
    let cert_bytes = parse_hex_var(cert_hex, "HOST_CERT").map_err(|m| header_err(body, &m))?;

    // Common Final 0.953 §A.1: host cert layout has a u16 length at
    // offset 2..4 (big-endian) equal to the total cert length. Be
    // tolerant if the buffer is too short to even check.
    if cert_bytes.len() >= 4 {
        let declared = u16::from_be_bytes([cert_bytes[2], cert_bytes[3]]) as usize;
        if declared != cert_bytes.len() {
            return Err(header_err(
                body,
                &format!(
                    "HC: HOST_CERT internal length field {declared} != buffer length {}",
                    cert_bytes.len()
                ),
            ));
        }
    }

    let mut host_priv_key = [0u8; 20];
    host_priv_key.copy_from_slice(&priv_bytes);
    db.host_certs.push(HostCertRecord {
        host_priv_key,
        host_cert: cert_bytes,
        comment: comment.map(str::to_string),
    });
    Ok(())
}

fn parse_dc(
    fields: &[&str],
    comment: Option<&str>,
    body: &str,
    db: &mut KeyDb,
) -> Result<(), AacsError> {
    let priv_hex = find_named(fields, "DRIVE_PRIV_KEY")
        .ok_or_else(|| header_err(body, "DC: missing DRIVE_PRIV_KEY field"))?;
    let cert_hex = find_named(fields, "DRIVE_CERT")
        .ok_or_else(|| header_err(body, "DC: missing DRIVE_CERT field"))?;

    let priv_bytes =
        parse_hex_fixed(priv_hex, 40, "DRIVE_PRIV_KEY").map_err(|m| header_err(body, &m))?;
    let cert_bytes = parse_hex_var(cert_hex, "DRIVE_CERT").map_err(|m| header_err(body, &m))?;

    let mut drive_priv_key = [0u8; 20];
    drive_priv_key.copy_from_slice(&priv_bytes);
    db.drive_certs.push(DriveCertRecord {
        drive_priv_key,
        drive_cert: cert_bytes,
        comment: comment.map(str::to_string),
    });
    Ok(())
}

fn parse_discid(
    fields: &[&str],
    comment: Option<&str>,
    body: &str,
    db: &mut KeyDb,
    current_discid: &mut Option<[u8; 20]>,
) -> Result<(), AacsError> {
    // DISCID is positional: `| DISCID | 0x<40 hex chars> [| label]`.
    let positionals = positional_values(fields);
    if positionals.is_empty() {
        return Err(header_err(body, "DISCID: missing disc-id positional value"));
    }
    let id_bytes =
        parse_hex_fixed(positionals[0], 40, "DISCID").map_err(|m| header_err(body, &m))?;
    let mut disc_id = [0u8; 20];
    disc_id.copy_from_slice(&id_bytes);
    *current_discid = Some(disc_id);

    // Free-form trailing positional tokens become the label.
    let label = if positionals.len() > 1 {
        Some(positionals[1..].join(" | "))
    } else {
        None
    };

    let rec = db
        .disc_records
        .entry(disc_id)
        .or_insert_with(|| DiscRecords {
            disc_id,
            ..DiscRecords::default()
        });
    if rec.label.is_none() {
        rec.label = label;
    }
    if rec.label.is_none() {
        rec.label = comment.map(str::to_string);
    }
    Ok(())
}

fn require_discid(
    current_discid: &Option<[u8; 20]>,
    leader: &str,
    body: &str,
) -> Result<[u8; 20], AacsError> {
    current_discid.ok_or_else(|| {
        header_err(
            body,
            &format!("{leader}: must be preceded by a `| DISCID |` row"),
        )
    })
}

fn parse_vid(
    fields: &[&str],
    body: &str,
    db: &mut KeyDb,
    current_discid: &Option<[u8; 20]>,
) -> Result<(), AacsError> {
    let did = require_discid(current_discid, "VID", body)?;
    let value = positional_or_named(fields, "VID", body)?;
    let bytes = parse_hex_fixed(value, 32, "VID").map_err(|m| header_err(body, &m))?;
    let mut vid = [0u8; 16];
    vid.copy_from_slice(&bytes);
    let rec = db.disc_records.entry(did).or_insert_with(|| DiscRecords {
        disc_id: did,
        ..DiscRecords::default()
    });
    rec.vid = Some(vid);
    Ok(())
}

fn parse_vuk(
    fields: &[&str],
    body: &str,
    db: &mut KeyDb,
    current_discid: &Option<[u8; 20]>,
) -> Result<(), AacsError> {
    let did = require_discid(current_discid, "VUK", body)?;
    let value = positional_or_named(fields, "VUK", body)?;
    let bytes = parse_hex_fixed(value, 32, "VUK").map_err(|m| header_err(body, &m))?;
    let mut v = [0u8; 16];
    v.copy_from_slice(&bytes);
    let rec = db.disc_records.entry(did).or_insert_with(|| DiscRecords {
        disc_id: did,
        ..DiscRecords::default()
    });
    rec.vuk = Some(Vuk::from_bytes(v));
    Ok(())
}

fn parse_mek(
    fields: &[&str],
    body: &str,
    db: &mut KeyDb,
    current_discid: &Option<[u8; 20]>,
) -> Result<(), AacsError> {
    let did = require_discid(current_discid, "MEK", body)?;
    let value = positional_or_named(fields, "MEK", body)?;
    let bytes = parse_hex_fixed(value, 32, "MEK").map_err(|m| header_err(body, &m))?;
    let mut mek = [0u8; 16];
    mek.copy_from_slice(&bytes);
    let rec = db.disc_records.entry(did).or_insert_with(|| DiscRecords {
        disc_id: did,
        ..DiscRecords::default()
    });
    rec.mek = Some(mek);
    Ok(())
}

fn parse_tk(
    fields: &[&str],
    body: &str,
    db: &mut KeyDb,
    current_discid: &Option<[u8; 20]>,
) -> Result<(), AacsError> {
    let did = require_discid(current_discid, "TK", body)?;
    let value = positional_or_named(fields, "TK", body)?;
    let bytes = parse_hex_fixed(value, 32, "TK").map_err(|m| header_err(body, &m))?;
    let mut tk = [0u8; 16];
    tk.copy_from_slice(&bytes);
    let rec = db.disc_records.entry(did).or_insert_with(|| DiscRecords {
        disc_id: did,
        ..DiscRecords::default()
    });
    rec.title_keys.push(tk);
    Ok(())
}

fn parse_kcd(
    fields: &[&str],
    body: &str,
    db: &mut KeyDb,
    current_discid: &Option<[u8; 20]>,
) -> Result<(), AacsError> {
    let did = require_discid(current_discid, "KCD", body)?;
    let value = positional_or_named(fields, "KCD", body)?;
    let bytes = parse_hex_var(value, "KCD").map_err(|m| header_err(body, &m))?;
    let rec = db.disc_records.entry(did).or_insert_with(|| DiscRecords {
        disc_id: did,
        ..DiscRecords::default()
    });
    rec.kcd = Some(bytes);
    Ok(())
}

/// Resolve the single hex value of a record that accepts both
/// `| NAME 0xVALUE |` and `| NAME | 0xVALUE |` shapes. The
/// format-doc table for "other record types" writes both styles
/// interchangeably (e.g. `VUK 0x<32 hex chars>` as a single token,
/// versus `| VID | 0x<32 hex chars> |` as two). Accept either.
fn positional_or_named<'a>(
    fields: &'a [&'a str],
    name: &str,
    body: &str,
) -> Result<&'a str, AacsError> {
    if let Some(v) = find_named(fields, name) {
        return Ok(v);
    }
    let positionals = positional_values(fields);
    if positionals.len() == 1 {
        return Ok(positionals[0]);
    }
    Err(header_err(
        body,
        &format!(
            "{name}: expected `{name} 0xVALUE` or `0xVALUE`, got {} positionals + no named match",
            positionals.len()
        ),
    ))
}

// ---- shared helpers ------------------------------------------------------

fn strip_hex_prefix(s: &str) -> &str {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
}

fn parse_hex_array_20_legacy(text: &str) -> Result<[u8; 20], AacsError> {
    if text.len() != 40 {
        return Err(make_legacy_err(text));
    }
    let mut out = [0u8; 20];
    for (i, byte) in out.iter_mut().enumerate() {
        let pair = &text[i * 2..i * 2 + 2];
        *byte = u8::from_str_radix(pair, 16).map_err(|_| make_legacy_err(text))?;
    }
    Ok(out)
}

fn parse_hex_array_16_legacy(text: &str) -> Result<[u8; 16], AacsError> {
    if text.len() != 32 {
        return Err(make_legacy_err(text));
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        let pair = &text[i * 2..i * 2 + 2];
        *byte = u8::from_str_radix(pair, 16).map_err(|_| make_legacy_err(text))?;
    }
    Ok(out)
}

fn make_legacy_err(snippet: &str) -> AacsError {
    let limit = snippet.len().min(80);
    let cut = snippet
        .char_indices()
        .take_while(|(i, _)| *i < limit)
        .last()
        .map(|(i, c)| i + c.len_utf8())
        .unwrap_or(0);
    AacsError::KeyDbParseError(snippet[..cut].to_string())
}

fn header_err(snippet: &str, msg: &str) -> AacsError {
    let limit = snippet.len().min(80);
    let cut = snippet
        .char_indices()
        .take_while(|(i, _)| *i < limit)
        .last()
        .map(|(i, c)| i + c.len_utf8())
        .unwrap_or(0);
    AacsError::HeaderParseError(format!("{msg} (near {:?})", &snippet[..cut]))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- legacy form back-compat tests ----------------------------------

    #[test]
    fn parses_canonical_line() {
        let text = "0123456789ABCDEF0123456789ABCDEF01234567 = V 0102030405060708090A0B0C0D0E0F10 | Test Disc";
        let db = KeyDb::parse(text).unwrap();
        assert_eq!(db.len(), 1);
        let id = parse_hex_array_20_legacy("0123456789ABCDEF0123456789ABCDEF01234567").unwrap();
        let entry = db.entry_for_disc(&id).unwrap();
        assert_eq!(entry.label.as_deref(), Some("Test Disc"));
        assert_eq!(entry.vuk.as_bytes()[0], 0x01);
    }

    #[test]
    fn parses_lowercase_hex() {
        let text = "abcdef0123456789abcdef0123456789abcdef01 = v fedcba9876543210fedcba9876543210";
        let db = KeyDb::parse(text).unwrap();
        assert_eq!(db.len(), 1);
        let id = parse_hex_array_20_legacy("ABCDEF0123456789ABCDEF0123456789ABCDEF01").unwrap();
        assert!(db.entry_for_disc(&id).is_some());
    }

    #[test]
    fn ignores_blank_lines_and_comments() {
        let text = r#"
; this is a comment
;another comment

0123456789ABCDEF0123456789ABCDEF01234567 = V 0102030405060708090A0B0C0D0E0F10 ; trailing comment
"#;
        let db = KeyDb::parse(text).unwrap();
        assert_eq!(db.len(), 1);
    }

    /// Real-world KEYDB.cfg files mix free-form banner lines,
    /// Processing Key records, and exporter-specific metadata that
    /// don't match our `<id> = V <vuk>` shape. We skip those rather
    /// than failing the whole load on the first bad line.
    #[test]
    fn skips_malformed_lines_without_failing_the_load() {
        let text = r#"
; banner
00 = V 0102030405060708090A0B0C0D0E0F10
0123456789ABCDEF0123456789ABCDEF01234567 = X 0102030405060708090A0B0C0D0E0F10
0123456789ABCDEF0123456789ABCDEF01234567 = V 0102
0123456789ABCDEF0123456789ABCDEF01234567 = V CAFEBABE0102030405060708090A0B0C | OK
"#;
        let db = KeyDb::parse(text).unwrap();
        assert_eq!(db.len(), 1);
        let id = parse_hex_array_20_legacy("0123456789ABCDEF0123456789ABCDEF01234567").unwrap();
        let entry = db.entry_for_disc(&id).unwrap();
        assert_eq!(entry.vuk.as_bytes()[0], 0xCA);
        assert_eq!(entry.label.as_deref(), Some("OK"));
    }

    /// Extended libbluray/aacskeys format: `0x`-prefixed disc-id +
    /// pipe-tokenised single-char flags (D/M/I/V/U) introducing each
    /// value, plus `<id>-0x<hex>` Unit Keys after `U`.
    #[test]
    fn parses_extended_libbluray_format() {
        let text = "0x0123456789ABCDEF0123456789ABCDEF01234567 = Test Title \
                    | D | 2017-10-12 \
                    | M | 0x6D6284E100C23949F40559732EA541CE \
                    | I | 0x3E91BD640F849EA14131E70B818A5182 \
                    | V | 0xD8C278536EE614B877FCF3E4DD631091 \
                    | U | 1-0xC8702051C53A11F873EF5851737E6B75 \
                    ; trailing comment";
        let db = KeyDb::parse(text).unwrap();
        assert_eq!(db.len(), 1);
        let id = parse_hex_array_20_legacy("0123456789ABCDEF0123456789ABCDEF01234567").unwrap();
        let entry = db.entry_for_disc(&id).unwrap();
        assert_eq!(entry.vuk.as_bytes()[0], 0xD8);
        assert_eq!(entry.vuk.as_bytes()[15], 0x91);
        assert_eq!(entry.unit_keys.len(), 1);
        assert_eq!(entry.unit_keys[0].0, 1);
        assert_eq!(entry.unit_keys[0].1[0], 0xC8);
        assert_eq!(entry.unit_keys[0].1[15], 0x75);
        assert_eq!(entry.label.as_deref(), Some("Test Title"));
    }

    #[test]
    fn parses_extended_with_multiple_unit_keys() {
        let text = "0x0123456789ABCDEF0123456789ABCDEF01234567 = X \
                    | V | 0x0102030405060708090A0B0C0D0E0F10 \
                    | U | 1-0x11111111111111111111111111111111 \
                    | 2-0x22222222222222222222222222222222 \
                    | 3-0x33333333333333333333333333333333";
        let db = KeyDb::parse(text).unwrap();
        let id = parse_hex_array_20_legacy("0123456789ABCDEF0123456789ABCDEF01234567").unwrap();
        let entry = db.entry_for_disc(&id).unwrap();
        assert_eq!(entry.unit_keys.len(), 3);
        assert_eq!(entry.unit_keys[0], (1, [0x11; 16]));
        assert_eq!(entry.unit_keys[1], (2, [0x22; 16]));
        assert_eq!(entry.unit_keys[2], (3, [0x33; 16]));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_library_preferences_is_in_search_path() {
        let saved_home = std::env::var_os("HOME");
        std::env::set_var("HOME", "/Users/oxideav-test");
        let saved_env = std::env::var_os("OXIDEAV_AACS_KEYDB");
        std::env::remove_var("OXIDEAV_AACS_KEYDB");

        let paths = default_search_paths();
        let want =
            std::path::PathBuf::from("/Users/oxideav-test/Library/Preferences/aacs/KEYDB.cfg");
        assert!(
            paths.contains(&want),
            "macOS search path missing Library/Preferences entry: {paths:?}",
        );

        match saved_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        if let Some(v) = saved_env {
            std::env::set_var("OXIDEAV_AACS_KEYDB", v);
        }
    }

    // ---- `|`-leader record success tests --------------------------------

    /// `| DK |` Device Key, all four named fields.
    #[test]
    fn parses_dk_record() {
        let line = "| DK | DEVICE_KEY 0x000102030405060708090A0B0C0D0E0F \
                    | DEVICE_NODE 0x0800 \
                    | KEY_UV 0x00000400 \
                    | KEY_U_MASK_SHIFT 0x17 \
                    ; MKBv01-MKBv48";
        let db = KeyDb::parse(line).unwrap();
        assert_eq!(db.device_keys().len(), 1);
        let dk = &db.device_keys()[0];
        assert_eq!(
            dk.device_key,
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                0x0E, 0x0F,
            ]
        );
        assert_eq!(dk.device_node, [0x08, 0x00]);
        assert_eq!(dk.key_uv, [0x00, 0x00, 0x04, 0x00]);
        assert_eq!(dk.key_u_mask_shift, 0x17);
        assert_eq!(dk.comment.as_deref(), Some("MKBv01-MKBv48"));
    }

    /// `| PK |` Processing Key.
    #[test]
    fn parses_pk_record() {
        let line = "| PK | 0xAABBCCDDEEFF00112233445566778899 ; MKBv12";
        let db = KeyDb::parse(line).unwrap();
        assert_eq!(db.processing_keys().len(), 1);
        let pk = &db.processing_keys()[0];
        assert_eq!(pk.processing_key[0], 0xAA);
        assert_eq!(pk.processing_key[15], 0x99);
        assert_eq!(pk.comment.as_deref(), Some("MKBv12"));
    }

    /// `| HC |` Host Cert + private key. Cert is exactly 92 bytes with
    /// the cert-type=0x02 + version=0x03 + length=0x005C header.
    #[test]
    fn parses_hc_record() {
        // 92-byte cert: type=0x02, ver=0x03, length=0x005C BE, then
        // arbitrary payload bytes 0x04..0x5B.
        let mut cert = vec![0x02u8, 0x03, 0x00, 0x5C];
        for i in 4..92u8 {
            cert.push(i);
        }
        assert_eq!(cert.len(), 92);
        let cert_hex: String = cert.iter().map(|b| format!("{b:02X}")).collect();
        // 20-byte priv key.
        let priv_hex = "0102030405060708090A0B0C0D0E0F1011121314";
        let line = format!("| HC | HOST_PRIV_KEY 0x{priv_hex} | HOST_CERT 0x{cert_hex} ; valid");
        let db = KeyDb::parse(&line).unwrap();
        assert_eq!(db.host_certs().len(), 1);
        let hc = &db.host_certs()[0];
        assert_eq!(hc.host_priv_key[0], 0x01);
        assert_eq!(hc.host_priv_key[19], 0x14);
        assert_eq!(hc.host_cert.len(), 92);
        assert_eq!(hc.cert_type(), Some(0x02));
        assert_eq!(hc.declared_length(), Some(92));
        // Host ID at offset 8..14.
        assert_eq!(hc.host_id(), Some([8, 9, 10, 11, 12, 13]));
        assert_eq!(hc.comment.as_deref(), Some("valid"));
    }

    /// `| DC |` Drive Cert + private key.
    #[test]
    fn parses_dc_record() {
        let priv_hex = "1112131415161718191A1B1C1D1E1F2021222324";
        let cert_hex = "DEADBEEFCAFEBABE";
        let line = format!("| DC | DRIVE_PRIV_KEY 0x{priv_hex} | DRIVE_CERT 0x{cert_hex}");
        let db = KeyDb::parse(&line).unwrap();
        assert_eq!(db.drive_certs().len(), 1);
        let dc = &db.drive_certs()[0];
        assert_eq!(dc.drive_priv_key[0], 0x11);
        assert_eq!(
            dc.drive_cert,
            vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]
        );
    }

    /// `| DISCID |` + `| VID |` + `| VUK |` + `| MEK |` + `| TK |` scoped
    /// records all attach to the same disc.
    #[test]
    fn parses_disc_scoped_records() {
        let text = "\
| DISCID | 0x0123456789ABCDEF0123456789ABCDEF01234567 \n\
| VID | 0xAABBCCDDEEFF00112233445566778899 \n\
| VUK | 0xD8C278536EE614B877FCF3E4DD631091 \n\
| MEK | 0x11111111111111111111111111111111 \n\
| TK | 0x22222222222222222222222222222222 \n\
| TK | 0x33333333333333333333333333333333 \n\
";
        let db = KeyDb::parse(text).unwrap();
        let id = parse_hex_array_20_legacy("0123456789ABCDEF0123456789ABCDEF01234567").unwrap();
        let rec = db.disc_record(&id).unwrap();
        assert_eq!(rec.disc_id, id);
        assert_eq!(rec.vid.unwrap()[0], 0xAA);
        assert_eq!(rec.vuk.unwrap().as_bytes()[15], 0x91);
        assert_eq!(rec.mek.unwrap(), [0x11; 16]);
        assert_eq!(rec.title_keys.len(), 2);
        assert_eq!(rec.title_keys[0], [0x22; 16]);
        assert_eq!(rec.title_keys[1], [0x33; 16]);

        // vuk_for_disc looks through both maps.
        assert_eq!(db.vuk_for_disc(&id).unwrap().as_bytes()[0], 0xD8);
    }

    /// `| KCD |` Key Conversion Data — variable-length hex.
    #[test]
    fn parses_kcd_record() {
        let text = "\
| DISCID | 0x0123456789ABCDEF0123456789ABCDEF01234567 \n\
| KCD | 0xABCDEF0123 \n\
";
        let db = KeyDb::parse(text).unwrap();
        let id = parse_hex_array_20_legacy("0123456789ABCDEF0123456789ABCDEF01234567").unwrap();
        let rec = db.disc_record(&id).unwrap();
        assert_eq!(
            rec.kcd.as_deref(),
            Some(&[0xAB, 0xCD, 0xEF, 0x01, 0x23][..])
        );
    }

    // ---- `|`-leader record rejection tests ------------------------------

    /// DK with the wrong byte-count for `DEVICE_KEY` is rejected (and
    /// the parser skips it rather than failing the load).
    #[test]
    fn rejects_dk_with_bad_device_key_length() {
        let line = "| DK | DEVICE_KEY 0x0001 | DEVICE_NODE 0x0800 | KEY_UV 0x00000400 | KEY_U_MASK_SHIFT 0x17";
        let db = KeyDb::parse(line).unwrap();
        assert!(db.device_keys().is_empty());
    }

    /// DK missing the required `KEY_UV` field is rejected.
    #[test]
    fn rejects_dk_missing_required_field() {
        let line = "| DK | DEVICE_KEY 0x000102030405060708090A0B0C0D0E0F | DEVICE_NODE 0x0800 | KEY_U_MASK_SHIFT 0x17";
        let db = KeyDb::parse(line).unwrap();
        assert!(db.device_keys().is_empty());
    }

    /// PK with the wrong hex length is rejected.
    #[test]
    fn rejects_pk_with_bad_length() {
        let line = "| PK | 0xAABBCC";
        let db = KeyDb::parse(line).unwrap();
        assert!(db.processing_keys().is_empty());
    }

    /// HC whose embedded length field disagrees with its actual byte
    /// count is rejected.
    #[test]
    fn rejects_hc_with_mismatched_internal_length() {
        // Cert says it's 0x0064 = 100 bytes in the header but is only 8 long.
        let line = "| HC | HOST_PRIV_KEY 0x0102030405060708090A0B0C0D0E0F1011121314 | HOST_CERT 0x0203006401020304";
        let db = KeyDb::parse(line).unwrap();
        assert!(db.host_certs().is_empty());
    }

    /// A `| VID |` row outside any `DISCID` scope is rejected.
    #[test]
    fn rejects_vid_without_discid() {
        let line = "| VID | 0xAABBCCDDEEFF00112233445566778899";
        let db = KeyDb::parse(line).unwrap();
        assert!(db.disc_records().is_empty());
    }

    /// Unrecognised leader is rejected without aborting parse.
    #[test]
    fn rejects_unknown_leader() {
        let text = "| WHAT | 0x00 \n| PK | 0x00112233445566778899AABBCCDDEEFF";
        let db = KeyDb::parse(text).unwrap();
        // PK still landed.
        assert_eq!(db.processing_keys().len(), 1);
    }

    // ---- mixed-file test ------------------------------------------------

    /// A KEYDB.cfg combining legacy `<DISC_ID>=V<VUK>` lines, DK / PK /
    /// HC headers, and a DISCID-scoped record set.
    #[test]
    fn parses_mixed_keydb_file() {
        let text = "\
; AACS keydb.cfg — synthetic mixed test\n\
\n\
0000000000000000000000000000000000000001 = V 0102030405060708090A0B0C0D0E0F10 | Legacy Disc A\n\
\n\
| DK | DEVICE_KEY 0x000102030405060708090A0B0C0D0E0F | DEVICE_NODE 0x0800 | KEY_UV 0x00000400 | KEY_U_MASK_SHIFT 0x17 ; MKBv01-MKBv48\n\
| DK | DEVICE_KEY 0x101112131415161718191A1B1C1D1E1F | DEVICE_NODE 0x0C00 | KEY_UV 0x00000A00 | KEY_U_MASK_SHIFT 0x0B ; MKBv49-MKBv71\n\
\n\
| PK | 0xAABBCCDDEEFF00112233445566778899 ; MKBv12\n\
| PK | 0xBBCCDDEEFF0011223344556677889900 ; MKBv24-MKBv48\n\
\n\
| DISCID | 0x0123456789ABCDEF0123456789ABCDEF01234567 \n\
| VUK | 0xD8C278536EE614B877FCF3E4DD631091 \n\
| TK | 0x22222222222222222222222222222222 \n\
";
        let db = KeyDb::parse(text).unwrap();
        // Legacy entry survives.
        let legacy_id =
            parse_hex_array_20_legacy("0000000000000000000000000000000000000001").unwrap();
        assert_eq!(
            db.entry_for_disc(&legacy_id).unwrap().label.as_deref(),
            Some("Legacy Disc A")
        );
        assert_eq!(db.len(), 1);
        // DK + PK rows accumulated.
        assert_eq!(db.device_keys().len(), 2);
        assert_eq!(db.processing_keys().len(), 2);
        assert_eq!(db.device_keys()[0].key_u_mask_shift, 0x17);
        assert_eq!(db.device_keys()[1].key_u_mask_shift, 0x0B);
        // DISCID scope captured VUK + TK.
        let scoped_id =
            parse_hex_array_20_legacy("0123456789ABCDEF0123456789ABCDEF01234567").unwrap();
        let rec = db.disc_record(&scoped_id).unwrap();
        assert_eq!(rec.vuk.unwrap().as_bytes()[0], 0xD8);
        assert_eq!(rec.title_keys, vec![[0x22; 16]]);
        // vuk_for_disc finds both maps.
        assert_eq!(db.vuk_for_disc(&legacy_id).unwrap().as_bytes()[0], 0x01);
        assert_eq!(db.vuk_for_disc(&scoped_id).unwrap().as_bytes()[0], 0xD8);
    }

    /// Backward-compat: the pre-Phase-A integration-test fixture (legacy
    /// per-disc lines only) still parses to exactly the same shape it
    /// did before the `|`-leader code path was added.
    #[test]
    fn legacy_only_file_unchanged() {
        let text = "\
; legacy-only fixture\n\
0000000000000000000000000000000000000001 = V 0102030405060708090A0B0C0D0E0F10 | Synthetic A\n\
0000000000000000000000000000000000000002 = V 1112131415161718191A1B1C1D1E1F20 ; trailing comment\n\
0000000000000000000000000000000000000003 = V 2122232425262728292A2B2C2D2E2F30 | Disc with | pipes | in label\n\
";
        let db = KeyDb::parse(text).unwrap();
        assert_eq!(db.len(), 3);
        assert!(db.device_keys().is_empty());
        assert!(db.processing_keys().is_empty());
        assert!(db.host_certs().is_empty());
        assert!(db.drive_certs().is_empty());
        assert!(db.disc_records().is_empty());
    }
}
