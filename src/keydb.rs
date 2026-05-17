//! KEYDB.cfg parser — the de-facto community VUK key-database format.
//!
//! This format is **not** specified by AACS LA. It is the convention
//! used by libbluray and similar OSS tools to store
//! `(disc_id, volume_unique_key)` pairs the user has obtained
//! out-of-band. Each significant line has the form
//!
//! ```text
//! <DISC_ID_40_hex_chars> = V <VUK_32_hex_chars> | <free-form label>
//! ```
//!
//! Where:
//!
//! - `DISC_ID` is the SHA-1-equivalent 20-byte (40-hex) identifier of
//!   the BD-ROM, taken from the leading 20 bytes of the disc's
//!   Content Certificate ID. Hex is case-insensitive.
//! - The token `V` (capital letter `V`) means the line holds a Volume
//!   Unique Key. We also tolerate lowercase `v`.
//! - `VUK` is 16 bytes / 32 hex characters.
//! - The trailing `| label` is optional free-form text (e.g. the
//!   title); we preserve it for diagnostics but never rely on it.
//!
//! `;` introduces a comment to end-of-line. Empty lines are ignored.
//!
//! The implementation here was written *from this description*; no
//! libbluray / aacskeys source was consulted.

use crate::error::AacsError;
use crate::vuk::Vuk;
use std::collections::BTreeMap;
use std::path::Path;

/// One parsed KEYDB.cfg entry.
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

/// In-memory KEYDB.cfg database.
#[derive(Debug, Default, Clone)]
pub struct KeyDb {
    by_disc_id: BTreeMap<[u8; 20], KeyDbEntry>,
}

impl KeyDb {
    /// Parse a KEYDB.cfg byte stream from a `&str`.
    ///
    /// Lines that do not parse are not silently dropped: the first
    /// parse failure returns [`AacsError::KeyDbParseError`] with the
    /// offending line (truncated to 80 chars).
    pub fn parse(text: &str) -> Result<Self, AacsError> {
        let mut out = Self::default();
        for raw in text.lines() {
            // Strip `;` comments to end-of-line.
            let line = match raw.find(';') {
                Some(i) => &raw[..i],
                None => raw,
            };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let entry = parse_line(line)?;
            out.by_disc_id.insert(entry.disc_id, entry);
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
    pub fn vuk_for_disc(&self, disc_id: &[u8; 20]) -> Option<Vuk> {
        self.by_disc_id.get(disc_id).map(|e| e.vuk)
    }

    /// Look up the full parsed entry by disc ID.
    pub fn entry_for_disc(&self, disc_id: &[u8; 20]) -> Option<&KeyDbEntry> {
        self.by_disc_id.get(disc_id)
    }

    /// Iterate all entries.
    pub fn entries(&self) -> impl Iterator<Item = &KeyDbEntry> {
        self.by_disc_id.values()
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.by_disc_id.len()
    }

    /// Whether the database is empty.
    pub fn is_empty(&self) -> bool {
        self.by_disc_id.is_empty()
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

/// Parse one KEYDB.cfg line. Tolerates both the simple form
///
/// ```text
/// <DISC_ID 40 hex> = V <VUK 32 hex> | <label>
/// ```
///
/// and the extended libbluray/aacskeys form (with optional `0x`
/// prefixes on every hex value, multiple `|`-separated tokens, and
/// single-char flag tokens `D`/`M`/`I`/`V`/`U` that introduce the
/// next value):
///
/// ```text
/// 0x<DISC_ID> = <name> | D | <date> | M | 0x<MK> | I | 0x<VOL_ID>
///             | V | 0x<VUK> | U | 1-0x<UK1> | 2-0x<UK2> | ... ; <comment>
/// ```
fn parse_line(line: &str) -> Result<KeyDbEntry, AacsError> {
    let (disc_id_text, rhs) = match line.split_once('=') {
        Some(parts) => parts,
        None => return Err(make_parse_err(line)),
    };
    let disc_id_text = strip_hex_prefix(disc_id_text.trim());
    let disc_id = parse_hex_array_20(disc_id_text)?;

    // Tokenise the RHS on `|`. Each pipe-token may carry one or two
    // sub-tokens (whitespace-separated): either `<FLAG> <VALUE>`
    // (e.g. simple form `V 0102...`), `<FLAG>` alone with the value
    // in the NEXT pipe-token (extended libbluray form), `<VALUE>`
    // alone (claimed by the most recent flag), or a `<id>-0x<key>`
    // Unit-Key entry. Single-char flags D/M/I/V/U set the state
    // machine; non-flag/non-key tokens accumulate into `label`.
    let pipe_tokens: Vec<&str> = rhs.split('|').map(str::trim).collect();
    let mut vuk_bytes: Option<[u8; 16]> = None;
    let mut unit_keys: Vec<(u16, [u8; 16])> = Vec::new();
    let mut label_parts: Vec<String> = Vec::new();
    let mut current_flag: Option<char> = None;
    for ptok in pipe_tokens {
        if ptok.is_empty() {
            continue;
        }
        // Split off a leading single-char flag (D/M/I/V/U,
        // case-insensitive). Everything else is the "value", which
        // is claimed by the current flag state (or accumulated into
        // label if no flag is active).
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
                    vuk_bytes = Some(parse_hex_array_16(raw)?);
                }
                current_flag = None;
            }
            Some('U') => {
                if let Some((id_str, key_str)) = value.split_once('-') {
                    let key_str = strip_hex_prefix(key_str.trim());
                    if let (Ok(id), Ok(key)) =
                        (id_str.trim().parse::<u16>(), parse_hex_array_16(key_str))
                    {
                        unit_keys.push((id, key));
                    }
                }
                // Stay in U state — next pipe-token may be another unit key.
            }
            Some(_) => {
                // D / M / I value — recognised but not stored.
                current_flag = None;
            }
            None => {
                label_parts.push(value.to_string());
            }
        }
    }

    let vuk_bytes = vuk_bytes.ok_or_else(|| make_parse_err(line))?;
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

/// Strip a leading `0x` or `0X` if present. Tolerant of empty.
fn strip_hex_prefix(s: &str) -> &str {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
}

fn parse_hex_array_20(text: &str) -> Result<[u8; 20], AacsError> {
    if text.len() != 40 {
        return Err(make_parse_err(text));
    }
    let mut out = [0u8; 20];
    for (i, byte) in out.iter_mut().enumerate() {
        let pair = &text[i * 2..i * 2 + 2];
        *byte = u8::from_str_radix(pair, 16).map_err(|_| make_parse_err(text))?;
    }
    Ok(out)
}

fn parse_hex_array_16(text: &str) -> Result<[u8; 16], AacsError> {
    if text.len() != 32 {
        return Err(make_parse_err(text));
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        let pair = &text[i * 2..i * 2 + 2];
        *byte = u8::from_str_radix(pair, 16).map_err(|_| make_parse_err(text))?;
    }
    Ok(out)
}

fn make_parse_err(snippet: &str) -> AacsError {
    let limit = snippet.len().min(80);
    let cut = snippet
        .char_indices()
        .take_while(|(i, _)| *i < limit)
        .last()
        .map(|(i, c)| i + c.len_utf8())
        .unwrap_or(0);
    AacsError::KeyDbParseError(snippet[..cut].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_line() {
        let text = "0123456789ABCDEF0123456789ABCDEF01234567 = V 0102030405060708090A0B0C0D0E0F10 | Test Disc";
        let db = KeyDb::parse(text).unwrap();
        assert_eq!(db.len(), 1);
        let id = parse_hex_array_20("0123456789ABCDEF0123456789ABCDEF01234567").unwrap();
        let entry = db.entry_for_disc(&id).unwrap();
        assert_eq!(entry.label.as_deref(), Some("Test Disc"));
        assert_eq!(entry.vuk.as_bytes()[0], 0x01);
    }

    #[test]
    fn parses_lowercase_hex() {
        let text = "abcdef0123456789abcdef0123456789abcdef01 = v fedcba9876543210fedcba9876543210";
        let db = KeyDb::parse(text).unwrap();
        assert_eq!(db.len(), 1);
        let id = parse_hex_array_20("ABCDEF0123456789ABCDEF0123456789ABCDEF01").unwrap();
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

    #[test]
    fn rejects_malformed_line() {
        // Wrong number of hex chars for disc id.
        let text = "00 = V 0102030405060708090A0B0C0D0E0F10";
        assert!(matches!(
            KeyDb::parse(text),
            Err(AacsError::KeyDbParseError(_))
        ));
    }

    #[test]
    fn rejects_wrong_tag() {
        let text = "0123456789ABCDEF0123456789ABCDEF01234567 = X 0102030405060708090A0B0C0D0E0F10";
        assert!(matches!(
            KeyDb::parse(text),
            Err(AacsError::KeyDbParseError(_))
        ));
    }

    #[test]
    fn rejects_wrong_vuk_length() {
        let text = "0123456789ABCDEF0123456789ABCDEF01234567 = V 0102";
        assert!(matches!(
            KeyDb::parse(text),
            Err(AacsError::KeyDbParseError(_))
        ));
    }

    /// Extended libbluray/aacskeys format: `0x`-prefixed disc-id +
    /// pipe-tokenised single-char flags (D/M/I/V/U) introducing each
    /// value, plus `<id>-0x<hex>` Unit Keys after `U`. Tolerated for
    /// compatibility with the de-facto community KEYDB.cfg files
    /// users already maintain for libbluray/makemkv.
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
        let id = parse_hex_array_20("0123456789ABCDEF0123456789ABCDEF01234567").unwrap();
        let entry = db.entry_for_disc(&id).unwrap();
        assert_eq!(entry.vuk.as_bytes()[0], 0xD8);
        assert_eq!(entry.vuk.as_bytes()[15], 0x91);
        assert_eq!(entry.unit_keys.len(), 1);
        assert_eq!(entry.unit_keys[0].0, 1);
        assert_eq!(entry.unit_keys[0].1[0], 0xC8);
        assert_eq!(entry.unit_keys[0].1[15], 0x75);
        assert_eq!(entry.label.as_deref(), Some("Test Title"));
    }

    /// Multiple Unit Keys in one extended line.
    #[test]
    fn parses_extended_with_multiple_unit_keys() {
        let text = "0x0123456789ABCDEF0123456789ABCDEF01234567 = X \
                    | V | 0x0102030405060708090A0B0C0D0E0F10 \
                    | U | 1-0x11111111111111111111111111111111 \
                    | 2-0x22222222222222222222222222222222 \
                    | 3-0x33333333333333333333333333333333";
        let db = KeyDb::parse(text).unwrap();
        let id = parse_hex_array_20("0123456789ABCDEF0123456789ABCDEF01234567").unwrap();
        let entry = db.entry_for_disc(&id).unwrap();
        assert_eq!(entry.unit_keys.len(), 3);
        assert_eq!(entry.unit_keys[0], (1, [0x11; 16]));
        assert_eq!(entry.unit_keys[1], (2, [0x22; 16]));
        assert_eq!(entry.unit_keys[2], (3, [0x33; 16]));
    }

    /// On macOS, `default_search_paths()` includes the native
    /// `~/Library/Preferences/aacs/KEYDB.cfg` location ahead of the
    /// XDG fallbacks, so users don't have to set `XDG_CONFIG_HOME`
    /// just to be found by `KeyDb::load_default`.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_library_preferences_is_in_search_path() {
        // Pin HOME to a deterministic value so this test doesn't depend
        // on the runner's $HOME (CI sets it to /Users/runner; dev box
        // sets it to /Users/<name>; either is fine as long as the
        // produced path joins through Library/Preferences/aacs/).
        let saved_home = std::env::var_os("HOME");
        std::env::set_var("HOME", "/Users/oxideav-test");
        // Also clear OXIDEAV_AACS_KEYDB so it doesn't push to the front
        // and shadow the macOS entry from the search order.
        let saved_env = std::env::var_os("OXIDEAV_AACS_KEYDB");
        std::env::remove_var("OXIDEAV_AACS_KEYDB");

        let paths = default_search_paths();
        let want =
            std::path::PathBuf::from("/Users/oxideav-test/Library/Preferences/aacs/KEYDB.cfg");
        assert!(
            paths.contains(&want),
            "macOS search path missing Library/Preferences entry: {paths:?}",
        );

        // Restore env so neighbour tests don't see the change.
        match saved_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        if let Some(v) = saved_env {
            std::env::set_var("OXIDEAV_AACS_KEYDB", v);
        }
    }
}
