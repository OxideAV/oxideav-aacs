//! KEYDB.cfg parser integration tests — synthetic fixtures only.

use oxideav_aacs::{AacsError, KeyDb};

fn parse_disc_id(s: &str) -> [u8; 20] {
    assert_eq!(s.len(), 40);
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

#[test]
fn parses_multi_line_keydb() {
    let text = r#"
; Test KEYDB.cfg — entries are synthetic, none are real disc keys.
; Format: <DISC_ID:40hex> = V <VUK:32hex> [| label]

0000000000000000000000000000000000000001 = V 0102030405060708090A0B0C0D0E0F10 | Synthetic A
0000000000000000000000000000000000000002 = V 1112131415161718191A1B1C1D1E1F20 ; trailing comment

; another commented block
0000000000000000000000000000000000000003 = V 2122232425262728292A2B2C2D2E2F30 | Disc with | pipes | in label
"#;
    let db = KeyDb::parse(text).unwrap();
    assert_eq!(db.len(), 3);
    let a = db
        .entry_for_disc(&parse_disc_id("0000000000000000000000000000000000000001"))
        .unwrap();
    assert_eq!(a.label.as_deref(), Some("Synthetic A"));
    let b = db
        .entry_for_disc(&parse_disc_id("0000000000000000000000000000000000000002"))
        .unwrap();
    assert_eq!(b.label, None); // trailing `;` comment was stripped, so no label
    let c = db
        .entry_for_disc(&parse_disc_id("0000000000000000000000000000000000000003"))
        .unwrap();
    // `|` splitn(2) so the rest survives intact
    assert_eq!(c.label.as_deref(), Some("Disc with | pipes | in label"));
}

#[test]
fn lookup_returns_vuk_bytes() {
    let text = "FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00 = V AABBCCDDEEFF00112233445566778899";
    let db = KeyDb::parse(text).unwrap();
    let id = parse_disc_id("FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00");
    let vuk = db.vuk_for_disc(&id).unwrap();
    assert_eq!(vuk.as_bytes()[0], 0xAA);
    assert_eq!(vuk.as_bytes()[15], 0x99);
    let missing = parse_disc_id("0000000000000000000000000000000000000000");
    assert!(db.vuk_for_disc(&missing).is_none());
}

#[test]
fn ignores_purely_blank_input() {
    let db = KeyDb::parse("\n\n\n   ; only comments\n   \n").unwrap();
    assert!(db.is_empty());
}

#[test]
fn rejects_malformed_disc_id() {
    // Disc ID is too short.
    let text = "00 = V 0102030405060708090A0B0C0D0E0F10";
    assert!(matches!(
        KeyDb::parse(text),
        Err(AacsError::KeyDbParseError(_))
    ));
}

#[test]
fn rejects_malformed_vuk() {
    // VUK has a non-hex character.
    let text = "0000000000000000000000000000000000000001 = V GG02030405060708090A0B0C0D0E0F10";
    assert!(matches!(
        KeyDb::parse(text),
        Err(AacsError::KeyDbParseError(_))
    ));
}

#[test]
fn load_from_env_override() {
    use std::io::Write;
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        tmp,
        "0000000000000000000000000000000000000005 = V 0102030405060708090A0B0C0D0E0F10"
    )
    .unwrap();
    let path = tmp.path().to_path_buf();
    // Set the env override and call load_default.
    let prev = std::env::var("OXIDEAV_AACS_KEYDB").ok();
    // Safe within a single test; serial test harness would be more
    // defensive but we don't share state with other tests here.
    unsafe {
        std::env::set_var("OXIDEAV_AACS_KEYDB", &path);
    }
    let db = KeyDb::load_default().unwrap();
    assert_eq!(db.len(), 1);
    // Restore env.
    unsafe {
        if let Some(p) = prev {
            std::env::set_var("OXIDEAV_AACS_KEYDB", p);
        } else {
            std::env::remove_var("OXIDEAV_AACS_KEYDB");
        }
    }
}
