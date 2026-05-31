//! Structured-malformation robustness tests for the KEYDB.cfg parser.
//!
//! Round 200 adds an enumerated "fuzz" coverage layer for the KEYDB.cfg
//! parser: every record type's plausible malformations (truncated hex,
//! oversized hex, non-hex characters, missing required fields, swapped
//! field-name and value, unknown leaders, mixed line endings, multi-byte
//! UTF-8 in record body, very long lines, hostile combinations) are
//! enumerated as fixed inputs and the parser is expected to:
//!
//! - **Never panic / overflow / loop indefinitely** on any input.
//! - **Never abort the whole parse** because one line is bad — the
//!   `parse(text)` API is *tolerant*, every malformed line is skipped
//!   individually so a single bad line never costs the caller the good
//!   ones that surround it.
//! - **Surface every skip through [`ParseReport`]** when the caller
//!   uses [`KeyDb::parse_with_report`], so a downstream tool can show
//!   the user a "loaded N, skipped M (here's why)" summary instead of
//!   silently dropping records.
//!
//! These tests don't try to be exhaustive in the cryptographic sense
//! (there's no random input source; CI must be deterministic). They
//! enumerate every structurally distinct failure mode the parser
//! exposes, plus a "scan the printable-ASCII byte range" sweep over the
//! leading byte so a regression that crashes on an unusual character
//! would be caught.
//!
//! No external keys, no real KEYDB.cfg content — every line is
//! synthesised in-test.

use oxideav_aacs::{KeyDb, ParseReport, SkippedLine};

// ---------------------------------------------------------------------
// Core invariants
// ---------------------------------------------------------------------

/// Parsing an empty input yields an empty database and a clean report.
#[test]
fn empty_input_is_clean() {
    let (db, report) = KeyDb::parse_with_report("").unwrap();
    assert!(db.is_empty());
    assert!(report.is_clean());
    assert_eq!(report.skipped_count(), 0);
}

/// A file that's nothing but comments + whitespace yields an empty,
/// clean parse (no records, no skipped lines).
#[test]
fn pure_comment_file_is_clean() {
    let text = "\
; banner line\n\
\n\
   ; indented comment\n\
;\n\
\n\
";
    let (db, report) = KeyDb::parse_with_report(text).unwrap();
    assert!(db.is_empty());
    assert!(
        report.is_clean(),
        "pure-comment file must produce zero skipped lines, got {:?}",
        report.skipped
    );
}

/// `parse(text)` returns the same database `parse_with_report` would
/// produce — the legacy API is just a thin discard of the report.
#[test]
fn parse_and_parse_with_report_agree_on_database() {
    let text = "\
; legacy line\n\
0000000000000000000000000000000000000001 = V 0102030405060708090A0B0C0D0E0F10 | A\n\
| PK | 0xAABBCCDDEEFF00112233445566778899 ; pk\n\
";
    let db1 = KeyDb::parse(text).unwrap();
    let (db2, report) = KeyDb::parse_with_report(text).unwrap();
    assert!(report.is_clean());
    assert_eq!(db1.len(), db2.len());
    assert_eq!(db1.processing_keys().len(), db2.processing_keys().len());
}

// ---------------------------------------------------------------------
// ParseReport surfaces every individual line failure
// ---------------------------------------------------------------------

/// The report's `skipped` list preserves source order and 1-based line
/// numbers. A file with good / bad / good must produce exactly one
/// skipped entry at the middle line number.
#[test]
fn skipped_lines_carry_one_based_line_numbers_in_source_order() {
    let text = "\
0000000000000000000000000000000000000001 = V 0102030405060708090A0B0C0D0E0F10\n\
THIS LINE IS NEITHER A LEGACY ENTRY NOR A PIPE RECORD\n\
0000000000000000000000000000000000000002 = V 1112131415161718191A1B1C1D1E1F20\n\
";
    let (db, report) = KeyDb::parse_with_report(text).unwrap();
    assert_eq!(db.len(), 2);
    assert_eq!(report.skipped_count(), 1);
    assert_eq!(report.skipped[0].line_number, 2);
    assert!(
        !report.skipped[0].reason.is_empty(),
        "skipped reason should be a non-empty diagnostic"
    );
    assert!(
        !report.skipped[0].snippet.is_empty(),
        "skipped snippet should be a non-empty excerpt"
    );
}

/// `is_clean()` flips to false the moment we hit even one unparseable
/// line.
#[test]
fn is_clean_reflects_any_skip() {
    let mut r = ParseReport::default();
    assert!(r.is_clean());
    r.skipped.push(SkippedLine {
        line_number: 7,
        snippet: "x".into(),
        reason: "y".into(),
    });
    assert!(!r.is_clean());
    assert_eq!(r.skipped_count(), 1);
}

// ---------------------------------------------------------------------
// Per-record-type structured-malformation enumeration
// ---------------------------------------------------------------------

/// `| DK |` — Device Key: each named field at the wrong byte-count
/// independently skips the line (and never aborts the load).
#[test]
fn dk_record_each_field_wrong_length_is_skipped() {
    // Format-doc DK field byte counts: DEVICE_KEY=16, DEVICE_NODE=2,
    // KEY_UV=4, KEY_U_MASK_SHIFT=1. For each field, swap the correct
    // hex-pair count for a wrong one.
    let cases: &[(&str, &str, &str, &str)] = &[
        // (label, dk_hex, node_hex, uv_hex_and_shift)
        (
            "short DEVICE_KEY",
            "0x000102",
            "0x0800",
            "0x00000400 | KEY_U_MASK_SHIFT 0x17",
        ),
        (
            "short DEVICE_NODE",
            "0x000102030405060708090A0B0C0D0E0F",
            "0x08",
            "0x00000400 | KEY_U_MASK_SHIFT 0x17",
        ),
        (
            "short KEY_UV",
            "0x000102030405060708090A0B0C0D0E0F",
            "0x0800",
            "0x0400 | KEY_U_MASK_SHIFT 0x17",
        ),
        (
            "long KEY_U_MASK_SHIFT",
            "0x000102030405060708090A0B0C0D0E0F",
            "0x0800",
            "0x00000400 | KEY_U_MASK_SHIFT 0x1717",
        ),
    ];
    for (label, dk, node, tail) in cases {
        let line = format!("| DK | DEVICE_KEY {dk} | DEVICE_NODE {node} | KEY_UV {tail}");
        let (db, report) = KeyDb::parse_with_report(&line).unwrap();
        assert!(
            db.device_keys().is_empty(),
            "case {label}: DK should have been skipped, got {:?}",
            db.device_keys()
        );
        assert_eq!(
            report.skipped_count(),
            1,
            "case {label}: expected exactly one skipped line"
        );
    }
}

/// `| DK |` — each required-field absence independently skips.
#[test]
fn dk_record_missing_each_required_field_is_skipped() {
    let full_fields = [
        "DEVICE_KEY 0x000102030405060708090A0B0C0D0E0F",
        "DEVICE_NODE 0x0800",
        "KEY_UV 0x00000400",
        "KEY_U_MASK_SHIFT 0x17",
    ];
    // For each field, drop it and verify the line is rejected.
    for drop_i in 0..full_fields.len() {
        let kept: Vec<&str> = full_fields
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != drop_i)
            .map(|(_, f)| *f)
            .collect();
        let line = format!("| DK | {}", kept.join(" | "));
        let (db, report) = KeyDb::parse_with_report(&line).unwrap();
        assert!(
            db.device_keys().is_empty(),
            "dropping field {drop_i} should reject DK"
        );
        assert_eq!(report.skipped_count(), 1);
    }
}

/// `| PK |` — both too-short and too-long hex are rejected, and the
/// rejection reason is captured in the report.
#[test]
fn pk_record_wrong_hex_lengths_are_rejected_with_reason() {
    for hex in ["0x00", "0xAA", "0xAABB", "0xAABBCCDDEEFF00112233445566"] {
        let line = format!("| PK | {hex}");
        let (db, report) = KeyDb::parse_with_report(&line).unwrap();
        assert!(
            db.processing_keys().is_empty(),
            "hex {hex} must be rejected"
        );
        assert_eq!(report.skipped_count(), 1);
        assert!(
            report.skipped[0].reason.contains("PROCESSING_KEY")
                || report.skipped[0].reason.contains("positional"),
            "rejection reason should mention the failing field, got {:?}",
            report.skipped[0].reason
        );
    }
}

/// `| HC |` — declared cert-length and buffer length must match. A
/// header that lies about its size is rejected without panicking, with
/// a useful diagnostic.
#[test]
fn hc_record_internal_length_mismatch_is_rejected() {
    // Type=0x02, Ver=0x03, declared=0x0064 (=100), only 8 bytes.
    let line =
        "| HC | HOST_PRIV_KEY 0x0102030405060708090A0B0C0D0E0F1011121314 | HOST_CERT 0x0203006401020304";
    let (db, report) = KeyDb::parse_with_report(line).unwrap();
    assert!(db.host_certs().is_empty());
    assert_eq!(report.skipped_count(), 1);
    assert!(
        report.skipped[0].reason.contains("HOST_CERT")
            || report.skipped[0].reason.contains("length"),
        "report should explain the length mismatch, got {:?}",
        report.skipped[0].reason
    );
}

/// `| HC |` — odd-length HOST_CERT hex (not byte-aligned) is rejected
/// rather than truncated.
#[test]
fn hc_record_odd_length_hex_is_rejected() {
    let line = "| HC | HOST_PRIV_KEY 0x0102030405060708090A0B0C0D0E0F1011121314 | HOST_CERT 0x020";
    let (db, report) = KeyDb::parse_with_report(line).unwrap();
    assert!(db.host_certs().is_empty());
    assert_eq!(report.skipped_count(), 1);
}

/// `| HC |` — HOST_CERT field that's missing the `0x` prefix is
/// rejected (the format doc requires `0x`-prefixed hex literals).
#[test]
fn hc_record_missing_hex_prefix_is_rejected() {
    let line =
        "| HC | HOST_PRIV_KEY 0102030405060708090A0B0C0D0E0F1011121314 | HOST_CERT 0xDEADBEEF";
    let (db, report) = KeyDb::parse_with_report(line).unwrap();
    assert!(db.host_certs().is_empty());
    assert_eq!(report.skipped_count(), 1);
}

/// `| DC |` — Drive Certificate with one of its required named fields
/// missing is skipped without affecting the rest of the file.
#[test]
fn dc_record_missing_required_field_is_skipped() {
    let cases = [
        "| DC | DRIVE_PRIV_KEY 0x1112131415161718191A1B1C1D1E1F2021222324",
        "| DC | DRIVE_CERT 0xDEADBEEF",
    ];
    for line in cases {
        let (db, report) = KeyDb::parse_with_report(line).unwrap();
        assert!(db.drive_certs().is_empty(), "line {line:?} should reject");
        assert_eq!(report.skipped_count(), 1);
    }
}

/// `| VID |`, `| VUK |`, `| MEK |`, `| TK |`, `| KCD |` — each must be
/// preceded by a `| DISCID |` row. Out-of-scope rows are rejected.
#[test]
fn discid_scoped_rows_require_a_preceding_discid() {
    let scoped_lines = [
        "| VID | 0xAABBCCDDEEFF00112233445566778899",
        "| VUK | 0xAABBCCDDEEFF00112233445566778899",
        "| MEK | 0xAABBCCDDEEFF00112233445566778899",
        "| TK | 0xAABBCCDDEEFF00112233445566778899",
        "| KCD | 0xDEADBEEF",
    ];
    for line in scoped_lines {
        let (db, report) = KeyDb::parse_with_report(line).unwrap();
        assert!(
            db.disc_records().is_empty(),
            "out-of-scope line {line:?} should reject"
        );
        assert_eq!(report.skipped_count(), 1);
        assert!(
            report.skipped[0].reason.contains("DISCID"),
            "report should mention the missing DISCID, got {:?}",
            report.skipped[0].reason
        );
    }
}

/// `| DISCID |` with a wrong-length disc-id is rejected. A subsequent
/// scoped `| VUK |` is then itself rejected (no DISCID scope).
#[test]
fn malformed_discid_invalidates_subsequent_scoped_rows() {
    let text = "\
| DISCID | 0x00112233\n\
| VUK | 0xAABBCCDDEEFF00112233445566778899\n\
";
    let (db, report) = KeyDb::parse_with_report(text).unwrap();
    assert!(db.disc_records().is_empty());
    // Both lines should be in the skipped report: the bad DISCID + the
    // VUK that found no scope.
    assert_eq!(report.skipped_count(), 2);
}

/// Unknown leaders (anything not in the set DK / PK / HC / DC / DISCID
/// / VID / VUK / MEK / TK / KCD) are rejected without aborting.
#[test]
fn unknown_leader_is_rejected_with_diagnostic() {
    let text = "\
| WHAT | 0x00\n\
| ???? | 0x00\n\
| 1234 | 0x00\n\
| PK | 0xAABBCCDDEEFF00112233445566778899\n\
";
    let (db, report) = KeyDb::parse_with_report(text).unwrap();
    // PK row still landed.
    assert_eq!(db.processing_keys().len(), 1);
    assert_eq!(report.skipped_count(), 3);
    for s in &report.skipped {
        assert!(
            s.reason.contains("unrecognised") || s.reason.contains("leader"),
            "unknown-leader rejection should mention 'unrecognised'/'leader', got {:?}",
            s.reason
        );
    }
}

/// A line that's *almost* a pipe record but has no opening `|` is
/// dispatched to the legacy parser, which also rejects it. The
/// rejection happens through the legacy path's KeyDbParseError.
#[test]
fn line_without_leader_pipe_is_dispatched_to_legacy_path() {
    let line = "DK | DEVICE_KEY 0x00";
    let (db, report) = KeyDb::parse_with_report(line).unwrap();
    assert!(db.is_empty());
    assert_eq!(report.skipped_count(), 1);
}

// ---------------------------------------------------------------------
// Legacy <DISC_ID>=V<VUK> path malformations
// ---------------------------------------------------------------------

/// Legacy line with a too-short disc-id is skipped.
#[test]
fn legacy_short_disc_id_is_skipped() {
    let text = "00 = V 0102030405060708090A0B0C0D0E0F10";
    let (db, report) = KeyDb::parse_with_report(text).unwrap();
    assert!(db.is_empty());
    assert_eq!(report.skipped_count(), 1);
}

/// Legacy line with a too-short VUK is skipped.
#[test]
fn legacy_short_vuk_is_skipped() {
    let text = "0000000000000000000000000000000000000001 = V 010203";
    let (db, report) = KeyDb::parse_with_report(text).unwrap();
    assert!(db.is_empty());
    assert_eq!(report.skipped_count(), 1);
}

/// Legacy line with a non-hex character in the disc-id is skipped.
#[test]
fn legacy_nonhex_disc_id_is_skipped() {
    let text = "GG00000000000000000000000000000000000001 = V 0102030405060708090A0B0C0D0E0F10";
    let (db, report) = KeyDb::parse_with_report(text).unwrap();
    assert!(db.is_empty());
    assert_eq!(report.skipped_count(), 1);
}

/// Legacy line missing the `=` separator entirely is skipped.
#[test]
fn legacy_missing_equals_is_skipped() {
    let text = "0000000000000000000000000000000000000001 V 0102030405060708090A0B0C0D0E0F10";
    let (db, report) = KeyDb::parse_with_report(text).unwrap();
    assert!(db.is_empty());
    assert_eq!(report.skipped_count(), 1);
}

// ---------------------------------------------------------------------
// "Fuzz" coverage — line-leading byte sweep + mixed line endings +
// large inputs + adversarial encodings
// ---------------------------------------------------------------------

/// Sweep the printable-ASCII byte range as the first character of a
/// line. The parser must never panic; every line should either parse
/// (only for hex digits, which trigger the legacy path) or be skipped
/// cleanly.
#[test]
fn parser_does_not_panic_on_any_printable_ascii_leader() {
    for c in 0x20u8..=0x7Eu8 {
        let ch = char::from(c);
        // Skip `;` (turns the whole line into a comment, expected to
        // produce zero entries and no skip).
        let line = format!("{ch}   uninterpretable garbage");
        let (_db, report) = KeyDb::parse_with_report(&line).unwrap();
        // Either it's a comment-only or empty body (0 skipped) or a
        // garbage body (1 skipped); never panic, never error.
        assert!(
            report.skipped_count() <= 1,
            "leader byte 0x{c:02X} produced multi-line skip: {:?}",
            report.skipped
        );
    }
}

/// Mixed line endings: CRLF, LF, lone CR mid-text. `str::lines()` is
/// the source-of-truth splitter and handles CRLF + LF cleanly; any line
/// with an embedded `\r` should not crash the parser.
#[test]
fn crlf_and_mixed_line_endings_are_tolerated() {
    let text = "\
0000000000000000000000000000000000000001 = V 0102030405060708090A0B0C0D0E0F10\r\n\
0000000000000000000000000000000000000002 = V 1112131415161718191A1B1C1D1E1F20\n\
| PK | 0xAABBCCDDEEFF00112233445566778899\r\n\
";
    let (db, report) = KeyDb::parse_with_report(text).unwrap();
    assert_eq!(db.len(), 2);
    assert_eq!(db.processing_keys().len(), 1);
    assert!(report.is_clean());
}

/// A very long line (10 KiB of `X` characters) must not panic or take
/// pathological time; the truncated excerpt in the report stays under
/// the 80-byte cap.
#[test]
fn very_long_bad_line_is_skipped_with_truncated_excerpt() {
    let bad = "X".repeat(10_240);
    let (db, report) = KeyDb::parse_with_report(&bad).unwrap();
    assert!(db.is_empty());
    assert_eq!(report.skipped_count(), 1);
    assert!(
        report.skipped[0].snippet.len() <= 80,
        "snippet should be capped at 80 bytes, got {}",
        report.skipped[0].snippet.len()
    );
    // The original 10 KiB string never made it into the report.
    assert_ne!(report.skipped[0].snippet, bad);
}

/// Multi-byte UTF-8 in a record body must not cause the snippet
/// truncation to split a codepoint. The reason field is a `String` so
/// it's already valid UTF-8; the snippet field must be too.
#[test]
fn multi_byte_utf8_in_bad_line_does_not_split_codepoints() {
    // Three-byte "雪" then padding so the truncation lands in the middle
    // of the multi-byte sequence if it ignored char boundaries.
    let bad = format!("{}{}", "雪".repeat(40), "x".repeat(100));
    let (_db, report) = KeyDb::parse_with_report(&bad).unwrap();
    assert_eq!(report.skipped_count(), 1);
    // No panic; the snippet round-trips through String::from cleanly.
    let _ = report.skipped[0].snippet.chars().count();
}

/// An interleaved file of legitimate + adversarial lines preserves the
/// good records and reports each bad line with its own line number.
#[test]
fn interleaved_good_and_bad_lines_keep_good_and_report_each_bad() {
    let text = "\
0000000000000000000000000000000000000001 = V 0102030405060708090A0B0C0D0E0F10\n\
| ZZZZ | garbage\n\
| PK | 0xAABBCCDDEEFF00112233445566778899\n\
random non-record text\n\
| HC | HOST_PRIV_KEY 0xDEAD | HOST_CERT 0xBEEF\n\
0000000000000000000000000000000000000002 = V 1112131415161718191A1B1C1D1E1F20\n\
| DISCID | 0x0000000000000000000000000000000000000003\n\
| VUK | 0xCAFEBABECAFEBABECAFEBABECAFEBABE\n\
";
    let (db, report) = KeyDb::parse_with_report(text).unwrap();
    // Legacy entries: lines 1 + 6.
    assert_eq!(db.len(), 2);
    // PK rows: line 3.
    assert_eq!(db.processing_keys().len(), 1);
    // DISCID + VUK scoped record: lines 7 + 8.
    assert_eq!(db.disc_records().len(), 1);
    // Skipped lines: line 2 (ZZZZ), line 4 (random), line 5 (HC with
    // wrong-length priv-key) = 3 skips.
    assert_eq!(
        report.skipped_count(),
        3,
        "expected 3 skipped, got {:?}",
        report
            .skipped
            .iter()
            .map(|s| (s.line_number, &s.reason))
            .collect::<Vec<_>>()
    );
    // Line numbers come back in source order.
    let line_numbers: Vec<usize> = report.skipped.iter().map(|s| s.line_number).collect();
    assert_eq!(line_numbers, vec![2, 4, 5]);
}

/// A line that's only whitespace + a `;` comment must not appear in
/// the skipped report — comment-only lines never count as "bad".
#[test]
fn comment_only_and_whitespace_lines_never_appear_in_skipped_report() {
    let text = "\
\n\
   \t\n\
; comment\n\
   ; indented comment\n\
0000000000000000000000000000000000000001 = V 0102030405060708090A0B0C0D0E0F10\n\
\n\
";
    let (db, report) = KeyDb::parse_with_report(text).unwrap();
    assert_eq!(db.len(), 1);
    assert!(
        report.is_clean(),
        "report unexpectedly skipped: {:?}",
        report.skipped
    );
}

/// A pile of pipe-record-shaped garbage of every leader-letter combo
/// (4-letter alphabetic uppercase tags) — none match a known leader,
/// every line is skipped, no panic.
#[test]
fn many_unknown_leaders_in_one_file_all_get_skipped() {
    let mut text = String::new();
    // 26 letters × use as leading char; we won't enumerate every 4-char
    // combo (would be 26^4 lines), but we cover one per letter as a
    // representative sweep.
    for c in 'A'..='Z' {
        text.push_str(&format!("| {c}{c}{c}{c} | 0x00\n"));
    }
    let (db, report) = KeyDb::parse_with_report(&text).unwrap();
    assert!(db.is_empty());
    // Exclude `D`, `P`, `H`, `T`, `V`, `M`, `K` — `DDDD`/`PPPP`/etc.
    // don't match real leaders either, so every line is skipped.
    assert_eq!(report.skipped_count(), 26);
}
