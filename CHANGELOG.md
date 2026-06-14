# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Round 299 GET CONFIGURATION (`0x46`) + AACS Feature Descriptor (Feature `0x010D`, Common §4.14.1 Table 4-4)

The host's capability-discovery path: before issuing any AACS command a
PC Host issues `GET CONFIGURATION` to confirm the logical unit
implements the AACS Feature (Feature Code `0x010D`) and to read the
drive's AACS capability bits. This was the named gap in
`docs/container/aacs/mmc/aacs-keyclass-02-wire-format.md` §6 (the only
fully-specified AACS-over-MMC command the crate did not yet model).

- **`GetConfiguration`** — typed builder for the 10-byte `GET
  CONFIGURATION` CDB (opcode `0x46`, RT field byte 1 bits 1..0, Starting
  Feature Number bytes 2..3 big-endian, Allocation Length bytes 7..8
  big-endian) with `cdb()` / `parse_cdb()` inverses per MMC-6 §6.5.1.1
  Table 256. Constructor **`GetConfiguration::aacs_feature()`** sets
  RT = `10b` and Starting Feature Number = `0x010D`. Unlike the four
  AACS Key-Class / Disc-Structure commands this is a *10-byte* CDB, so
  it does not share the 12-byte `MMC_CDB_LEN` frame;
  `GET_CONFIGURATION_CDB_LEN` = `10`.
- **`AacsFeatureDescriptor`** + **`to_bytes()`** /
  **`parse_aacs_feature_descriptor(buf)`** — the 8-byte descriptor
  (generic 4-byte Feature Descriptor header — Feature Code `0x010D`,
  `Version 0010b`, Persistent/Current bits, `Additional Length 04h` —
  plus the 4-byte Feature Dependent Data) per AACS Common §4.14.1
  Table 4-4 / MMC-6 §5.2.2. Byte 4 decodes the RDC / RMC / WBE / BEC /
  BNG capability flags; byte 5 the Block Count for Binding Nonce; byte 6
  the Number of AGIDs (3-bit); byte 7 the AACS version (`01h`). The
  struct doc records the §4.14.1 trust rule (the host must read BEC/WBE
  from the *signed Drive Certificate*, not this descriptor).
- **`find_aacs_feature_descriptor(response)`** — walks a full GET
  CONFIGURATION response (8-byte Feature Header + variable-length
  descriptors, each `4 + Additional Length` bytes per MMC-6 §5.2.1
  Tables 86–88) and returns the AACS descriptor, `None` for a non-AACS
  drive, or `Truncated` on a short buffer / over-running descriptor.
- **`build_get_configuration_aacs_response(descriptor, current_profile)`**
  — mints a minimal well-formed response (Feature Header with the
  count-after-itself Data Length + one AACS descriptor) for round-trip
  tests.

Named constants `GET_CONFIGURATION_OPCODE` (`0x46`), `FEATURE_AACS`
(`0x010D`), `GET_CONFIG_RT_ALL` / `GET_CONFIG_RT_CURRENT` /
`GET_CONFIG_RT_ONE`, `FEATURE_HEADER_LEN`, `AACS_FEATURE_DESCRIPTOR_LEN`,
`AACS_FEATURE_ADDITIONAL_LENGTH`, `AACS_FEATURE_VERSION`,
`AACS_FEATURE_AACS_VERSION`. New integration suite
`tests/synth_round299_get_configuration.rs` (17 cases) pins the CDB +
descriptor byte layout, both inverse round-trips, the all-flags-set /
all-flags-clear cases, the 3-bit Number-of-AGIDs masking, the
Feature-list walk (including skipping a leading non-AACS descriptor and
the `None`-when-absent path), and every rejection (wrong opcode / wrong
Feature Code / wrong Additional Length / truncated header / over-running
descriptor).

### Added — Round 288 Type-4 verify-precursor-or-apply-KCD Media Key resolution (Common §3.2.5.1.4)

`Mkb::resolve_media_key_with_kcd(candidate_precursor, kcd)` centralises
the Common spec §3.2.5.1.4 decision a KCD-equipped device performs after
the Subset-Difference walk, which (for a Type-4 MKB) yields a Media Key
*Precursor* `K_mp` rather than the final Media Key:

1. If `K_mp` *already* verifies against the Verify Media Key Record it is
   itself the correct `K_m` and is returned unchanged — the device
   "shall not apply the KCD data, even if it is a type of device that
   normally would use KCD data" (e.g. an old MKB into whose part of the
   tree the KCD has not yet been incorporated).
2. Otherwise `K_m = AES-G(K_mp, KCD)` is computed and verified; on
   success the converted value is returned.
3. If neither verifies, the new
   `AacsError::MediaKeyPrecursorResolutionFailed` is returned.

Previously the per-primitive `subdiff::apply_key_conversion_data` helper
left this branch to the caller (its doc comment told callers to "verify
the precursor first, and only invoke `apply_key_conversion_data` if it
doesn't verify"), which made it possible to apply KCD to a precursor that
was already the final Media Key and silently derive a wrong key. The new
method makes the spec branch un-skippable. Four unit tests pin the
pass-through, the conversion, the dual-failure error, and the
missing-Verify-Media-Key-Record path. Lib tests 181 → 185.

### Added — Round 277 SEND DISC STRUCTURE Format `0x85` Bus-Encryption Sector Extents (Common §4.14.5.2 Table 4-29)

The SEND DISC STRUCTURE (`0xBF`) Format `0x85` sub-payload — the
host→drive command that establishes the sector ranges whose Bus
Encryption Flag shall be set when data is written — completes the
§4.14.5 Table 4-27 Format table (Format `0x84` Write Data Key landed
in round 269).

- `SendDiscStructure::aacs_bus_encryption_sector_extents(num_extents)`
  — typed `0xBF` CDB constructor (Media Type BD, Format Code `0x85`,
  Parameter List Length `4 + N*16`, AGID reserved — Format `0x85`
  requires no AACS authentication).
- `build_send_disc_structure_bus_encryption_sector_extents` /
  `parse_send_disc_structure_bus_encryption_sector_extents` — the
  Table 4-29 parameter list `[length:u16 = 2 + N*16][reserved:u16]` +
  `N` 16-byte LBA Extent Structures
  `[reserved:8 || Start LBA:u32 || LBA Count:u32]`. An empty list is
  the "clear current extents" request (`[0x00,0x02,0x00,0x00]`).
- `validate_bus_encryption_sector_extents(extents, media_capacity_lba)`
  — the §4.14.5.2 sorted / non-overlapping / non-zero-count /
  within-capacity ingest check; each violation surfaces as a tagged
  `AacsError::InvalidValue`.

`MockDrive` gains a `media_capacity_lba: u32` slot and a SEND DISC
STRUCTURE Format `0x85` dispatcher arm enforcing the §4.14.5.2
SYSTEM RESOURCE FAILURE (too many extents) and INVALID FIELD IN
PARAMETER LIST (malformed table) rules, then replacing the stored
extent set. New integration suite
`tests/synth_round277_send_bus_encryption_sector_extents.rs` (14 cases).

## [0.1.3](https://github.com/OxideAV/oxideav-aacs/compare/v0.1.2...v0.1.3) - 2026-06-10

### Other

- feature-gate MockDrive + AKE self-checks behind test-util (out of default public API)
- SEND DISC STRUCTURE Format 0x84 Write Data Key (Common §4.14.5.1 Table 4-28)
- handshake-level integration tests for Format 0x85 Bus-Encryption Sector Extents
- drop release-plz.toml — use release-plz defaults across the workspace
- READ DISC STRUCTURE Format 0x85 Bus-Encryption Sector Extents (Common §4.14.3.6 Table 4-20)
- READ DISC STRUCTURE Format 0x84 Data Keys sub-payload (Common §4.14.3.5 Table 4-19)
- REPORT KEY Binding Nonce sub-payloads (Common §4.14.2.4 Table 4-10 / §4.14.2.5 Table 4-11)
- typed Type-and-Version accessors (Common §3.2.5.1.1 / Table 3-2)
- Content Revocation List parse + per-segment ECDSA verify + revocation-record lookup (PVB §2.7 / Tables 2-2..2-5)
- signed Content Certificate parse + verify (PVB §2.4/§2.5/§2.6 + BD-Prerecorded Table 2-1)
- AKE/EC runtime self-check entry points (Common §2.3 + §4.3)
- structured ParseReport + fuzz/robustness suite for KEYDB.cfg parser
- fix MKB Subset-Difference walk to match the spec
- bundle the AACS LA root public key as a spec constant

### Changed — `MockDrive` + AKE self-checks moved behind `test-util` feature

The in-process synthetic-drive test fixture `MockDrive` and the two
self-checks that drive it — `ake_full_self_check` and `all_self_checks`
— are now gated behind a new `test-util` cargo feature and are no longer
part of the default public API. They remain reachable from the crate's
own tests (the crate enables `test-util` on itself via a self
dev-dependency). The three pure-math self-checks — `curve_self_check`,
`aacs_la_pub_self_check`, and `ake_ecdh_self_check` — stay public and
ungated, as do `DriveCommand`, `ScsiResponse`, `DataDirection`, and all
real command builders/parsers. External consumers that imported
`MockDrive`, `ake_full_self_check`, or `all_self_checks` should enable
`features = ["test-util"]` on the `oxideav-aacs` dependency.

### Added — Round 269 SEND DISC STRUCTURE Format `0x84` Write Data Key
  (Common §4.14.5 Tables 4-26 / 4-27 + §4.14.5.1 Table 4-28; MMC-6
  §6.36.2.1 Table 572 / §6.36.3.2.11 Table 591)

The SEND DISC STRUCTURE (`0xBF`) command — the host→drive counterpart
of READ DISC STRUCTURE — enters the typed MMC surface with its Format
Code `0x84` (Write Data Key) sub-payload: the command a host issues to
replace the Write Data Key the §4.11 Bus Encryption layer uses to wrap
sectors it writes. Previous rounds covered the full READ-side Format
Code table (`0x80`..`0x85`); this round opens the SEND side at the
§4.14.5.1 entry. The remaining Table 4-27 entry — Format `0x85`,
Bus-Encryption Sector Extents ingest with the §4.14.5.2 sorted /
non-overlapping / capacity / non-zero-count validation rules — is the
named next step.

- **`SendDiscStructure`** — typed `0xBF` CDB builder per Table 4-26:
  Media Type in the low nibble of byte 1, bytes 2..6 reserved, Format
  Code at byte 7, Parameter List Length at bytes 8..9 (big-endian),
  AGID in bits 7..6 of byte 10 (used only for Format `0x84` per MMC-6
  §6.36.2.4), Control at byte 11. `cdb()` / `parse_cdb()` inverses
  mirror the existing `ReadDiscStructure` / `SendKey` pattern.
- **`SendDiscStructure::aacs_write_data_key(agid)`** — constructor for
  the Format `0x84` send. Media Type BD, parameter list length 20
  (= 4-byte header + 16-byte encrypted Write Data Key).
- **`build_send_disc_structure_write_data_key(kwd_encrypted)`** /
  **`parse_send_disc_structure_write_data_key(buf)`** — the Table 4-28
  parameter list `[length:u16=0x0012][reserved:u16][Kwd:16]`. The
  two-byte Data Length field does not count itself, so its mandated
  value is `0x0012`; the parser rejects any other length field and
  truncated buffers. Bytes 4..19 carry the replacement Write Data Key,
  encrypted by the Bus Key using AES-128E per §4.14.5.1 paragraph 3 —
  the host wraps the plaintext with the existing
  `aes_128_ecb_encrypt(bus_key, kwd)` primitive before building the
  list.
- **`SEND_DISC_STRUCTURE_OPCODE`** = `0xBF` and
  **`FORMAT_AACS_WRITE_DATA_KEY`** = `0x84` — named constants for the
  new opcode and the SEND-side Format Code (numerically the same value
  as the READ-side `FORMAT_AACS_DATA_KEYS`, named separately because
  Table 4-27 defines it as a distinct data-out payload).

`MockDrive` gains a `SEND_DISC_STRUCTURE_OPCODE` dispatcher arm and a
`last_write_data_key_sent: Option<[u8; 16]>` capture slot holding the
on-wire (still-wrapped) key field. In `auth` mode the mock unwraps the
incoming key with AES-128D under the established Bus Key and stores
the plaintext in `write_data_key`, returning the spec-mandated KEY NOT
ESTABLISHED error path (§4.14.5.1 final paragraph) when the `auth`
slot is armed but no Bus Key has been derived; in static-fixture mode
the wire bytes are adopted verbatim, mirroring the READ-side Format
`0x84` behaviour. The §4.14.5.1 INSUFFICIENT PERMISSION branch (host
not authorized to send the Write Data Key) is not modelled — the mock
treats every caller as authorized. The Read Data Key is never touched,
matching the §4.11 "the drive sets Kwd equal to Krd on media insertion
until the host overwrites it" lifecycle.

Companion test suite `tests/synth_round269_write_data_key_send.rs`
(9 cases): static-mode end-to-end round-trip (wire bytes adopted
verbatim, Krd untouched, response data-in phase empty), CDB byte
layout pin against Table 4-26 (opcode/media-type/reserved-span/format/
length/AGID/control), parameter-list byte layout pin against Table
4-28, wrap-under-planted-Bus-Key (drive stores plaintext, capture slot
stores wrapped bytes), KEY-NOT-ESTABLISHED error path with state
unchanged, read-back coherence (SEND `0x84` then READ `0x84` recovers
the new Kwd and the unchanged Krd under the same Bus Key), a full §4.3
AKE handshake whose host-side Bus Key wraps a replacement Kwd that the
drive's independently-derived Bus Key unwraps to the same plaintext,
malformed-parameter-list rejection (wrong length field + truncated
buffer, state unchanged both times), and a builder/parser
encode→decode→unwrap round-trip. Eight additional unit tests live in
`src/mmc.rs` alongside the existing CDB-layout cases (including
unknown-Format and wrong-data-direction rejection by the dispatcher
arm).

### Added — Round 246 READ DISC STRUCTURE Format `0x85` Bus-Encryption
  Sector Extents (Common §4.14.3.6 Table 4-20 / MMC-6 §6.22.3.1.6 Table 389)

The READ DISC STRUCTURE Format Code `0x85` sub-payload — the
variable-length LBA-Extent table the logical unit publishes so the host
can discover which sector ranges are subject to §4.11 Bus Encryption —
is now exposed as a typed CDB constructor + response parser pair.
Previous rounds covered Format Codes `0x80` / `0x81` / `0x82` (IDs),
`0x83` (MKB packs), and `0x84` (Data Keys); `0x85` closes the
sub-payload list at the no-authentication entry the spec permits
without the §4.3 AKE (§4.14.3.6 final sentence: "This command does not
require AACS authentication.").

- **`ReadDiscStructure::aacs_bus_encryption_sector_extents()`** — CDB
  constructor for Format `0x85`. Media Type BD, AGID reserved (no
  AACS authentication required), Address + Layer reserved, allocation
  length sized for the worst-case 256-extent response (12 + 256 * 16
  = 4108 bytes; callers issuing the command against a known smaller
  bound may shrink `allocation_length` after constructing the CDB).
- **`BusEncryptionSectorExtent { start_lba: u32, lba_count: u32 }`** —
  one LBA range. Both fields are 32-bit big-endian on the wire (bytes
  12+n*16..15+n*16 and 16+n*16..19+n*16 of Table 4-20).
- **`BusEncryptionSectorExtentsResponse { maximum: u16, extents:
  Vec<BusEncryptionSectorExtent> }`** — decoded variable-length wire
  layout `[length:u16 = N*16 + 2][reserved:u8][maximum:u8]` followed
  by `N` 16-byte extent records `[reserved:8 || Start LBA:4 || LBA
  Count:4]`. The `maximum` field spans `1..=256`; the on-wire encoding
  represents `256` as the byte value `0` per the §4.14.3.6 paragraph 3
  sentinel ("The value 256 is denoted by a '0' in the field.").
- **`parse_bus_encryption_sector_extents_response(buf)`** — wire-layout
  parser. Decodes the `0` → `256` sentinel back to its semantic value;
  preserves the on-wire extent order verbatim (per §4.14.3.6 paragraph
  3 the extents are sorted by `start_lba` ascending and non-overlapping,
  but the parser does not enforce the invariant — the SEND DISC
  STRUCTURE Format `0x85` ingest path is where the logical unit
  rejects malformed tables per §4.14.5.x). Rejects buffers whose
  length field is below `2`, buffers shorter than `2 + length`, and
  extent sections whose byte count is not a multiple of 16.
- **`FORMAT_AACS_BUS_ENCRYPTION_SECTOR_EXTENTS`** = `0x85` and
  **`BUS_ENCRYPTION_SECTOR_EXTENT_LEN`** = `16` — named constants for
  the new Format Code and the per-record wire stride.

`MockDrive` gains `bus_encryption_sector_extents:
Vec<BusEncryptionSectorExtent>` + `max_bus_encryption_sector_extents:
u16` slots and a Format `0x85` dispatcher arm that serialises the
table verbatim. The default `with_test_fixture` constructor pre-loads
two non-overlapping extents in ascending Start LBA order (matching the
§4.14.3.6 paragraph 3 sort rule) so the round-trip test surfaces any
byte-order or stride drift; `Default` initialises an empty extent list
with a `maximum` of `1`. The empty-table path emits a 4-byte response
(`length = 2`) per §4.14.3.6 paragraph 2 ("If no Bus-Encryption Sector
Extents are currently defined, the Data Length field shall be 2."); the
256-extent ceiling is encoded as the wire byte `0` per §4.14.3.6
paragraph 3. Because this Format Code does not require AACS
authentication, the dispatcher walks the branch without consulting
`MockDrive::auth`.

Companion test suite `tests/synth_round246_bus_encryption_sector_extents.rs`
(12 cases) exercises end-to-end round-trip through `MockDrive`, pins
the CDB byte layout (Format `0x85`, allocation length `0x100C`, AGID
field zeroed, Address + Layer Number reserved), pins the response wire
layout (length field encoding `N*16 + 2`, per-record stride 16, Start
LBA at offset 8 of each record, LBA Count at offset 12), pins the
`256 ↔ wire-byte 0` sentinel for the Maximum field both directions,
exercises the empty-table path explicitly, walks a three-extent
hand-stuffed wire payload byte-by-byte to catch any silent u32-field
swap, and rejects malformed inputs (length field below `2`, truncated
buffer, misaligned stride). Nine additional unit tests live in
`src/mmc.rs` alongside the existing CDB-layout cases.

### Added — Round 243 READ DISC STRUCTURE Format `0x84` Data Keys
  (Common §4.14.3.5 Table 4-19)

The READ DISC STRUCTURE Format Code `0x84` sub-payload — the encrypted
Read/Write Data Key pair the Bus Encryption layer (§4.11) uses to wrap
sector payloads — is now exposed as a typed CDB constructor + response
parser pair. Previous rounds covered Format Codes `0x80` / `0x81` / `0x82`
(IDs) and `0x83` (MKB packs); `0x84` brings the sub-payload list level
with the §4.11 protocol the surrounding `aes` + `ake` modules already
implement.

- **`ReadDiscStructure::aacs_data_keys(agid)`** — CDB constructor for
  Format `0x84`. Media Type BD, allocation length 36 (= 4-byte header
  + 16-byte Read Data Key + 16-byte Write Data Key), AGID in bits
  7..6 of byte 10; bytes 2..6 reserved per the §4.14.3.5 table.
- **`DataKeysResponse { read_data_key_encrypted: [u8; 16],
  write_data_key_encrypted: [u8; 16] }`** — decoded 36-byte wire
  layout `[length:u16=0x0022][reserved:u16][Krd:16][Kwd:16]` per
  Table 4-19. Both Data Keys are on the wire wrapped under the Bus
  Key with AES-128E per §4.11.
- **`DataKeysResponse::decrypt_read_data_key(bus_key)`** /
  **`decrypt_write_data_key(bus_key)`** — host-side unwrap helpers
  (AES-128D under the same Bus Key) recovering plaintext `Krd` /
  `Kwd`.
- **`parse_data_keys_response(buf)`** — wire-layout parser; rejects
  buffers whose length field is not `0x0022` and truncated payloads.
- **`FORMAT_AACS_DATA_KEYS`** = `0x84` and **`DATA_KEY_LEN`** = `16` —
  named constants for the new Format Code and key-field width.

`MockDrive` gains `read_data_key: [u8; 16]` / `write_data_key: [u8;
16]` plaintext slots and a `last_data_keys_read: bool` capture flag so
tests can assert the §4.14.3.5 branch ran. In `auth` mode the mock
wraps each Data Key with `aes_128_ecb_encrypt(bus_key, key)` per §4.11
("the Bus Key is used to protect the Data Keys using AES-128E") before
serialising the response; in static-fixture mode the plaintext bytes
go out verbatim, mirroring the existing Volume-ID / PMSN / Media-ID
behaviour. When the `auth` slot is set but the Bus Key has not yet
been derived, the dispatcher returns the spec-mandated
KEY-NOT-ESTABLISHED error path (§4.14.3.5 final paragraph), surfaced
as `AacsError::InvalidValue { what: "READ_DISC_STRUCTURE Format 0x84
without Bus Key", … }`.

Companion test suite `tests/synth_round243_data_keys.rs` (9 cases)
covers end-to-end round-trip through `MockDrive` in both static and
synthetic-Bus-Key modes, pins the CDB byte layout (Format byte 0x84,
allocation length 0x0024, AGID packing, zero Reserved/Address), pins
the response wire layout (length field `0x0022`, 36-byte total, Krd
at bytes 4..19 and Kwd at bytes 20..35), pins the AES-128E ↔
AES-128D wrap/unwrap round-trip property, and rejects malformed
inputs (wrong length field, truncated payload). Six additional unit
tests live in `src/mmc.rs` alongside the existing CDB-layout cases.

The previous `read_disc_structure_unknown_format_is_rejected` test
case (which had used `0x84` as a placeholder "not modelled" Format
Code) moves to `0x87` so the rejection diagnostic still surfaces from
the dispatcher's catch-all arm.

### Added — Round 240 REPORT KEY Binding Nonce sub-payloads
  (Common §4.14.2.4 Table 4-10 / §4.14.2.5 Table 4-11)

The two AACS Key Class `0x02` Key Format codes the spec defines
alongside the previously-implemented AGID / Drive Cert Challenge /
Drive Key / Drive Cert / Invalidate-AGID set — `0x20` (Binding Nonce —
generated in drive) and `0x21` (Binding Nonce — read from medium) —
were declared as named constants since round 93 but had no typed CDB
constructor or response parser. Round 240 fills that hole:

- **`ReportKey::aacs_binding_nonce_gen(agid, starting_lba, block_count)`** —
  CDB constructor for the generate-and-store variant. The LBA Extent
  identified by `(starting_lba, block_count)` lands in CDB bytes 2..5
  (big-endian) and byte 6 per AACS Common §4.14.2 final paragraph; the
  rest of the CDB follows Table 513.
- **`ReportKey::aacs_binding_nonce_read(agid, starting_lba, block_count)`** —
  CDB constructor for the read-from-medium variant. Same wire layout;
  the only difference is the Key Format field (`0x21` vs `0x20`),
  which selects the §4.7.2 read protocol over §4.7.1 generate.
- **`BindingNonceResponse { binding_nonce: [u8; 16], mac: [u8; 16] }`** —
  decoded response. Both Key Formats share the 36-byte response wire
  layout (Tables 4-10 and 4-11 are identical):
  `[length:u16=0x0022][reserved:u16][nonce:16][mac:16]`.
- **`parse_report_key_binding_nonce(buf)`** — parser for that wire
  layout. A single parser covers both Key Formats.
- **`BINDING_NONCE_LEN`** = 16 and **`BINDING_NONCE_MAC_LEN`** = 16 —
  named constants for the two payload fields.

The 16-byte MAC the response carries is `Dm = CMAC(BK, Nonce)` under
the §4.3-derived Bus Key per the §4.7.1 / §4.7.2 transferred-binding-
nonce protocol; the caller validates it against its own
`Hm = CMAC(BK, Nonce)` after deriving the Bus Key from the §4.3 AKE.

`MockDrive` now dispatches both Key Format codes and stores the
`(key_format, starting_lba, block_count)` triple from the most recent
Binding Nonce CDB in a new `last_binding_nonce_op: Option<(u8, u32,
u8)>` field, so a test can confirm the AACS Common §4.14.2 LBA-Extent
CDB packing. In `auth` mode the mock recomputes the MAC with
`aes_128_cmac(bus_key, binding_nonce)` per §4.7; in static mode it
returns the fixture `binding_nonce_mac` verbatim. Static-fixture
`binding_nonce` / `binding_nonce_mac` slots use the same
index-pattern-tagging idiom as the existing Volume-ID / PMSN / Media-ID
fixture bytes.

Companion test suite `tests/synth_round240_binding_nonce.rs`
(7 cases) covers both Key Formats end-to-end through `MockDrive`,
asserts the 36-byte response length matches Table 4-10, pins the LBA
Extent CDB packing (bytes 2..5 big-endian + byte 6), distinguishes
`0x20` from `0x21` via the CDB Key Format field, and rejects malformed
inputs (wrong length field, truncated payload). Five additional unit
tests live in `src/mmc.rs` alongside the existing CDB-layout cases.

### Added — Round 236 MKB Type-and-Version typed accessors
  (Common §3.2.5.1.1 / Table 3-2)

Three small, surface-level typed accessors on the parsed `Mkb` that
expose Type-and-Version Record fields a downstream consumer would
otherwise have to extract by hand from the existing `mkb_type` / raw
`version` fields:

- **`MkbType::has_aacs_marker() -> bool`** — verifies the low 16 bits
  of the on-wire MKBType field match the spec-mandated `0x1003`
  marker (Table 3-2's `000x_1003₁₆` layout). The three named variants
  (`Type3` / `Type4` / `Type10`) always return `true`; the
  `Other(u32)` catch-all returns `true` iff the low 16 bits actually
  match. The parser does **not** reject non-marker values
  (manufacturer-specific behaviour per §3.2.5 final paragraph for an
  improperly formatted MKB), so the predicate lets a caller assert
  well-formedness explicitly.

- **`MkbType::generation() -> Option<u8>`** — returns the high-byte
  of the on-wire MKBType field when the `0x1003` marker is present
  (so `Type3 → Some(3)`, `Type4 → Some(4)`, `Type10 → Some(10)`,
  `Other(0x0007_1003) → Some(7)` for forward-compat with a
  hypothetical generation the spec might define later), and `None`
  when the marker doesn't match.

- **`Mkb::generation() -> Option<u8>`** — convenience wrapper that
  forwards to `mkb_type.and_then(|t| t.generation())`. Returns `None`
  on a hand-constructed `Mkb` with no Type-and-Version Record (the
  parser would have errored out with `MissingTypeAndVersionRecord`
  before returning such an `Mkb`).

- **`Mkb::is_test_mkb() -> bool`** — Common §3.2.5.1.1 reads "The
  Version Numbers begin at 1; 0 is a special value used for test
  Media Key Blocks." This predicate surfaces that sentinel so a
  Licensed Player that wants to refuse test MKBs in production can
  gate on it before any further processing.

Pure surface additions: no behavioural change to `Mkb::parse`, no new
parse-error variants, no fixture changes. One new test
(`mkb_generation_and_is_test_mkb_render_from_parsed_type_record`)
parses synthetic MKBs covering every spec-defined generation, a
forward-compat generation, a malformed non-`1003` field, the
`version == 0` test sentinel, and a default-constructed `Mkb`, and
pins the accessors' contract for each case. Two additional unit
tests cover `MkbType::has_aacs_marker` and `MkbType::generation` on
the enum variants directly.

### Added — Round 229 Content Revocation List parse + per-segment
  ECDSA verify + revocation-record lookup (PVB §2.7 / Tables 2-2..2-5)

New module `crl` implements the AACS-LA-signed Content Revocation List
(`ContentRevocation.lst` stored under the `\AACS\` and
`\AACS\DUPLICATE\` directories) — the signed list of revoked Content
Certificate IDs, Managed Copy Server Certificate IDs, and Recordable
Media Revocation Records (RMRR) a Licensed Player consults before
honouring the Content Certificate the round-222 layer parses /
verifies.

- **`ContentRevocationList::parse(bytes)`** — decodes a
  `ContentRevocation.lst` blob into:
  - The 4-byte CRL Header (`List Type` 4 bits + reserved nibble, 2-byte
    big-endian `List Version`, 1-byte `Number of Segments`).
  - `N` `CrlSegment { segment_size, records, signature }` records, each
    starting with a 4-byte `Segment Size` field, then a Revocation
    Record Set of decoded `RevocationRecord`s, then a trailing 40-byte
    Entity Signature. The Segment Size #1 cap (≤ 128 KiB − CRL Header
    per PVB §2.7) is enforced; trailing `0x00` padding bytes after the
    last segment are tolerated per the PVB §2.2 mastering rule.
- **`RevocationRecord`** enum — structured decode of every spec-defined
  Record Type plus a forward-compatibility `Unknown` variant:
  - `ContentCertificateId { range, id }` (PVB Table 2-3,
    `Record_Type == 0x0`) — 4-bit Record_Type + 12-bit Range + 6-byte
    Content Certificate ID.
  - `ManagedCopyServerCertificateId { range, id }` (PVB Table 2-4,
    `Record_Type == 0x1`).
  - `RecordableMedia(RecordableMediaRevocation)` (PVB Table 2-5, the
    three contiguous `0x2 / 0x3 / 0x4` records folded on parse into one
    high-level record carrying the `ICCID` flag, 3-bit `Recordable
    Media Type`, 6-byte Content Certificate ID, and 16-byte Media ID).
    A 3-record run that doesn't begin with `Record_Type == 0x2` or
    whose `0x3` / `0x4` continuation is missing is preserved verbatim
    as `Unknown` so adjacent valid records still apply.
  - `Unknown { record_type, bytes }` per PVB §2.7 ("If a Licensed
    Product encounters a Revocation Record with a Record_Type value
    it does not recognize, the record shall be ignored.") — preserves
    the raw 8 bytes so a forward-compatibility record doesn't cause
    adjacent valid records to be silently dropped.
- **`ContentRevocationList::verify_segment_signature(k, aacs_la_pub)`**
  + **`verify_last_segment_signature(aacs_la_pub)`** +
  **`verify_all_segments(aacs_la_pub)`** — run
  `AACS_Verify(AACS_LApub, CRL_Segsig, CRL_Seg)` with the spec's
  cumulative-prefix signed range: segment `k`'s signed payload is
  "CRL Header || segment 0 bytes (size + records + signature) || … ||
  segment k bytes (size + records)" — everything before segment `k`'s
  own 40-byte signature. The `verify_last_segment_signature` helper
  encodes the PVB §2.7 spec optimisation ("when reading more than one
  CRL Segment, only the signature of the last Segment shall be
  checked since that signature includes all previous fields including
  previous Segments and the CRL Header").
- **`ContentRevocationList::is_content_certificate_id_revoked(id)`**
  + **`is_managed_copy_server_id_revoked(id)`** — global revocation
  queries that walk every segment's records and apply the spec
  range-match semantics; the Content-Certificate query additionally
  surfaces the embedded Content Certificate IDs of any `RecordableMedia`
  records whose ICCID flag is `0` (PVB §2.7.2 step 4 from the Prepared
  Video book).
- **`ContentRevocationList::recordable_media_revoked(media_type,
  media_id, content_certificate_id)`** — the four-step §2.7.2
  applicability check for a `(type, media_id, content_certificate_id)`
  triple. Returns `true` only when an RMRR matches both the media
  type and the media ID and either its ICCID flag is `1` or its
  embedded Content Certificate ID matches the queried CCID.
- **`ContentRevocationList::to_bytes`** — byte-exact round-trip with
  `parse` for any value that parsed cleanly (used by the test fixture
  builder to mint signed synthetic CRLs).
- New types `ManagedCopyServerCertificateId(pub [u8; 6])`,
  `RecordableMediaRevocation { iccid, media_type,
  content_certificate_id, media_id }`, and `RecordableMediaType`
  (`BdRecordable` / `HdDvdRecordable` / `DvdRecordable` /
  `PlusRecordable` / `Reserved(u8)` for forward-compatibility).
- Public constants `LIST_TYPE_FIRST_GEN`, `CRL_HEADER_LEN`,
  `REVOCATION_RECORD_LEN`, `SEGMENT_SIGNATURE_LEN`,
  `SEGMENT_1_SIZE_MAX`, and the five `RECORD_TYPE_*` tag values.

No new error variants — the module reuses `AacsError::Truncated`,
`OversizedRecord`, `InvalidValue`, and `MkbSignatureInvalid` so the
consumer can fold all `AACS_Verify` failures through the same branch
that already handles the MKB-side and Content-Certificate-side
ECDSA verify failures.

Companion integration test `tests/synth_round229_crl.rs` (10 cases)
mints a synthetic AACS LA Entity ECDSA key pair, builds a fully
populated three-segment CRL (segment 0: 4 CCID records including a
12-ID range; segment 1: 2 MCS records; segment 2: 1 RMRR with
ICCID=0), then pins: byte-exact round trip, per-segment + last-segment
+ all-segment signature verification, cumulative-prefix signed-range
lengths, content-certificate range semantics, MCS range semantics,
RMRR with ICCID=1 (matches by media only), RMRR with ICCID=0 (also
revokes by CCID), wrong public key rejects every segment, in-place
record tampering breaks the last-segment signature, trailing
`0x00`-padding tolerance, and `Unknown`-record preservation.

Lib-side test module (18 cases) covers single-segment round trips for
each record type, the RMRR bit-layout (ICCID at bit 3, media type at
bits 2..=0 of byte 0 of record 1), the 16-byte Media ID
reassembly across the three on-wire records, the Range-match
semantics for both CCID and MCS records, multi-segment cumulative
prefix verification, malformed RMRR-1-without-2-or-3 preservation as
`Unknown`, segment-size-too-small rejection, the
first-segment 128 KiB cap, zero-`Number_of_Segments` rejection,
truncated-buffer rejection, and trailing-non-zero-byte rejection.

### Added — Round 222 signed Content Certificate parse + verify
  (PVB §2.4 / §2.5 / §2.6, BD-Prerecorded Table 2-1)

New module `content_certificate` implements the AACS-LA-signed Table
2-1 wrapper that binds a BD-ROM physical layer's revocation parameters,
BDMV usage-rules hashes, and per-Content-Hash-Table digests into one
ECDSA-signed blob — the Pre-recorded Video Book §2.6 verification the
Content Hash Table integrity check (already implemented in round 188)
depends on.

- **`ContentCertificate::parse(bytes)`** — decodes one
  `Content00N.cer` file into the generic PVB Table 2-1 header
  (Certificate Type, BEE flag, `Total_Number_of_HashUnits`,
  `Total_Number_of_Layers`, `Layer_Number`, `Number_of_HashUnits`,
  `Number_of_Digests`, `Applicant ID`, `Content Sequence Number`,
  `Minimum CRL Version`), the variable-length `Format_Specific_Section`
  (with the `Length_Format_Specific_Section` 4-byte-alignment rule
  enforced and `L = 0` accepted as the spec's alignment-pad case), the
  `Number_of_Digests` 8-byte `Content Hash Table Digest`s, and the
  trailing 40-byte `Signature Data` field.
- **`ContentCertificate::verify_signature(aacs_cc_pub)`** —
  `AACS_Verify(AACS_CC_pub, Signature_Data, CC)` over the certificate
  bytes up to but excluding the trailing 40-byte signature (PVB §2.5
  step 4 / §2.6 step 5). The caller supplies the AACS LA Content
  Certificate public key; AACS LA distributes it only to licensees so
  the crate ships no key material.
- **`ContentCertificate::content_hash_table_digest(cht_bytes)`** +
  **`verify_content_hash_table_digest(digest_index, cht_bytes)`** —
  recompute `CHT_d = [SHA-1(CHT)]_lsb_64` (PVB §2.5 step 3 / §2.6
  step 3) over the raw on-disc Content Hash Table bytes and match
  against the per-layer digest stored in the certificate.
- **`ContentCertificate::content_certificate_id()`** — returns the
  6-byte Content Certificate ID = `Applicant_ID || Content Sequence
  Number` per PVB §2.4; this is the lookup key for PVB Table 2-3
  Revocation Records.
- **`ContentCertificate::bd_format_specific_section()`** /
  **`BdFormatSpecificSection::parse(bytes)`** — decode the
  BD-Prerecorded Final 0.953 Table 2-1 Format-Specific Section
  (`Hash_Value_of_MC_Manifest_File`(20) + `Hash_Value_of_BDJ_Root_Cert`
  (20) + `Num_of_CPS_Unit`(2) + `J × Hash_Value_of_CPS_Unit_Usage_File`
  (20·J)) out of the generic variable-length region.
- **`ContentSequenceNumber`** — structured 6-bit CCSS ID / 15-bit
  Timestamp / 11-bit Sequence Number (= `Sequence Number 1(4) ||
  Sequence Number 2(7)`) decoder + re-encoder for the bit layout in
  BD-Prerecorded Table 2-1 bytes 16..=19.
- **`usage_rules_hash(bytes)`** — exposes the `C_ur =
  SHA-1(Usage_Rules)` primitive from PVB §2.6 so the caller can apply
  it to whichever usage-rules artefact the adaptation book specifies
  (the BD spec uses the MC Manifest File and the per-CPS-Unit Usage
  Files).

Reused error variants only: `AacsError::Truncated` /
`AacsError::OversizedRecord` (mirror the existing parser surface),
`AacsError::InvalidValue` (unknown Certificate Type or violated length
alignment), `AacsError::MkbSignatureInvalid` (signature `AACS_Verify`
rejected; reused so consumers can fold all `AACS_Verify` failures
through one branch), and `AacsError::ContentHashMismatch` (recomputed
`CHT_d` did not match a stored digest).

Companion integration test `tests/synth_round222_content_certificate.rs`
(6 cases) mints a synthetic AACS_CC ECDSA key pair, builds a
fully-populated layer-0 certificate over two synthetic Content Hash
Tables, and asserts that: the canonical `to_bytes` form round-trips
through `parse` byte-exact; the `verify_signature` check passes against
the synthetic public key; tampering one stored CHT digest breaks
`verify_signature`; tampering the on-disc CHT bytes breaks the
per-digest match; a wrong public key rejects the signature; `CHT_d` is
exactly 8 bytes; and `usage_rules_hash` is plain SHA-1 and
deterministic.

Lib-side test module (16 cases) covers
`ContentSequenceNumber::{from,to}_be_bytes` round-tripping across
boundary values, BD Format-Specific Section parse / round-trip /
truncated-prefix / short-trailer rejection, full-certificate round-trip,
unknown-`Certificate Type` rejection, the `(L + 2) ≡ 0 (mod 4)` length
alignment rule, signature-payload range, and the `L = 0` alignment-pad
path.

### Added — Round 211 AKE/EC runtime self-check entry points

New module `self_check` exposes runtime-callable self-check entry points
for the AACS 160-bit curve (Common Final 0.953 §2.3 Table 2-1) + the
§4.3 Drive-Host AKE state machine. A downstream consumer (e.g.
`oxideav-bluray`) can now validate the in-tree cryptographic primitives
before issuing a real SCSI command to a Licensed Drive, without itself
needing AACS LA key material or a real disc.

Four checks, callable independently or as a single cascade:

- **`curve_self_check()`** — Table 2-1 identity round-trip: generator
  `G` is on the curve, `n·G == O`, `G.double() == G + G`,
  `(a + b)·G == a·G + b·G` for two independent scalars, scalar
  `a · a⁻¹ ≡ 1 (mod n)`, and the affine→bytes→affine round-trip is
  identity.
- **`aacs_la_pub_self_check()`** — the bundled `AACS_LA_PUB_X` /
  `AACS_LA_PUB_Y` coordinates form a valid on-curve secp160r1 point, and
  the `aacs_la_pub_point()` helper agrees.
- **`ake_ecdh_self_check()`** — synthetic ECDH: `Dv = dk·G`, `Hv = hk·G`,
  then `lsb_128(x(hk·Dv)) == lsb_128(x(dk·Hv))` per §4.3 step 28/29; the
  agreed Bus Key is also checked non-degenerate (not all-zero).
- **`ake_full_self_check()`** — full §4.3 AKE end-to-end against a
  synthetic-LA-rooted in-process `MockDrive`: mints a synthetic AACS LA
  root, signs synthetic Drive + Host certificates, runs
  `host_authenticate` through an authenticating `DriveAuthState`, and
  asserts both sides derive the same 128-bit Bus Key. Exercises every
  Phase B + Phase C path in a single call.
- **`all_self_checks()`** — convenience wrapper running all four in
  sequence and short-circuiting on the first failure.

Failures surface as a new `AacsError::SelfCheckFailed { what:
&'static str }` variant carrying a tag for the failing identity (e.g.
`"n·G != point at infinity"`, `"ECDH bus keys disagree"`, `"host and
drive Bus Keys disagree after full §4.3 AKE"`).

Companion integration test `tests/synth_round211_self_check.rs` (6
cases) pins the per-function pass on a clean build and asserts the
cascade is idempotent across repeated invocations (no hidden RNG, no
stashed state). All values are synthesised in-source from constants — no
real AACS LA key material, no disc fixtures.

### Added — structured `ParseReport` for KEYDB.cfg + fuzz/robustness suite

The `KEYDB.cfg` parser already skipped malformed lines individually
rather than aborting the whole load, but the only way to find out
*what* was skipped was the `OXIDEAV_AACS_DEBUG=1` stderr toggle. Round
200 surfaces that information programmatically:

- **`KeyDb::parse_with_report(&str) -> Result<(KeyDb, ParseReport)>`**
  — same tolerant per-line semantics as `KeyDb::parse`; in addition,
  every non-empty / non-comment line the parser couldn't interpret is
  captured in a `ParseReport`. The report exposes:
  - `skipped: Vec<SkippedLine>` — 1-based `line_number`, 80-byte
    UTF-8-safe `snippet` of the offending line, and the
    `Display`-formatted `AacsError` `reason` returned by the per-line
    parser.
  - `is_clean()` / `skipped_count()` accessors.
- **`KeyDb::load_from_with_report(path)`** — same shape, reading from
  a filesystem path. Useful for diagnostic tooling that wants to show
  a "loaded N records, skipped M lines for the following reasons"
  summary instead of silently dropping records.
- **`KeyDb::parse(text)`** is unchanged behaviourally — it's now a
  thin discard of the report and continues to honour
  `OXIDEAV_AACS_DEBUG=1` for stderr mirroring.
- A new `truncate_excerpt` helper consolidates the UTF-8-boundary-safe
  snippet logic shared by `KeyDbParseError` / `HeaderParseError` so
  multi-byte codepoints can never be split by the 80-byte cap.

New public types `oxideav_aacs::{ParseReport, SkippedLine}`. No
behavioural change to any other crate API.

A companion integration test suite,
`tests/synth_round200_keydb_fuzz.rs` (27 cases, all synthetic),
provides "fuzz-equivalent" coverage by enumerating every structurally
distinct failure mode the parser exposes:

- Per-record-type malformations: short / long / odd-length /
  non-`0x`-prefixed hex literals, each required field missing, each
  named field at the wrong byte count, declared-vs-actual length
  mismatches for `HC` certificates.
- Scope rules: `VID` / `VUK` / `MEK` / `TK` / `KCD` rows outside any
  `DISCID` scope are rejected; a malformed `DISCID` invalidates the
  subsequent scoped rows.
- Lexical robustness: mixed CRLF / LF / lone-CR line endings, the
  printable-ASCII byte range as the first character of a line,
  multi-byte UTF-8 in record bodies (snippet truncation must not
  split codepoints), and a 10 KiB malformed line (the snippet must
  stay under 80 bytes).
- Composite: `ParseReport.skipped` line numbers come back in source
  order; comment-only / whitespace-only lines never appear in the
  report; a file of 26 unknown leaders all skip without aborting.

The suite pins three invariants: the parser never panics, never aborts
the whole load because of one bad line, and every skip is surfaced
through `ParseReport` exactly once.

## [0.1.2](https://github.com/OxideAV/oxideav-aacs/compare/v0.1.1...v0.1.2) - 2026-05-29

### Other

- Content Hash Table parse + Hash-Unit integrity verify (BD-Prerecorded §2.3)
- AACS_Verify integration for §3.2.5.1.2/.3/.8 signature records
- paraphrase external-implementation citations in src/
- READ_DISC_STRUCTURE Format 0x81/0x82/0x83 sub-payload constructors + parsers (AACS Common §4.14.3.2 / §4.14.3.3 / §4.14.3.4)
- Phase D: Type-4 MKB + Key Conversion Data post-processing (AACS Common 0.953 §3.2.5.1.4 + BD-Prerecorded §3.8)

### Added — Content Hash Table parsing + Hash-Unit integrity verification (BD-Prerecorded §2.3)

New `cht` module implementing the Content Hash Table (CHT) integrity
layer per AACS BD-Prerecorded Final 0.953 §2.3 — the per-Hash-Unit
SHA-1 check a Licensed Player runs over `\BDMV\STREAM` Clip AV data:

- **`cht::ContentHashTable::parse(bytes, number_of_digests,
  number_of_hash_units) -> Result<ContentHashTable>`** — parses a
  `ContentHash00N.tbl` per Table 2-2: a header of `Number_of_Digests`
  12-byte `ClipDescriptor` records (`Starting_HU_Num` / `Clip_Num` /
  `HU_Offset_in_Clip`, all 32-bit `uimsbf`) followed by
  `Number_of_HashUnits` 8-byte (`bslbf`) Hash Values. The two counts
  are NOT stored in the table file — they come from the per-layer
  Content Certificate (Table 2-1), so the parser takes them as
  arguments. Trailing `00`-padding is tolerated (authoring/mastering
  rule).
- **`cht::ContentHashTable::verify_hash_unit(index, hash_unit_bytes)
  -> Result<()>`** — recomputes `Hash_Value =
  [SHA-1(Hash_Unit)]_lsb_64` (§2.3.2.1, least-significant 8 bytes of
  the 20-byte SHA-1 digest) and compares it to the stored Hash Value.
  Per §2.3.2.1 the *encrypted* on-disc bytes are hashed, so this
  verifies integrity without a Title Key.
- **`cht::hash_value_of_unit(hash_unit) -> [u8; 8]`** — the standalone
  `[SHA-1(·)]_lsb_64` primitive (e.g. for a CHT author).
- **`cht::ContentHashTable::{len, is_empty}`** — a zero-byte CHT is
  valid for a layer with no Clip AV file ≥ 96 Logical Sectors.
- Size constants: `HASH_UNIT_SIZE` (96 × 2048 = 196608 bytes =
  exactly 32 Aligned Units, and 7 of them = the spec's 1344 KB
  minimum), `LOGICAL_SECTOR_SIZE` (2048), `LOGICAL_SECTORS_PER_HASH_UNIT`
  (96), `HASH_VALUE_SIZE` (8).

New error variants:

- `AacsError::BadHashUnitLength(usize)` — supplied Hash Unit was not
  exactly 196608 bytes.
- `AacsError::ContentHashMismatch { index }` — recomputed
  `[SHA-1(Hash_Unit)]_lsb_64` did not match the stored Hash Value.

Tests: 9 `cht` unit tests (size arithmetic, lsb-64 extraction,
header/body roundtrip, tamper / wrong-length / out-of-range / short-
buffer rejection, trailing-padding tolerance, zero-byte table) + 4
`tests/synth_cht.rs` integration tests (incl. one that builds a Hash
Unit from 32 freshly-encrypted Aligned Units and verifies the
encrypted bytes with no Title Key, then detects a single-byte flip).
All synthetic — no disc-derived material.

No docs gap: §2.3 (Table 2-2 syntax, §2.3.1 Hash-Unit geometry,
§2.3.2.1 `[SHA-1(Hash_Unit)]_lsb_64`) and the §2 "Logical Sector =
2048 bytes" definition in `AACS_Spec_BD_Prerecorded_Final_0_953.pdf`
are unambiguous. Standalone (`--no-default-features`) build still
passes.

### Added — AACS LA signature verification on MKB records (§3.2.5.1.2 / §3.2.5.1.3 / §3.2.5.1.8)

Wires the existing `ecdsa::verify` (`AACS_Verify`) primitive into the
MKB parser so callers that hold the AACS LA public key can check the
three MKB signatures the spec defines:

- **`Mkb::verify_end_of_block_signature(&self, original_bytes,
  aacs_la_pub) -> Result<()>`** — verifies the End-of-Media-Key-Block
  Record signature per Common spec §3.2.5.1.8
  (`AACS_Verify(AACS_LApub, Signature Data, MKB)`, where `MKB` is the
  byte range up to but not including the End-of-MKB record).
- **`Mkb::verify_host_revocation_list(&self, original_bytes,
  aacs_la_pub) -> Result<()>`** + the parallel
  **`verify_drive_revocation_list`** — verify the per-signature-block
  ECDSA signatures inside the HRL / DRL records (Common spec
  §3.2.5.1.2 / §3.2.5.1.3). Each block's signed-data range is the
  cumulative prefix "Type-and-Version Record || HRL/DRL record bytes
  up to the byte immediately preceding this signature", so block N's
  signature transitively also covers blocks 1..=N−1.
- **`Mkb::end_of_block_signature: Option<[u8; 40]>`** + the new
  **`RevocationSignatureBlock { entries_in_block, entries, signature
  }`** struct surfaced on `Mkb::host_revocation_blocks` /
  `drive_revocation_blocks` — both expose the raw 40-byte ECDSA
  signature(s) for callers that want to feed them to an external
  verifier.
- **`Mkb::type_and_version_raw: Vec<u8>`** — the on-wire bytes of the
  mandatory Type-and-Version Record (header included), preserved by
  the parser because §3.2.5.1.2 requires it as the first portion of
  the HRL / DRL signed data.

The parser still tolerates revocation blocks whose trailing signature
field is truncated (per §3.2.5.1.2 final paragraph — "hosts are
required to store only the data being signed for the first signature
block, but not required to store the signature itself"); the verifier
surfaces `AacsError::MkbSignatureMissing` rather than panicking on a
`None`-signature block.

This crate ships **no AACS LA public key**. AACS LA distributes
`AACS_LApub` to licensees only, so the verifier takes a `&Point`
parameter; callers obtain the key out-of-band. A non-licensed
deployment can still call the verifiers against a self-issued LA
identity (e.g. for end-to-end MKB-authoring tests).

New error variants:

- `AacsError::MkbSignatureMissing` — the requested signature record
  was absent or its payload was not the expected 40 bytes.
- `AacsError::MkbSignatureInvalid` — the signature was present but
  `AACS_Verify` rejected it under the supplied public key.

Tests:

- 8 new `mkb` unit tests covering: End-of-MKB sign-then-verify
  roundtrip, wrong-key rejection, prefix-tamper rejection, no-record
  → MkbSignatureMissing, non-40-byte payload → MkbSignatureMissing,
  single-block HRL verify roundtrip, DRL wrong-key rejection,
  no-signature-block-stored truncation tolerance, and a two-block
  cumulative-prefix HRL chain.
- 2 new integration tests in `tests/synth_round1_mkb_sig.rs` that
  build a full Type-and-Version + HRL + Verify-Media-Key +
  End-of-MKB byte stream through the public API and confirm both
  verifiers accept the legitimate signatures + reject a tampered
  buffer.

No docs gap; the spec text for all three signed-data ranges
(`docs/container/aacs/AACS_Spec_Common_Final_0953.pdf` §3.2.5.1.2
final paragraph, §3.2.5.1.3 second paragraph, §3.2.5.1.8 second
paragraph) is unambiguous. Standalone (`--no-default-features`)
build still passes.

### Added — `READ_DISC_STRUCTURE` Format `0x81`/`0x82`/`0x83` sub-payloads

Closes the §4.14.3.2 (Pre-recorded Media Serial Number / PMSN),
§4.14.3.3 (Media Identifier), and §4.14.3.4 (Media Key Block Pack)
sub-payload gap that Phase B left as Format-Code constants without
matching CDB constructors, response decoders, or `MockDrive` service.

- **`ReadDiscStructure::aacs_media_id(agid)`** — CDB builder for
  Format Code `0x82` (Media Identifier) per AACS Common §4.14.3.3
  Table 4-17. Same on-wire layout as the Volume Identifier and PMSN
  reads: 36-byte response with `[length=0x0022:u16][reserved:u16]
  [Media ID:16][MAC:16]`.
- **`parse_media_serial_response`** + **`MediaSerialNumberResponse`**
  — Format `0x81` decoder per Table 4-16. The MAC byte field is
  `Dm = CMAC(BK, PMSN)` per §4.5 step 3.
- **`parse_media_id_response`** + **`MediaIdentifierResponse`** —
  Format `0x82` decoder per Table 4-17 / Table 4-15 layout. The MAC
  is `Dm = CMAC(BK, MediaID)` per §4.6 step 3.
- **`parse_mkb_pack_response`** + **`MkbPackResponse`** — Format
  `0x83` decoder per Table 4-18, with variable-length pack body up
  to 32,768 bytes. Returns the `total_packs` count alongside the
  pack data. (Per §4.14.3.4 the MKB itself is *not* bus-encrypted —
  the spec note is explicit about this.)
- **`MockDrive`** grows four new fields — `media_serial_number`,
  `media_serial_mac`, `media_identifier`, `media_id_mac` — populated
  with deterministic patterns by `with_test_fixture()`. The
  `READ_DISC_STRUCTURE_OPCODE` dispatch arm now serves Format
  `0x81` and `0x82` with the same auth-vs-static MAC selection the
  Volume ID path already uses: when `auth.bus_key` is `Some`, the
  mock recomputes `Dm = CMAC(BK, ID)` per §4.5 / §4.6; otherwise it
  returns the fixture-MAC bytes.

New tests:

- 7 new unit tests in `mmc.rs`: PMSN/Media-ID CDB-byte-layout
  invariants, response-parser round trips, length-field /
  truncated-payload rejection, and the MKB-pack length-counting
  semantics.
- 4 new integration tests in `tests/synth_phaseb_mmc.rs`: PMSN +
  Media-ID `MockDrive` end-to-end round trips, an unknown-format
  rejection, and an MKB-pack hand-built-wire round trip (since the
  MKB body is not bus-encrypted, hand-stuffed wire bytes are the
  right level for the Phase B sub-payload layer).

No new dependencies, no `oxideav-core` API change, no docs-gap (all
three sub-payloads are in `docs/container/aacs/`
`AACS_Spec_Common_Final_0953.pdf` Tables 4-16 / 4-17 / 4-18). The
crate's standalone (no-default features) build still passes.

### Added — Phase D: Type-4 MKB + Key Conversion Data post-processing

Wires the AACS Common spec §3.2.5.1.4 + BD-Prerecorded §3.8 "Type-4
MKB / Media Key Precursor" path into the high-level `AacsVolume`
pipeline. Type-4 MKBs emit a Media Key *Precursor* `K_mp` from the
Subset-Difference walk rather than the Media Key directly; devices
that are required to use Key Conversion Data combine `K_mp` with the
disc's 16-byte KCD payload via `K_m = AES-G(K_mp, KCD)` before VUK
derivation. The KCD itself is sourced out-of-band (from the BD-ROM
KCD-Mark, surfaced in `oxideav-aacs` via the `| KCD |` row of a
`KEYDB.cfg` file → `DiscRecords::kcd`).

- **`subdiff::apply_key_conversion_data(kmp, kcd)`** — the
  `K_m = AES-G(K_mp, KCD)` primitive. Equivalent to
  `aes::aes_g(kmp, kcd)`; named separately for readability at the
  call site. Re-exported from the crate root.
- **`AacsVolume::derive_vuk_from_device_key_with_kcd(device, vol_id,
  kcd)`** — Type-4-aware VUK derivation implementing the spec's
  "verify-then-apply-KCD" decision tree:
  1. SD-walk to obtain the raw precursor (or Media Key for Type-3).
  2. If that value already verifies under the Verify Media Key Record
     (the spec's "old MKB" rule, §3.2.5.1.4 final paragraph), adopt
     it as `K_m` and skip KCD application — even if a KCD was
     supplied.
  3. Otherwise apply `AES-G(K_mp, KCD)` and re-verify; failure
     surfaces `MediaKeyVerificationFailed`.
- **`AacsVolume::derive_media_key_from_device_key(device)`** —
  exposed cryptographic primitive returning the raw SD-walk output
  (precursor for Type-4, Media Key for Type-3). Lets callers make
  the verify/KCD decision themselves rather than going through the
  higher-level `_with_kcd` helper.
- **`Mkb::is_verified_media_key(km) -> bool`** — boolean variant of
  the existing `verify_media_key`, returning `false` (rather than
  `MissingVerifyMediaKeyRecord`) when the `0x81` record is absent.
  The Type-4 decision path needs this distinction.
- **`MkbType::requires_kcd()`** + **`MkbType::as_u32()`** — predicate
  + wire-format inverse of the parser's `from_u32`.

`derive_vuk_from_device_key` is refactored on top of
`derive_media_key_from_device_key` + the existing
`Mkb::verify_media_key` so the Type-3 path is byte-identical to the
prior implementation.

New `tests/synth_phased_kcd.rs` (7 tests) pins:
- Type-4 + valid KCD round-trip → matching VUK.
- Type-4 + wrong KCD → `MediaKeyVerificationFailed`.
- Type-4 "old MKB" precursor-verifies-directly fallback (KCD ignored
  even when supplied).
- Type-4 without KCD when KCD was needed → error.
- Type-3 with a stray KCD argument → KCD ignored.
- `KCD` record loads from a synthetic `KEYDB.cfg`.
- Synthetic SD configuration sanity check.

Plus 5 new mkb unit tests covering `MkbType::requires_kcd`,
`MkbType::as_u32` round-trip, and `is_verified_media_key` edges.

No new external dependencies, no docs-gap (Common spec §3.2.5.1.1 +
§3.2.5.1.4 + BD-Prerecorded §3.8 are all in `docs/container/aacs/`),
no `oxideav-core` API change. The crate's standalone (no-default
features) build still passes.

## [0.1.1](https://github.com/OxideAV/oxideav-aacs/compare/v0.1.0...v0.1.1) - 2026-05-22

### Other

- Phase C: Drive-Host AKE + ECDSA-secp160r1 + Bus Key (AACS Common 0.953 §4.3)
- Phase B — SCSI MMC drive command layer (REPORT_KEY / SEND_KEY / READ_DISC_STRUCTURE)
- parse |-leader DK / PK / HC / DC / DISCID-scoped records (Phase A)
- disc_id is SHA-1(Unit_Key_RO.inf), not SHA-1(Volume_ID)
- disc_id_for_volume_id — SHA-1(volume_id) for KEYDB.cfg lookup
- fmt + tests: align integration tests with permissive parse
- tolerate sector-padding zeros after the End-of-MKB record

### Added — Phase C: Drive-Host Authentication & Key Exchange (AKE)

New `ec`, `ecdsa`, and `ake` modules implementing the AACS Common
Final 0.953 §4.3 "AACS Drive Authentication Algorithm" (Figure 4-9)
end-to-end on top of the Phase B MMC layer. All cryptography is
clean-room from the spec's published math (Table 2-1 curve parameters,
§2.3 ECDSA, §2.1.5 SHA-1, §2.1.6 CMAC); no external crypto-library
source (RustCrypto / OpenSSL / libaacs / …) was consulted. The
`openssl` CLI was used only as an opaque test-vector oracle, and the
ECDSA path is additionally cross-checked bit-exact against an
independent Python big-int reference.

- **`ec` module** — a 160-bit big-integer (`U160`, five `u32` limbs)
  and short-Weierstrass curve over `GF(p)` for the AACS curve
  (Table 2-1: `a = -3`, prime `p`, base point `G`, order `n`). Affine
  `add`/`double`/`is_on_curve` plus a Jacobian-coordinate
  `mul_scalar` (single final inversion). 40-byte EC-point encoding
  `x(20) || y(20)`.
- **`ecdsa` module** — `AACS_Sign` / `AACS_Verify` (X9.62 / FIPS
  186-2) with a clean-room FIPS 180-2 SHA-1 digest; 40-byte `r || s`
  signatures. A deterministic `k` helper (AES-H based, *not* RFC 6979)
  makes the synthetic test handshake reproducible. SHA-1 validated
  against the FIPS 180-2 `abc` / empty / two-block vectors; the full
  sign/verify against an independent Python reference vector.
- **`aes::aes_128_cmac`** — AES-128-CMAC (NIST SP 800-38B), validated
  against the SP 800-38B Appendix D.1 example MACs (empty / 1-block /
  partial / full-message).
- **`ake` module**:
  - `Certificate::parse` + `verify_signature` for the 92-byte Drive
    (Table 4-1) / Host (Table 4-2) certificates
    (`Type Flags Length ID Reserved PubKey(40) Sig(40)`), with the
    `Cert_sig = bytes 52..91` signed over `Cert = bytes 0..51`.
  - `build_signed_certificate` to mint synthetic LA-signed certs.
  - `host_authenticate` — the §4.3 Host state machine driving any
    `DriveCommand` transport through AGID → Host Cert Challenge →
    Drive Cert Challenge → Drive Key → Host Key → Bus Key.
  - `DriveAuthState` — the §4.3 drive side (verify Host Cert + Hsig,
    sign `Dsig` over `Hn || Dv`, derive `Dk·Hv`), wired into the
    Phase B `MockDrive` via its new `auth` field.
  - `bus_key_from_point` — `BK = [x-coordinate of shared point]
    lsb_128` (§4.3 steps 28/29).
  - `read_verified_volume_id` — §4.4 Volume ID transfer with
    `Dm = CMAC(BK, Volume_ID)` host-side verification.
- New `AacsError` variants:
  `DriveCertSignatureInvalid`, `HostCertSignatureInvalid`,
  `DriveSignatureInvalid`, `HostSignatureInvalid`, `VolumeIdMacInvalid`.
- New integration suite `tests/synth_phasec_ake.rs` (5 tests): full
  synthetic-cert AKE round-trip with matching Host/Drive Bus Keys,
  §4.4 Volume ID verification, and rejection of a wrong-LA Drive cert,
  a wrong-LA Host cert, and a tampered Volume ID MAC.

**Note on the Bus Key KDF.** The task brief mentioned a possible
"AES-G / SHA-1 KDF" for the Bus Key; AACS Common Final 0.953 §4.3
steps 28/29 in fact define the Bus Key directly as the least
significant 128 bits of the x-coordinate of the shared ECDH point
(`Dk·Hv` / `Hk·Dv`) — no AES-G/SHA-1 post-derivation. This module
implements per the spec; the §4.4+ ID transfers then key AES-CMAC
under that Bus Key.

### Added — Phase B: SCSI MMC drive-command wire layer

New `mmc` module implementing the byte-level encoding/parsing for the
three SCSI MMC commands an AACS host needs to converse with a Licensed
Drive. Wire formats are taken from the publicly-hosted T10 working
drafts now staged at `docs/container/aacs/mmc/` (MMC-6 r02g, SPC-3 r23)
cross-referenced against AACS Common Final 0.953 §4.1–§4.14. No
external library source (libaacs / libbluray / etc.) was consulted.

- **Typed CDB constructors**, each emitting a 12-byte `[u8; 12]` block
  per MMC-6 Tables 381 / 513 / 599:
  - `ReportKey::{aacs_agid, aacs_drive_cert_challenge,
    aacs_drive_key, aacs_drive_cert, aacs_invalidate_agid}`.
  - `SendKey::{aacs_host_cert_challenge, aacs_host_key,
    aacs_invalidate_agid}`.
  - `ReadDiscStructure::{aacs_volume_id, aacs_media_serial,
    aacs_media_key_block_pack}`.
  - `parse_cdb()` inverse for each, used by the synthetic mock drive
    and by tests.
- **AACS sub-payload codecs** for the AKE round-trip:
  - `parse_report_key_agid` / `parse_report_key_drive_cert_chal` /
    `parse_report_key_drive_key` / `parse_report_key_drive_cert` —
    drive-to-host responses per AACS Common Tables 4-7, 4-8, 4-9 and
    MMC-6 Table 531.
  - `parse_volume_id_response` — 36-byte READ DISC STRUCTURE
    Format 0x80 reply per AACS Common Table 4-15
    (`[u16=0x0022][rsvd:u16][Volume ID:16][MAC:16]`).
  - `build_send_key_host_cert_chal` / `build_send_key_host_key` and
    their `parse_*` inverses — host-to-drive parameter lists per
    AACS Common Tables 4-24, 4-25 (`Hn || Cert_h` and `Hv || Hsig`
    respectively).
- **`DriveCommand` trait** abstracting the SCSI pass-through surface
  so platform-specific back-ends (macOS `IOSCSITaskDeviceInterface`,
  Linux `SG_IO`, Windows `IOCTL_SCSI_PASS_THROUGH_DIRECT`) can be
  written against a single contract once Phase C lands. Carries a
  `DataDirection` enum + `ScsiResponse { status, data }`.
- **`MockDrive`** in-process fixture implementing `DriveCommand`,
  populated with a deterministic synthetic Drive Certificate /
  Volume ID / nonces so tests can assert exact byte layouts.

Public re-exports added to `lib.rs` (`mmc` module + the typed
structures and parsers).

### Documentation gaps surfaced

- The workspace `docs/container/aacs/mmc/README.md` "AACS commands at
  a glance" section confuses two different command surfaces: it lists
  AACS Volume ID under "REPORT KEY Key Class=0x02 Key Format 0x12",
  but per MMC-6 Table 525 the REPORT KEY Key Class 0x02 Key Format
  table only defines 0x00 / 0x01 / 0x02 / 0x20 / 0x21 / 0x38 / 0x3F.
  The Volume Identifier in fact ships via `READ_DISC_STRUCTURE`
  Format Code 0x80 (MMC-6 Table 384 / AACS Common Table 4-15). This
  Phase B implementation follows the spec tables; the README would
  benefit from a follow-up edit clarifying which list belongs to
  which command.

### Tests

- 5 new `mmc` unit tests pinning the CDB byte layouts (opcode, Key
  Class, Allocation/Parameter-List Length packing, AGID bit packing).
- 13 new `tests/synth_phaseb_mmc.rs` integration tests round-tripping
  the AGID / Drive Cert Challenge / Drive Key / Drive Cert /
  Host Cert Challenge / Host Key / Volume ID / Invalidate-AGID flows
  through `MockDrive`.

### Out of scope (deferred to Phase C/D)

- ECDSA-secp160r1 sign/verify primitives needed for the cryptographic
  half of the AKE (Common spec §4.3 steps 9, 16, 18, 25, 27).
- `AES_G` / SHA-1-based Bus Key derivation from `Hk*Dv` / `Dk*Hv`.
- Actual hardware transport: macOS IOKit, Linux SG_IO, Windows IOCTL
  back-ends implementing `DriveCommand` against a real `/dev/sr0` /
  `IOSCSITaskDeviceInterface` / `IOCTL_SCSI_PASS_THROUGH_DIRECT`.
- Phase D: wiring the AKE + Bus-Key-protected reads into
  `oxideav-bluray` for unencrypted-at-rest disc playback.

### Added — Phase A: KEYDB.cfg `|`-leader header records

`KeyDb::parse` now recognises the `|`-leader record form documented in
`docs/container/aacs/keydb-cfg-format.md`, in addition to the
pre-existing per-disc `<DISC_ID>=V <VUK>` lines. New record types:

- `| DK |` Device Key (`DEVICE_KEY` + `DEVICE_NODE` + `KEY_UV` +
  `KEY_U_MASK_SHIFT`) — pins a key into the AACS Subset-Difference
  tree. Surfaced via `KeyDb::device_keys()`.
- `| PK |` Processing Key (16-byte AES-128) — the SD-tree walk output
  for a specific MKB. Surfaced via `KeyDb::processing_keys()`.
- `| HC |` Host Certificate + private key — 20-byte ECDSA-secp160r1
  scalar + variable-length signed cert. Parser validates the embedded
  `length` field (cert offset 2..4, big-endian) against the actual
  buffer length per AACS Common Final 0.953 §A.1; exposes `host_id()`,
  `cert_type()`, `declared_length()`. Surfaced via
  `KeyDb::host_certs()`.
- `| DC |` Drive Certificate + private key (drive side of the
  Drive-Host auth). Surfaced via `KeyDb::drive_certs()`.
- `| DISCID |` introduces a per-disc record-set scope; subsequent
  `| VID |`, `| VUK |`, `| MEK |`, `| TK |`, `| KCD |` rows attach to
  it. Surfaced as `DiscRecords` via `KeyDb::disc_records()` /
  `KeyDb::disc_record(&id)`.

`KeyDb::vuk_for_disc` now also looks through the `DISCID`-scoped
record map, so both legacy and `|`-leader files yield the same lookup
behaviour.

New `AacsError::HeaderParseError(String)` variant for malformed
`|`-leader lines.

Legacy per-disc lines continue to parse byte-identically (a dedicated
`legacy_only_file_unchanged` unit test pins this).

## [0.1.0](https://github.com/OxideAV/oxideav-aacs/compare/v0.0.1...v0.0.2) - 2026-05-17

### Other

- parse the extended libbluray/aacskeys KEYDB.cfg format
- probe ~/Library/Preferences/aacs/KEYDB.cfg on macOS

### Added

- macOS-native search path: `KeyDb::load_default()` now also probes
  `$HOME/Library/Preferences/aacs/KEYDB.cfg` ahead of the XDG fallbacks
  on `target_os = "macos"`. Matches the convention libbluray + similar
  tools use on Apple platforms — users no longer need to set
  `XDG_CONFIG_HOME` (or fall back to `~/.config/aacs/`) just to be
  found.

### Added — Round 1 (bootstrap, clean-room AACS Common + BD-Prerecorded 0.953)

Initial pure-Rust AACS decryption library. All spec references are to
the publicly-published AACS LA PDFs in the workspace's
`docs/container/aacs/` directory (`AACS_Spec_Common_Final_0953.pdf`
and `AACS_Spec_BD_Prerecorded_Final_0_953.pdf`). This is a clean-room
implementation; no `libaacs` / `aacskeys` / `libbluray` / `makemkv`
source was consulted.

- **Crypto primitives** (Common spec §2.1):
  - `aes::aes_128_ecb_encrypt` / `aes_128_ecb_decrypt` thin wrappers
    around the RustCrypto `aes` crate's `BlockEncrypt`/`BlockDecrypt`
    so the rest of the crate doesn't have to import the trait every
    time.
  - `aes::aes_128_cbc_decrypt` / `aes_128_cbc_encrypt` with explicit
    16-byte IV (the AACS default IV constant `IV0 =
    0BA0F8DDFEA61FB3D8DF9F566A050F78` is exposed as `aes::IV0_AACS`).
  - `aes::aes_g(x1, x2) = AES-128D(x1, x2) XOR x2` per Common spec
    §2.1.3 — the AACS-specific one-way function used to derive child
    keys and to mix Volume ID into the VUK.
  - `aes::aes_h(data)` per Common spec §2.1.4 — AES-G-based hash with
    SHA-1-style padding and the AACS `h0` IV constant
    `2DC2DF39420321D0CEF1FE2374029D95`. Implemented inline (no
    external SHA dep).
- **Subset-Difference tree** (Common spec §3.2.1 — §3.2.4):
  - `subdiff::aes_g3` triple-AES generator per Common spec §3.2.2,
    Figure 3-3, with the seed register IV constant
    `s0 = 7B103C5DCB08C4E51A27B01799053BD9`. Returns the three
    128-bit outputs (left subsidiary key, processing key, right
    subsidiary key).
  - `subdiff::SubsetDifference { u_mask, uv }` and
    `subdiff::applies_to_device(sd, d_node)` per Common spec
    §3.2.4 — the `(D_node & m_u) == (uv & m_u) && (D_node & m_v) !=
    (uv & m_v)` test that picks the subset-difference covering a
    given device.
  - `subdiff::derive_processing_key(device_key, stored_uv, stored_u_mask,
    stored_v_mask, target_uv, target_v_mask)` per Common spec
    §3.2.4 procedure (steps 1 — 4): walk down the tree from the
    stored Device Key's u-node toward the target v-node by repeated
    AES-G3 left/right child derivation, ending at the appropriate
    Device Key for the target subset-difference; return the
    Processing Key.
  - `subdiff::media_key_from_processing_key(processing_key, target_uv,
    encrypted_media_key_data)` per Common spec §3.2.4 end:
    `Km = AES-128D(Kp, C) XOR (0 || uv)`.
- **MKB parser** (Common spec §3.2.5):
  - `mkb::Mkb::parse(bytes)` walks the contiguous record stream and
    decodes:
    - `0x10` Type and Version Record (§3.2.5.1.1) — MKBType + Version
      Number.
    - `0x21` Host Revocation List Record (§3.2.5.1.2) — multi
      signature-block layout with `Range || HostID` 8-byte entries.
    - `0x20` Drive Revocation List Record (§3.2.5.1.3) — identical
      layout, different IDs.
    - `0x81` Verify Media Key Record (§3.2.5.1.4) — 16-byte ciphertext
      `Vd`, used to confirm a derived Media Key.
    - `0x04` Explicit Subset-Difference Record (§3.2.5.1.5) — 5-byte
      `(u_mask, uv)` entries.
    - `0x07` Subset-Difference Index Record (§3.2.5.1.6) — speed-up
      lookup; 4-byte span + 3-byte offsets.
    - `0x05` Media Key Data Record (§3.2.5.1.7) — 16-byte entries,
      one per explicit subset-difference, in matching order.
    - `0x0C` Media Key Variant Data Record (§3.2.5.2.1) — Class II
      MKB only.
    - `0x0D` Variant Number Record (§3.2.5.2.2) — Class II MKB only.
    - `0x02` End of Media Key Block Record (§3.2.5.1.8) — closes the
      block.
  - Unknown record types are ignored per spec §3.2.5 ("if a device
    encounters a Record with a Record Type field value it does not
    recognize, that is not an error; it shall ignore that Record and
    skip to the next").
  - `Mkb::verify_media_key(km)` cross-checks a derived Media Key
    against the `Verify Media Key Record`.
- **Unit Key file parser** (BD-Prerecorded spec §3.9.3):
  - `unit_key::UnitKeyFile::parse(bytes)` decodes the 32-bit
    `Unit_Key_Block_start_address`, the `Unit_Key_File_Header()`
    (Application_Type, Num_of_BD_Directory, Use_SKB_Unified_MKB_Flag,
    per-directory CPS_Unit_number assignments for First Playback /
    Top Menu / Titles), and the `Unit_Key_Block()` (Num_of_CPS_Unit
    + per-unit `MAC_of_PMSN || MAC_of_DeviceBindingNonce ||
    EncryptedCpsUnitKey`).
  - Tolerates the 65536-byte alignment and zero-padding requirement
    per spec note (*1) / (*2).
- **AACS directory walker** (BD-Prerecorded spec §3 + Figure 3-5):
  - `volume::AacsVolume::open(disc_root)` looks for `AACS/MKB_RO.inf`
    and `AACS/Unit_Key_RO.inf` under the supplied disc-mount root,
    falling back to `AACS/DUPLICATE/` if the primary copies are
    missing.
  - `volume::AacsVolume::cps_units()` returns the per-CPS-Unit
    metadata (encrypted title-key blob), pre-VUK.
  - `volume::AacsVolume::unwrap_title_keys(vuk)` walks every CPS unit
    and decrypts `EncryptedCpsUnitKey = AES-128E(Kvu, Kcu)` to recover
    `Kcu` per BD-Prerecorded §3.9.3.
- **VUK derivation** (BD-Prerecorded spec §3.3):
  - `vuk::derive_vuk(media_key, volume_id) = AES-G(Km, IDv)` —
    `AES-128D(Km, IDv) XOR IDv`.
- **Content scrambling** (BD-Prerecorded spec §3.10):
  - `content::decrypt_aligned_unit(cps_unit_key, unit_bytes)` decrypts
    a 6144-byte Aligned Unit. Computes
    `BlockKey = AES-128E(Kcu, seed) XOR seed` from the first 16 bytes
    (the cleartext "seed") per Figure 3-8, then AES-128-CBC-decrypts
    the remaining 6128 bytes under `BlockKey` with the AACS default
    IV (`IV0`).
  - `content::encrypt_aligned_unit(cps_unit_key, unit_bytes)`
    round-trip companion (used by the test suite to construct
    fixtures from known plaintext).
- **KEYDB.cfg parser**: the community-format VUK key database used by
  libbluray / similar OSS tools. Format implemented from the de-facto
  public description (the line layout `DISC_ID = V VUK | label` plus
  `;`-comments and blank lines); no source from those projects was
  consulted.
  - `keydb::KeyDb::parse(text)` accepts a string.
  - `keydb::KeyDb::load_from(path)` reads from a file.
  - `keydb::KeyDb::load_default()` walks the XDG search order:
    `OXIDEAV_AACS_KEYDB` env override first, then
    `$XDG_CONFIG_HOME/aacs/KEYDB.cfg`, then each entry in
    `$XDG_CONFIG_DIRS` (`:`-split), then `~/.config/aacs/KEYDB.cfg`
    as the conventional fallback.
  - `keydb::KeyDb::vuk_for_disc(&[u8; 20])` looks up a VUK by Disc
    ID; case-insensitive on the hex.
- **Volume integration**:
  - `volume::AacsVolume::resolve_vuk_from_keydb(&KeyDb)` — convenience
    for the KEYDB.cfg-based flow that doesn't need an active MKB walk.
  - `volume::AacsVolume::derive_vuk_from_device_key(&DeviceKey)` —
    full MKB walk using a Device Key from a manually-loaded key set.

### Test fixtures (synthetic only, no real disc keys)

- `tests/synth_round1_keydb.rs` — KEYDB.cfg parser positive +
  negative cases (comments, blank lines, lowercase hex, malformed
  lines).
- `tests/synth_round1_mkb.rs` — hand-crafted Type-3 MKB built record
  by record per spec §3.2.5; verifies type tag, version, every record
  is round-tripped through the parser, `verify_media_key()` accepts
  the correct Km and rejects a flipped bit.
- `tests/synth_round1_subdiff.rs` — minimal Subset-Difference tree
  walk: synthetic Device Key + uv path, single AES-G3 step, asserts
  the derived Processing Key matches the spec equation.
- `tests/synth_round1_content.rs` — round-trip of
  `encrypt_aligned_unit` -> `decrypt_aligned_unit` with a randomly
  generated CPS Unit Key + random seed + random plaintext payload;
  also asserts that a single-bit flip in the ciphertext changes the
  decryption.
- `tests/synth_round1_unit_key.rs` — hand-crafted Unit_Key_RO.inf
  built per spec §3.9.3 with 2 CPS units; verifies header decode and
  that `unwrap_title_keys(vuk)` recovers the matching Kcu values.
- `tests/synth_round1_volume.rs` — synthetic `AACS/` directory layout
  (MKB_RO.inf + Unit_Key_RO.inf) under a `tempdir()`; verifies
  `AacsVolume::open` finds both, that VUK from KEYDB.cfg unwraps the
  title keys, and that `decrypt_unit` on a freshly-encrypted aligned
  unit recovers the plaintext.

### Documentation gaps surfaced

- The Common spec doesn't include a worked numerical example for any
  of: AES-G3 with the published `s0`, Subset-Difference tree walk,
  Verify Media Key Record cross-check, or AES-G as
  `AES-128D(x1, x2) XOR x2`. Tests roundtrip our own
  generate/parse/derive paths but cannot cross-check against a
  third-party reference vector. A docs-collaborator-supplied test
  vector for AES-G3 (e.g., a known Device Key and the resulting
  Processing Key it derives) would close this gap.
- KEYDB.cfg is a de-facto community format; AACS LA does not specify
  it. The exact whitespace tolerance / comment grammar implemented
  here is what the parser accepts, and may diverge from what
  libbluray would accept in obscure edge cases.

### Out of scope

- Bus-encryption (BD-Prerecorded §3.7) — applies only to the SCSI
  bus between a Licensed Drive and PC Host; irrelevant when reading
  decrypted-at-rest disc images.
- Drive / Host authentication (Common spec ch. 4) — same reason.
- ECDSA signature verification of the MKB / HRL / DRL
  (`AACS_Verify(AACS_LA_pub, ...)`) — the spec defines these but we
  don't need them to derive Km. Could be added later if validation
  becomes important.
- Content Hash Table verification (BD-Prerecorded §2.3) — SHA-1 of
  Hash Units; structurally documented but not implemented.
- AACS 2.0 (Ultra HD Blu-ray) — separate spec family, not publicly
  released.
- BD+ — separate copy-protection layer, not publicly specified.
