# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2](https://github.com/OxideAV/oxideav-aacs/compare/v0.1.1...v0.1.2) - 2026-05-27

### Other

- Phase E — Content Hash Table parser + SHA-1 hash-unit verification (BD-Prerecorded 0.953 §2.3)
- Phase D: Type-4 MKB + Key Conversion Data post-processing (AACS Common 0.953 §3.2.5.1.4 + BD-Prerecorded §3.8)

### Added — Phase E: Content Hash Table parser + SHA-1 hash-unit verification

Implements the integrity-check half of AACS BD-Prerecorded Final
0.953 §2.3. A Licensed Player verifies on-disc Clip AV stream bytes
by SHA-1-hashing 96-Logical-Sector "Hash Units" of the *encrypted*
stream and comparing the least-significant 64 bits of each digest
against the `Hash_Value` stored in `AACS/ContentHashNNN.tbl`.

- **`cht` module** — new top-level module:
  - `ContentHashTable::parse(bytes, number_of_digests,
    number_of_hash_units)` per Table 2-2 syntax. Both counts are
    supplied by the caller because they live in the Content
    Certificate (`Content000.cer` / `Content001.cer`, §2.1 Table 2-1),
    not in the `.tbl` file itself.
  - `compute_hash_value(hash_unit) = [SHA-1(hash_unit)]_lsb_64` per
    §2.3.2.1 — bytes 12..20 of the 20-byte SHA-1 digest.
  - `HASH_UNIT_SIZE = 96 * 2048 = 196 608` bytes per §1.7 ("Hash
    Unit: A Hash Unit consists of a series of 96 Logical Sectors").
  - `DigestRecord { starting_hu_num, clip_num, hu_offset_in_clip }`
    — one row per Clip AV stream file ≥ 96 Logical Sectors.
  - `ContentHashTable::lookup_hash_value(clip_num, hu_in_clip)` —
    handles the §2.3.1 dual-layer "resume offset" case where Layer 1's
    `HU_Offset_in_Clip` is the count of HashUnits already covered on
    Layer 0, returning `None` for in-clip indices owned by the other
    layer.
  - `ContentHashTable::verify_hash_unit(clip_num, hu_in_clip,
    hash_unit)` — full lookup-then-compare; rejects wrong-sized Hash
    Units, unknown `(clip_num, hu_in_clip)`, and SHA-1 mismatches.

- **`AacsVolume::load_content_hash_table(layer, n_digests, n_hus)`** —
  reads `AACS/ContentHash000.tbl` (`layer = 0`) or
  `ContentHash001.tbl` (`layer = 1`) with `AACS/DUPLICATE/` fallback,
  matching the `MKB_RO.inf` / `Unit_Key_RO.inf` discovery. Higher
  layer numbers reject with `AacsError::InvalidValue` since BD9/BD25
  are at most dual-layer per §1.9.

- **New `AacsError::ContentHashMismatch { clip_num, hu_in_clip }`** —
  carries the failing `(clip_num, hu_in_clip)` so a caller can
  correlate the mismatch with the on-disc
  `BDMV/STREAM/<clip_num:05>.m2ts`.

Empty (`size = 0`) CHTs paired with `(0, 0)` counts parse cleanly per
§2.3.1 ("the size of CHT is zero bytes if there is no Clip AV stream
that has a file greater than or equal to 96 Logical Sectors on the
corresponding layer"). Authoring-tail zero padding after the body is
tolerated.

#### Out of scope (this phase)

- **Content Certificate (Table 2-1) parsing + `AACS_Verify` over the
  `Content000.cer` signature data.** The certificate carries the per-
  layer `Number_of_Digests` / `Number_of_HashUnits` that this CHT
  parser consumes, but its outer ECDSA signature needs the AACS LA
  root public key — out of scope for the same reason as the MKB's
  `AACS_Verify`. Phase E callers supply the two counts directly.
- **Content_Hash_Table_Digest cross-check (§2.3.2).** The Content
  Certificate stores a SHA-1 over each layer's Hash_Values array
  (`Content Hash Table Digest #N`); confirming this match needs the
  certificate parser landed first.
- **§2.3.3 verification policies** (random 7-of-N sampling on title
  start, ≥1% sampling during playback) — playback-loop concerns, not
  the CHT primitive itself.

#### Tests

- 13 new `cht` unit tests covering parse round-trip, zero-sized CHT,
  authoring zero-padding tolerance, truncation rejection, non-zero
  trailing junk rejection, `compute_hash_value` SHA-1 lsb_64
  equivalence, single-clip indexing, dual-layer resume offset,
  two-clips-on-one-layer indexing, verify round-trip, tamper
  detection, wrong-sized input rejection, unknown-clip rejection.
- 6 new `tests/synth_round2_cht.rs` integration tests round-tripping
  the parser through `AacsVolume::load_content_hash_table` with
  primary-and-DUPLICATE-fallback fixtures, dual-layer authoring,
  zero-sized CHT, invalid-layer rejection, and an end-to-end "build
  two Hash Units, author the CHT, parse via the volume, verify both
  → tamper one → assert `ContentHashMismatch` with the failing
  `(clip_num, hu_in_clip)`" scenario.

No new external dependencies. No `oxideav-core` API change. The
standalone (`--no-default-features`) build still passes.

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
