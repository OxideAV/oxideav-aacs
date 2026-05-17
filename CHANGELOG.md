# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
