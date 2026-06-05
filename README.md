# oxideav-aacs

Pure-Rust, clean-room implementation of the **AACS** (Advanced Access
Content System) decryption layer used by Blu-ray Disc, per the
publicly-published AACS LA technical specifications **Common Final
0.953** (Oct 2012) and **BD-Prerecorded Final 0.953** (Oct 2012).

Round 240 adds the **REPORT KEY Binding Nonce** sub-payload pair
(Key Format `0x20` / `0x21`) per AACS Common §4.14.2.4 Table 4-10
and §4.14.2.5 Table 4-11. The two named constants
`KF_REPORT_AACS_BINDING_NONCE_GEN` (`0x20`) and
`KF_REPORT_AACS_BINDING_NONCE_READ` (`0x21`) have been declared since
round 93's Phase B wire layer landed; round 240 fills in the typed
constructor + parser surface around them:

- **`ReportKey::aacs_binding_nonce_gen(agid, starting_lba, block_count)`** —
  generate-and-store CDB constructor (§4.7.1). The LBA Extent triple
  lands in CDB bytes 2..5 (big-endian) and byte 6 per AACS Common
  §4.14.2 final paragraph.
- **`ReportKey::aacs_binding_nonce_read(agid, starting_lba, block_count)`** —
  read-from-medium CDB constructor (§4.7.2). Same CDB wire layout;
  the Key Format field is the spec's only distinguishing bit.
- **`BindingNonceResponse { binding_nonce: [u8; 16], mac: [u8; 16] }`** +
  **`parse_report_key_binding_nonce(buf)`** — decoded response. Both
  Key Formats share the 36-byte wire layout
  `[length:u16=0x0022][reserved:u16][nonce:16][mac:16]`.
- **`BINDING_NONCE_LEN`** = 16, **`BINDING_NONCE_MAC_LEN`** = 16.

The 16-byte MAC is `Dm = CMAC(BK, Nonce)` under the §4.3-derived Bus
Key per the §4.7.1 / §4.7.2 transferred-binding-nonce protocol; the
caller verifies it against its own `Hm = CMAC(BK, Nonce)` after
deriving the Bus Key from the AKE. `MockDrive` dispatches both Key
Formats, records the `(key_format, starting_lba, block_count)` triple
in `last_binding_nonce_op`, and in `auth` mode recomputes the MAC
under the synthetic Bus Key.

Round 236 adds three small typed accessors that surface
Type-and-Version Record fields parsed under Common §3.2.5.1.1 /
Table 3-2 (`MKBType: 000x_1003₁₆`, `Version Number`):

- **`MkbType::has_aacs_marker() -> bool`** — verifies the on-wire
  field's low 16 bits match the spec-mandated `0x1003` marker. Useful
  when a caller wants to assert well-formedness on a value carried
  through the `Other(u32)` catch-all (the parser does not reject
  non-marker values; §3.2.5 leaves the behaviour for an improperly
  formatted MKB "manufacturer specific").
- **`MkbType::generation() -> Option<u8>`** + the convenience
  **`Mkb::generation() -> Option<u8>`** — the high-byte of the MKBType
  field as a generation number (`3`, `4`, or `10` for the three
  spec-defined values; forward-compat with hypothetical higher
  generations as long as the `0x1003` marker is intact). `None` when
  the marker doesn't match.
- **`Mkb::is_test_mkb() -> bool`** — the Common-spec §3.2.5.1.1
  Version-Number-`0` test-MKB sentinel.

Round 229 adds the **Content Revocation List** parse / per-segment
ECDSA verify / revocation-record lookup path per Pre-recorded Video
Book §2.7 (Tables 2-2 / 2-3 / 2-4 / 2-5), closing the Out-of-scope
revocation gap that round 222's Content Certificate layer left as
"future work". Module [`crl`] now exposes:

- **`ContentRevocationList::parse(bytes)`** — parses a
  `ContentRevocation.lst` blob into its CRL Header (`List Type`,
  `List Version`, `Number of Segments`) and the `N` CRL Segments, each
  of which carries a `Segment Size`, a sequence of structured
  `RevocationRecord`s, and the trailing 40-byte Entity Signature. The
  PVB §2.2 trailing-`0x00`-padding rule is enforced; the PVB §2.7
  first-segment 128 KiB cap is enforced.
- **`RevocationRecord`** — structured decode of every spec-defined
  Record Type:
  - `ContentCertificateId { range, id }` (PVB Table 2-3,
    `Record_Type == 0x0`) — 12-bit range + 6-byte Content Certificate
    ID with the spec's "`range == 0` revokes only this ID" semantics
    and `range > 0` revoking the inclusive `[id, id + range]` span.
  - `ManagedCopyServerCertificateId { range, id }` (PVB Table 2-4,
    `Record_Type == 0x1`).
  - `RecordableMedia(RecordableMediaRevocation { iccid, media_type,
    content_certificate_id, media_id })` (PVB Table 2-5, the
    three-contiguous-record `0x2 / 0x3 / 0x4` RMRR layout folded into
    a single high-level record, with the spec's `1 + 3 + 4 + 7 + 7`
    bit/byte split correctly reassembled).
  - `Unknown { record_type, bytes }` per PVB §2.7 ("If a Licensed
    Product encounters a Revocation Record with a Record_Type value
    it does not recognize, the record shall be ignored.") — preserved
    so a forward-compatibility record doesn't cause adjacent valid
    records to be silently dropped.
- **`ContentRevocationList::verify_segment_signature(k, aacs_la_pub)`**
  + **`verify_last_segment_signature`** + **`verify_all_segments`** —
  `AACS_Verify(AACS_LApub, CRL_Segsig, CRL_Seg)` per PVB §2.7 with the
  cumulative-prefix semantics ("the signature includes all previous
  fields including previous Segments and the CRL Header"). Verifying
  the last segment alone validates every preceding segment.
- **`ContentRevocationList::is_content_certificate_id_revoked(id)`**
  + **`is_managed_copy_server_id_revoked(id)`** — global revocation
  queries that walk every segment's records and apply the
  spec-defined range semantics; the
  `is_content_certificate_id_revoked` query also surfaces the
  embedded Content Certificate IDs inside `RecordableMedia` records
  whose ICCID flag is `0`.
- **`ContentRevocationList::recordable_media_revoked(media_type,
  media_id, content_certificate_id)`** — the four-step §2.7.2
  (Prepared Video book) applicability check for a `(type, media_id,
  content_certificate_id)` triple, honouring the ICCID-flag `0/1`
  branch.
- **`ContentRevocationList::to_bytes`** — byte-exact round-trip with
  `parse` for any value that parses cleanly (used by the test
  fixture builder to mint signed synthetic CRLs).

No real AACS LA Entity public key — AACS LA distributes it only to
licensees — so `verify_*` takes a caller-supplied `&ec::Point`. The
crate ships no real disc fixture; the integration suite mints a
synthetic LA identity and a three-segment CRL covering every defined
record type, including the Table 2-5 RMRR with both ICCID-flag values.

Round 222 added the **signed Content Certificate** parse/verify path
per Pre-recorded Video Book §2.4 / §2.5 / §2.6, with the BD-Prerecorded
Final 0.953 Table 2-1 Format-Specific Section decoded out. Module
[`content_certificate`] exposes:

- **`ContentCertificate::parse(bytes)`** — parses one `Content00N.cer`
  blob into its header (Certificate Type, BEE flag,
  `Total_Number_of_HashUnits`, `Total_Number_of_Layers`,
  `Layer_Number`, `Number_of_HashUnits`, `Number_of_Digests`,
  `Applicant ID`, `Content Sequence Number`, `Minimum CRL Version`),
  the variable-length `Format_Specific_Section`, the
  `Number_of_Digests` 8-byte `Content Hash Table Digest`s, and the
  40-byte `Signature Data`. The `Length_Format_Specific_Section`
  4-byte-alignment rule (PVB §2.4) is enforced; the `L = 0`
  alignment-pad case is accepted.
- **`ContentCertificate::verify_signature(aacs_cc_pub)`** —
  `AACS_Verify(AACS_CC_pub, Signature_Data, CC)` over the certificate
  bytes up to but excluding the trailing 40-byte signature
  (PVB §2.5 step 4 / §2.6 step 5).
- **`ContentCertificate::content_hash_table_digest(cht_bytes)`** /
  **`verify_content_hash_table_digest(digest_index, cht_bytes)`** —
  recomputes `CHT_d = [SHA-1(CHT)]_lsb_64` (PVB §2.5 step 3 / §2.6
  step 3) and matches it against the per-layer digest stored in the
  certificate.
- **`ContentCertificate::content_certificate_id()`** — returns the
  6-byte Content Certificate ID = `Applicant_ID || Content Sequence
  Number` per PVB §2.4; the lookup key for PVB Table 2-3 Revocation
  Records.
- **`ContentSequenceNumber`** — structured decoder for the 32-bit
  Content Sequence Number bit layout from BD-Prerecorded Table 2-1
  (6-bit CCSS ID, 15-bit Timestamp, 11-bit Sequence Number from
  `Sequence Number 1(4) || Sequence Number 2(7)`), with a re-encoder
  for round-trip authoring.
- **`BdFormatSpecificSection::parse(bytes)`** — decodes the
  BD-Prerecorded Table 2-1 Format-Specific Section into
  `Hash_Value_of_MC_Manifest_File`, `Hash_Value_of_BDJ_Root_Cert`,
  `Num_of_CPS_Unit`, and the `J × Hash_Value_of_CPS_Unit_Usage_File`
  20-byte SHA-1 array.
- **`usage_rules_hash(bytes)`** — the `C_ur = SHA-1(Usage_Rules)`
  primitive from PVB §2.6, exposed so the caller can apply it to
  whichever usage-rules artefact the adaptation book dictates.

No real AACS LA Content Certificate public key (AACS LA distributes it
only to licensees) — `verify_signature` takes a caller-supplied
`&ec::Point`. The CRL Table 2-2..2-5 layer is still out of scope; this
round only delivers the signed Table 2-1 wrapper around the
already-implemented (round 188) Content Hash Table integrity layer.

Round 211 adds **runtime AKE/EC self-check entry points** so a downstream
consumer (e.g. `oxideav-bluray`) can validate the in-tree §2.3 curve
constants + §4.3 AKE state machine before issuing a real SCSI command —
without itself needing a real Licensed Drive or AACS LA key material.
Module [`self_check`] exposes four independently callable checks that
cascade from cheap to expensive:

- **`curve_self_check()`** — Table 2-1 identity round-trip: `G` on curve,
  `n·G == O`, `G.double() == G + G`, `(a + b)·G == a·G + b·G`, scalar
  `a · a⁻¹ ≡ 1 (mod n)`, and `Point::from_coords(G.x, G.y) == G`.
- **`aacs_la_pub_self_check()`** — the bundled
  [`AACS_LA_PUB_X`] / [`AACS_LA_PUB_Y`] coordinates form a valid on-curve
  secp160r1 point, and the [`aacs_la_pub_point()`] helper agrees.
- **`ake_ecdh_self_check()`** — synthetic ECDH: `Dv = dk·G`, `Hv = hk·G`,
  then `lsb_128(x(hk·Dv)) == lsb_128(x(dk·Hv))` (§4.3 step 28 / 29 Bus
  Key derivation), with the agreed key checked non-degenerate.
- **`ake_full_self_check()`** — full §4.3 AKE end-to-end against a
  synthetic-LA-rooted in-process [`MockDrive`]: mints a synthetic AACS LA
  root, signs synthetic Drive + Host certificates, runs
  [`host_authenticate`] through the authenticating [`DriveAuthState`],
  and asserts both sides derive the same 128-bit Bus Key. This exercises
  every Phase B + Phase C path in a single call (CDB build/parse → ECDSA
  sign/verify → certificate parse → Bus Key derivation).
- **`all_self_checks()`** — convenience wrapper that runs all four
  in order and stops at the first failure.

Failures surface as `AacsError::SelfCheckFailed { what }` with a tag
naming the failing identity (e.g. `"n·G != point at infinity"`,
`"ECDH bus keys disagree"`, `"host and drive Bus Keys disagree after
full §4.3 AKE"`). Every check is deterministic, runs in ms, and uses no
real AACS LA key material.

Round 200 adds a **structured parse report** to the `KEYDB.cfg` parser
so callers can surface every skipped line — line number, excerpt,
parse-error reason — instead of relying on `OXIDEAV_AACS_DEBUG=1`
stderr output:

- **`KeyDb::parse_with_report(text) -> Result<(KeyDb, ParseReport)>`**
  — same tolerant per-line behaviour as `KeyDb::parse`, but every
  non-empty / non-comment line that fails to parse is captured in a
  `ParseReport { skipped: Vec<SkippedLine> }`. Each `SkippedLine`
  carries a 1-based `line_number`, an 80-byte UTF-8-safe `snippet` of
  the offending line, and the `Display`-formatted `AacsError` the
  per-line parser returned (`reason`).
- **`KeyDb::load_from_with_report(path)`** — same shape, reading from a
  filesystem path.
- **`ParseReport::is_clean()`** / **`ParseReport::skipped_count()`** —
  convenience accessors for the common "did the file load cleanly?"
  check.
- **`KeyDb::parse(text)`** is unchanged; it's now a thin discard of the
  report so existing callers see no behaviour change.

Companion test suite `tests/synth_round200_keydb_fuzz.rs` (27 cases)
enumerates every record type's plausible malformations — truncated /
oversized / odd-length / non-`0x`-prefixed hex, missing required
fields, unknown leaders, out-of-`DISCID`-scope rows, mixed CRLF / LF
line endings, multi-byte UTF-8 in record bodies, very long bad lines,
a printable-ASCII byte sweep over leader characters — and pins the
"never panic / never fail-whole-load / every skip surfaced in
`ParseReport`" invariants.

Round 188 adds the **Content Hash Table** integrity layer per
BD-Prerecorded Final 0.953 §2.3 — the per-Hash-Unit SHA-1 check a
Licensed Player runs to detect tampered Clip AV stream data:

- **`cht::ContentHashTable::parse(bytes, number_of_digests,
  number_of_hash_units)`** — parses a `ContentHash00N.tbl` (Table
  2-2): a header of `Number_of_Digests` 12-byte per-Clip descriptors
  (`Starting_HU_Num` / `Clip_Num` / `HU_Offset_in_Clip`) followed by
  `Number_of_HashUnits` 8-byte Hash Values. The two counts come from
  the per-layer Content Certificate (Table 2-1), not the table file
  itself, so they are passed in.
- **`cht::ContentHashTable::verify_hash_unit(index, hash_unit_bytes)`**
  — recomputes `Hash_Value = [SHA-1(Hash_Unit)]_lsb_64` (§2.3.2.1)
  and compares it to the stored value. A Hash Unit is 96 Logical
  Sectors = `96 × 2048` = **196608 bytes** (`cht::HASH_UNIT_SIZE`).
  The hash is taken over the *encrypted* on-disc bytes, so a player
  verifies integrity **without** holding the Title Key.
- **`cht::hash_value_of_unit(hash_unit)`** — the standalone
  `[SHA-1(·)]_lsb_64` primitive for a CHT author.

New error variants `AacsError::BadHashUnitLength` and
`ContentHashMismatch { index }`. The crate ships no Content
Certificate signature path yet (that's the AACS-LA-signed Table 2-1
digest layer) — only the CHT Hash-Unit verification it protects.

Round 183 wires `AACS_Verify` into the MKB parser so callers that
hold the AACS LA public key can check the three signatures the
Common spec defines: the End-of-Media-Key-Block Record signature
(§3.2.5.1.8) and the per-block ECDSA signatures inside the Host /
Drive Revocation List Records (§3.2.5.1.2 / §3.2.5.1.3).

- **`Mkb::verify_end_of_block_signature(original_bytes, aacs_la_pub)`**
  — runs `AACS_Verify(AACS_LApub, Signature, MKB)` against the MKB
  bytes up to but not including the End-of-MKB record.
- **`Mkb::verify_host_revocation_list` / `verify_drive_revocation_list`**
  — verify the per-signature-block ECDSA signatures cumulatively
  (block N's signed range = Type-and-Version Record || HRL/DRL
  record bytes up to the byte immediately preceding block N's
  signature).
- **`Mkb::end_of_block_signature: Option<[u8; 40]>`** and the new
  **`host_revocation_blocks` / `drive_revocation_blocks: Vec<RevocationSignatureBlock>`**
  fields expose the raw 40-byte ECDSA signatures so a caller can
  also feed them to an external verifier.

The crate ships no AACS LA public key (AACS LA distributes it to
licensees only); the verifiers take a `&ec::Point` parameter the
caller supplies. The parser still tolerates revocation blocks whose
trailing signature field is truncated per §3.2.5.1.2 final paragraph
("hosts are required to store only the data being signed for the
first signature block, but not required to store the signature
itself"); the verifier surfaces `AacsError::MkbSignatureMissing`
rather than panicking on a `None`-signature block.

Phase D (round 127) wires the Type-4 MKB / Key Conversion Data path
into the volume pipeline per AACS Common Final 0.953 §3.2.5.1.4 +
BD-Prerecorded Final 0.953 §3.8:

- **`subdiff::apply_key_conversion_data(kmp, kcd)`** — the
  `K_m = AES-G(K_mp, KCD)` primitive.
- **`AacsVolume::derive_vuk_from_device_key_with_kcd`** — Type-4-aware
  VUK derivation that walks the SD tree, tries the Verify Media Key
  Record on the precursor first (the spec's "old MKB" rule —
  precursor that verifies directly is the Media Key; KCD is NOT
  applied), and only invokes `AES-G(K_mp, KCD)` when the precursor
  fails verification.
- **`AacsVolume::derive_media_key_from_device_key`** — the raw
  SD-walk primitive for callers that want to make the verify/KCD
  decision themselves.
- **`Mkb::is_verified_media_key(km) -> bool`** + new
  `MkbType::requires_kcd` / `MkbType::as_u32` predicates.

`KEYDB.cfg` already parses the `| KCD |` record into
`DiscRecords::kcd`; that's the conventional source for the 16-byte
KCD payload the BD-ROM KCD-Mark would otherwise supply out-of-band.

Phase C (round 96) adds the Drive-Host Authentication & Key Exchange
(AKE) layer per AACS Common Final 0.953 §4.3, on top of the Phase B
MMC wire layer:

- **ECDSA over the AACS 160-bit curve** (Table 2-1, `a = -3` over
  `GF(p)`) — a clean-room big-integer + short-Weierstrass point
  implementation (`ec` module, Jacobian scalar multiply) with
  `AACS_Sign` / `AACS_Verify` (`ecdsa` module) and a clean-room
  FIPS 180-2 SHA-1 message digest. Cross-checked bit-exact against an
  independent Python big-int reference vector.
- **AES-128-CMAC** (NIST SP 800-38B) for the §4.4 transferred-ID MAC,
  validated against the SP 800-38B Appendix D.1 example vectors.
- **`host_authenticate`** — the full §4.3 Host-side state machine:
  AGID → `Hn || Host_Cert` → `Dn || Drive_Cert` (verify) →
  `Dv || Dsig` (verify) → `Hv || Hsig` → Bus Key. The drive side is
  modelled by an authenticating `DriveAuthState` wired into
  `MockDrive`, so a synthetic-cert handshake authenticates
  end-to-end and both sides derive the same 128-bit Bus Key
  (`BK = lsb_128(x-coordinate of Hk·Dv) = lsb_128(x(Dk·Hv))`).
- **`Certificate`** parse + AACS-LA-signature verification for the
  92-byte Drive (Table 4-1) / Host (Table 4-2) certificates, and
  **`read_verified_volume_id`** for the §4.4 Volume ID transfer with
  `CMAC(BK, Volume_ID)` verification.

No real AACS LA keys, no real certificates, no disc fixtures — every
test mints its own synthetic LA root + Drive/Host identities and runs
the handshake in-process.

Phase B (round 93) adds the SCSI MMC drive-command wire layer:

- **`REPORT_KEY` (0xA4)**, **`SEND_KEY` (0xA3)**, and
  **`READ_DISC_STRUCTURE` (0xAD)** typed CDB constructors per
  MMC-6 r02g + AACS Common Final 0.953.
- AACS Key Class 0x02 sub-payload constructors / parsers — AGID
  request, Drive Certificate Challenge (`Dn` + Drive Cert), Drive
  Key (`Dv` + `Dsig`), Drive Certificate, Host Certificate
  Challenge (`Hn` + Host Cert), Host Key (`Hv` + `Hsig`),
  Invalidate-AGID.
- Volume Identifier read via `READ_DISC_STRUCTURE` Format `0x80`
  (32-byte `Volume ID || MAC`); Pre-recorded Media Serial Number
  (Format `0x81`, §4.14.3.2 Table 4-16), Media Identifier (Format
  `0x82`, §4.14.3.3 Table 4-17), and Media Key Block Pack (Format
  `0x83`, §4.14.3.4 Table 4-18) constructors + response decoders.
- `DriveCommand` trait abstraction over the SCSI pass-through
  surface (`SG_IO` / `IOSCSITaskDeviceInterface` /
  `IOCTL_SCSI_PASS_THROUGH_DIRECT`) — Phase B ships only the trait
  + an in-process `MockDrive` for tests. No real-hardware transport
  yet.

Round 1 ships the full prerecorded-BD decryption pipeline:

- **KEYDB.cfg** parser (the de-facto community VUK key-database format)
  with XDG search order + `OXIDEAV_AACS_KEYDB` env override.
- **MKB_RO.inf** parser — every record type defined in the Common spec
  §3.2.5 (Type-and-Version, Host/Drive Revocation List, Verify Media
  Key, Explicit Subset-Difference, Subset-Difference Index, Media Key
  Data, Variant Data, End-of-MKB).
- **Unit_Key_RO.inf** parser — full BD-Prerecorded §3.9.3 Unit Key
  File header + Unit Key Block decode.
- **`AACS/` directory walker** — discovers `MKB_RO.inf` and
  `Unit_Key_RO.inf` under a disc-mount root, with `AACS/DUPLICATE/`
  fallback.
- **AES primitives**: AES-128 ECB block, AES-128-CBC stream with
  caller-supplied IV, AES-G one-way function, AES-G3 triple generator,
  AES-H hash — all built on top of the RustCrypto `aes` crate.
- **Subset-Difference tree walk** (Common spec §3.2.1 — §3.2.4):
  Device Key + MKB → Processing Key → Media Key.
- **VUK derivation** (BD-Prerecorded spec §3.3):
  `Kvu = AES-G(Km, IDv)`.
- **Title Key unwrap** (BD-Prerecorded spec §3.9.3): per-CPS-Unit
  `Encrypted CPS Unit Key = AES-128E(Kvu, Kcu)`.
- **Content scrambling** (BD-Prerecorded spec §3.10): the 6144-byte
  Aligned Unit / 16-byte cleartext seed / 6128-byte AES-128-CBC body
  decryption pipeline, with `BlockKey = AES-128E(Kcu, seed) XOR seed`.

The crate has **no real-disc fixtures**, no embedded Device Keys, no
embedded Processing Keys, no embedded Title Keys, and no disc-specific
test vectors. Every test constructs its own key material from scratch
and roundtrips through encrypt → parse → decrypt.

## Quick example

```rust,no_run
use oxideav_aacs::{AacsVolume, KeyDb, Vuk};

let volume = AacsVolume::open("/mnt/bd-rom")?;
let keydb = KeyDb::load_default()?;
let vuk = volume.resolve_vuk_from_keydb(&keydb)
    .expect("disc VUK not in KEYDB.cfg");
let mut volume = volume;
volume.unwrap_title_keys(&vuk)?;

// Now `volume.cps_units()[i].title_key()` holds the unwrapped key for
// CPS Unit `i`, and `volume.decrypt_unit(&unit, &aligned_6144)` is
// callable.
# Ok::<(), oxideav_aacs::AacsError>(())
```

## Crate features

| Feature    | Default | Effect                                                                 |
|------------|:-------:|------------------------------------------------------------------------|
| `registry` | yes     | Pulls in `oxideav-core` for the workspace-wide `Error` enum alias.     |

`default-features = false` gives a standalone build that exposes a
crate-local `AacsError` enum and the same parsing/crypto API surface
without the framework dependency tree.

## Legal hygiene

AACS LA publishes the protocol specifications openly at
<https://aacsla.com/aacs-specifications/>. Implementing the spec
non-commercially is the explicit purpose for which they are published.
This crate does **not** include or claim an AACS LA *Approved Drive* /
*Approved Player* licence (which is the LA's commercial business model
and a separate contractual artefact). Using `oxideav-aacs` against
real disc content additionally requires that the user have lawfully
obtained both the disc and the relevant Device Key / VUK material —
which AACS LA distributes only to licensees.

The implementation is **clean-room**: only the AACS LA PDFs, the
KEYDB.cfg format reference at `docs/container/aacs/keydb-cfg-format.md`,
the SCSI MMC working drafts under `docs/container/aacs/mmc/`, and a
2007-era Doom9 community thread on the Subset-Difference scheme were
consulted.

## Spec source ↔ module map

| Module                | Spec § (Common)        | Spec § (BD-Prerecorded) |
|-----------------------|------------------------|-------------------------|
| `aes`                 | §2.1.1 — §2.1.4        | (constant IV in §3.10)  |
| `cht`                 | (SHA-1 §2.1.5)         | §2.3                    |
| `content_certificate` | §2.3 (ECDSA)           | §2.1 (Table 2-1)        |
| `crl`                 | §2.3 (ECDSA)           | §2.7 (Tables 2-2..2-5)  |
| `subdiff`             | §3.2.1 — §3.2.4        | —                       |
| `mkb`                 | §3.2.5                 | §3.1, §3.4              |
| `unit_key`            | —                      | §3.9.3                  |
| `vuk`                 | —                      | §3.3                    |
| `content`             | —                      | §3.10                   |
| `volume`              | —                      | §3.1, §3.9, Figure 3-5  |
| `keydb`               | (de-facto community)   | —                       |
| `self_check`          | §2.3, §4.3             | —                       |

## Out of scope

- Bus encryption (BD-Prerecorded §3.7) — drive/host SCSI transport
  concern only.
- AACS Drive / Host authentication ECDSA layer (Common spec ch. 4
  §4.3 steps 14-23) — the wire-format CDBs that ferry the AKE
  protocol are now staged (Phase B); the ECDSA-secp160r1 sign /
  verify primitives are still pending (Phase C).
- Real AACS LA public key — AACS LA distributes it only to
  licensees, so the verifiers (`Mkb::verify_end_of_block_signature`,
  `verify_host_revocation_list`, `verify_drive_revocation_list`,
  `Certificate::verify_signature`) take a `&ec::Point` parameter the
  caller supplies; tests use a self-issued synthetic LA identity.
- Persistent CRL storage (PVB §2.7 "Licensed Products shall retain in
  non-volatile storage the List Version and the Revocation Record Set
  #1 of the highest verified List Version"). The crate exposes the
  primitives to compare list versions and merge / replace records
  across two CRLs, but the actual persistence layer is a player
  concern, out of scope here.
- AACS 2.0 (Ultra HD Blu-ray) — separate spec family, not publicly
  released.
- BD+ — separate copy-protection layer, not public.

## Authoritative references

- AACS LA, *Advanced Access Content System (AACS) — Introduction and
  Common Cryptographic Elements*, Revision 0.953 Final, 26 Oct 2012.
- AACS LA, *Advanced Access Content System (AACS) — Blu-ray Disc
  Pre-recorded Book*, Revision 0.953 Final, 26 Oct 2012.
- Doom9's Forum, *"Understanding AACS (including Subset-Difference)"*,
  thread 122363 (2007) — used only for cross-checking the §3.2.1
  diagram, never for code text.

All three are mirrored in
[`docs/container/aacs/`](https://github.com/OxideAV/oxideav-workspace/tree/master/docs/container/aacs)
in the workspace repo.

## License

MIT © 2026 Karpelès Lab Inc.
