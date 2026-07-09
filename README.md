# oxideav-aacs

[![CI](https://github.com/OxideAV/oxideav-aacs/actions/workflows/ci.yml/badge.svg)](https://github.com/OxideAV/oxideav-aacs/actions/workflows/ci.yml) [![crates.io](https://img.shields.io/crates/v/oxideav-aacs.svg)](https://crates.io/crates/oxideav-aacs) [![docs.rs](https://docs.rs/oxideav-aacs/badge.svg)](https://docs.rs/oxideav-aacs) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Pure-Rust, clean-room implementation of the **AACS** (Advanced Access
Content System) decryption layer used by Blu-ray Disc, per the
publicly-published AACS LA technical specifications **Common Final
0.953** (Oct 2012) and **BD-Prerecorded Final 0.953** (Oct 2012).

## Capabilities

### Prerecorded-BD decryption pipeline

- **KEYDB.cfg** parser (the de-facto community VUK key-database format)
  with XDG search order + `OXIDEAV_AACS_KEYDB` env override, plus a
  structured `parse_with_report` surfacing every skipped line with line
  number, snippet, and parse-error reason.
- **MKB_RO.inf** parser — every record type defined in Common §3.2.5
  (Type-and-Version, Host/Drive Revocation List, Verify Media Key,
  Explicit Subset-Difference, Subset-Difference Index, Media Key Data,
  Variant Data, End-of-MKB), plus typed accessors for the MKBType marker
  / generation / test-MKB sentinel.
- **Unit_Key_RO.inf** parser — full BD-Prerecorded §3.9.3 Unit Key File
  header + Unit Key Block decode.
- **`AACS/` directory walker** — discovers `MKB_RO.inf` and
  `Unit_Key_RO.inf` under a disc-mount root, with `AACS/DUPLICATE/`
  fallback.
- **AES primitives** — AES-128 ECB block, AES-128-CBC stream, AES-G
  one-way function, AES-G3 triple generator, AES-H hash.
- **Subset-Difference tree walk** (Common §3.2.1–§3.2.4): Device Key +
  MKB → Processing Key → Media Key, including the §3.2.5.1.4 Type-4 MKB
  Key-Conversion-Data verify-precursor-or-apply-KCD decision.
- **VUK derivation** (BD-Prerecorded §3.3): `Kvu = AES-G(Km, IDv)`.
- **Title Key unwrap** (BD-Prerecorded §3.9.3) and **content
  scrambling** (BD-Prerecorded §3.10): the 6144-byte Aligned Unit
  decryption pipeline with `BlockKey = AES-128E(Kcu, seed) XOR seed`.

### Signature / integrity verification

- **`AACS_Verify`** wired into the MKB parser for the
  End-of-Media-Key-Block, Host Revocation List, and Drive Revocation
  List signatures.
- **Content Hash Table** (`cht`) — BD-Prerecorded §2.3 per-Hash-Unit
  SHA-1 integrity check (196608-byte Hash Units, verifiable without the
  Title Key).
- **Content Certificate** (`content_certificate`) — Pre-recorded Video
  Book §2.4–§2.6 signed-certificate parse/verify, the BD-Prerecorded
  Table 2-1 Format-Specific Section, and the Content Certificate ID.
- **Content Revocation List** (`crl`) — PVB §2.7 parse, per-segment
  ECDSA verify, and revocation-record lookup for every defined record
  type, including the recordable-media (RMRR) layout.
- **CPS Unit Usage File / CCI** (`cci`) — BD-Prerecorded §3.9.4
  (Tables 3-17 – 3-33) copy-control and title-usage parse/serialize:
  the `CCI_and_other_info()` container, Basic CCI (EPN/CCI, Image
  Constraint, Digital Only, APSTB, per-Title Basic/Enhanced bitmap),
  Enhanced Title Usage (cacheable-permission windows with BCD
  `After`/`Before` dates), on-line Key Management (Binding Type), and
  Content Owner Authorized Outputs, all round-tripping through the
  Primary/Secondary CCI Area layout.

Because AACS LA distributes the LA Entity public key only to licensees,
every `verify_*` entry point takes a caller-supplied `&ec::Point`; the
test suite mints a synthetic LA identity.

### Drive / Host authentication (AKE) and MMC wire layer

- **ECDSA over the AACS 160-bit curve** (`ec`, `ecdsa`) — clean-room
  big-integer + short-Weierstrass point implementation with `AACS_Sign`
  / `AACS_Verify` and a clean-room SHA-1, plus **AES-128-CMAC**.
- **`host_authenticate`** (`ake`) — the full Common §4.3 AKE state
  machine, modelled end-to-end against an in-process authenticating
  `DriveAuthState` so both sides derive the same 128-bit Bus Key.
- **`Certificate`** parse + LA-signature verification for the 92-byte
  Drive / Host certificates.
- **SCSI MMC command layer** (`mmc`) — typed `REPORT KEY` (0xA4),
  `SEND KEY` (0xA3), `READ DISC STRUCTURE` (0xAD), `SEND DISC STRUCTURE`
  (0xBF), and `GET CONFIGURATION` (0x46) CDB constructors with parsers
  for the AACS Key-Class 0x02 sub-payloads, the READ / SEND DISC
  STRUCTURE Format-Code range `0x80`–`0x86` (Volume ID, serial number,
  media identifier, MKB packs, data keys, bus-encryption sector extents,
  CPRM media key block) and the AACS Feature Descriptor (`0x010D`).
  A `DriveCommand` trait abstracts the SCSI pass-through surface; the
  crate ships an in-process `MockDrive` for tests but no real-hardware
  transport.
- **Self-checks** (`self_check`) — curve identity, bundled LA public
  point, ECDH, and a full in-process §4.3 AKE round-trip that a consumer
  (e.g. `oxideav-bluray`) can run to validate the crate before issuing a
  real SCSI command.

The crate ships **no real-disc fixtures**, no embedded Device / Processing
/ Title Keys, and no disc-specific test vectors. Every test constructs
its own key material and round-trips encrypt → parse → decrypt.

## Quick example

```rust,no_run
use oxideav_aacs::{AacsVolume, KeyDb};

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

| Feature    | Default | Effect                                                            |
|------------|:-------:|-------------------------------------------------------------------|
| `registry` | yes     | Pulls in `oxideav-core` for the workspace-wide `Error` enum alias.|
| `test-util`| no      | Exposes the in-process synthetic `MockDrive` SCSI fixture and the `MockDrive`-coupled AKE self-checks. |

`default-features = false` gives a standalone build that exposes a
crate-local `AacsError` enum and the same parsing/crypto API surface
without the framework dependency tree.

## Legal hygiene

AACS LA publishes the protocol specifications openly at
<https://aacsla.com/aacs-specifications/>. Implementing the spec
non-commercially is the explicit purpose for which they are published.
This crate does **not** include or claim an AACS LA *Approved Drive* /
*Approved Player* licence. Using `oxideav-aacs` against real disc
content additionally requires that the user have lawfully obtained both
the disc and the relevant Device Key / VUK material — which AACS LA
distributes only to licensees.

The implementation is **clean-room**: only the AACS LA PDFs, the
KEYDB.cfg format reference at `docs/container/aacs/keydb-cfg-format.md`,
the SCSI MMC working drafts under `docs/container/aacs/mmc/`, and a
2007-era community thread on the Subset-Difference scheme (used only to
cross-check the §3.2.1 diagram, never for code text) were consulted.

## Spec source ↔ module map

| Module                | Spec § (Common)        | Spec § (BD-Prerecorded) |
|-----------------------|------------------------|-------------------------|
| `aes`                 | §2.1.1 — §2.1.4        | (constant IV in §3.10)  |
| `cht`                 | (SHA-1 §2.1.5)         | §2.3                    |
| `content_certificate` | §2.3 (ECDSA)           | §2.1 (Table 2-1)        |
| `crl`                 | §2.3 (ECDSA)           | §2.7 (Tables 2-2..2-5)  |
| `cci`                 | §5.2 (Title Usage)     | §3.9.4 (Tables 3-17..3-33) |
| `subdiff`             | §3.2.1 — §3.2.4        | —                       |
| `mkb`                 | §3.2.5                 | §3.1, §3.4              |
| `unit_key`            | —                      | §3.9.3                  |
| `vuk`                 | —                      | §3.3                    |
| `content`             | —                      | §3.10                   |
| `volume`              | —                      | §3.1, §3.9, Figure 3-5  |
| `keydb`               | (de-facto community)   | —                       |
| `ake` / `ecdsa` / `ec`| §4.3, ch. 4            | —                       |
| `mmc`                 | §4.14                  | —                       |
| `self_check`          | §2.3, §4.3             | —                       |

## Out of scope

- Real AACS LA public key (distributed only to licensees) — verifiers
  take a caller-supplied `&ec::Point`; tests use a synthetic LA identity.
- Real-hardware SCSI transport — only the `DriveCommand` trait and an
  in-process `MockDrive` are provided.
- Persistent CRL storage (a player concern; the version-compare / merge
  primitives are exposed but persistence is not).
- AACS 2.0 (Ultra HD Blu-ray) — separate spec family, not publicly
  released.
- BD+ — separate copy-protection layer, not public.

## Authoritative references

- AACS LA, *Advanced Access Content System (AACS) — Introduction and
  Common Cryptographic Elements*, Revision 0.953 Final, 26 Oct 2012.
- AACS LA, *Advanced Access Content System (AACS) — Blu-ray Disc
  Pre-recorded Book*, Revision 0.953 Final, 26 Oct 2012.

Both are mirrored in
[`docs/container/aacs/`](https://github.com/OxideAV/oxideav-workspace/tree/master/docs/container/aacs)
in the workspace repo.

## License

MIT © 2026 Karpelès Lab Inc.
