# oxideav-aacs

Pure-Rust, clean-room implementation of the **AACS** (Advanced Access
Content System) decryption layer used by Blu-ray Disc, per the
publicly-published AACS LA technical specifications **Common Final
0.953** (Oct 2012) and **BD-Prerecorded Final 0.953** (Oct 2012).

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
  (32-byte `Volume ID || MAC`).
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

The implementation is **clean-room**: only the AACS LA PDFs and a
2007-era Doom9 community thread on the Subset-Difference scheme were
consulted. No code or text from `libaacs`, `aacskeys`, `libbluray`,
`makemkv`, or related projects was used.

## Spec source ↔ module map

| Module                | Spec § (Common)        | Spec § (BD-Prerecorded) |
|-----------------------|------------------------|-------------------------|
| `aes`                 | §2.1.1 — §2.1.4        | (constant IV in §3.10)  |
| `subdiff`             | §3.2.1 — §3.2.4        | —                       |
| `mkb`                 | §3.2.5                 | §3.1, §3.4              |
| `unit_key`            | —                      | §3.9.3                  |
| `vuk`                 | —                      | §3.3                    |
| `content`             | —                      | §3.10                   |
| `volume`              | —                      | §3.1, §3.9, Figure 3-5  |
| `keydb`               | (de-facto community)   | —                       |

## Out of scope

- Bus encryption (BD-Prerecorded §3.7) — drive/host SCSI transport
  concern only.
- AACS Drive / Host authentication ECDSA layer (Common spec ch. 4
  §4.3 steps 14-23) — the wire-format CDBs that ferry the AKE
  protocol are now staged (Phase B); the ECDSA-secp160r1 sign /
  verify primitives are still pending (Phase C).
- ECDSA signature verification (`AACS_Verify(AACS_LA_pub, ...)`) —
  spec defines it but we don't need it to derive `Km`.
- Content Hash Table verification (BD-Prerecorded §2.3) — SHA-1
  integrity check; structurally documented.
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
