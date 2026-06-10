//! Round 211 — AACS Drive-Host AKE elliptic-curve round-trip self-checks.
//!
//! Phase C ([`crate::ake`]) sits on a clean-room implementation of the
//! AACS Common Final 0.953 §2.3 elliptic curve, a SHA-1 / ECDSA stack
//! ([`crate::ecdsa`]), and the §4.3 Drive-Host authentication state
//! machine. Any of those layers could be silently broken by a future
//! refactor — e.g. a typo in the Table 2-1 curve constants, an
//! off-by-one in the scalar reduction, a regression in the Jacobian
//! mixed-addition formulae — without the per-module unit tests catching
//! it (those tests only run under `cargo test`; downstream consumers like
//! [`oxideav-bluray`] never see them).
//!
//! This module exposes **runtime-callable** self-check entry points that
//! a consumer (or an integration test fixture) can invoke before issuing
//! a real SCSI command to a Licensed Drive. The four checks cascade from
//! cheap to expensive, each independently usable:
//!
//! 1. [`curve_self_check`] — Table 2-1 constants identity round-trip:
//!    `G` lies on the curve, `n·G == O`, point doubling matches
//!    `P + P`, scalar `(a + b)·G == a·G + b·G`, byte-encoding round-trip.
//! 2. [`aacs_la_pub_self_check`] — the bundled
//!    [`crate::AACS_LA_PUB_X`] / [`crate::AACS_LA_PUB_Y`] coordinates form
//!    a valid secp160r1 point. (Drift in those bytes would silently
//!    invalidate every signature verification the rest of the crate
//!    performs.)
//! 3. [`ake_ecdh_self_check`] — synthetic ECDH agreement: pick two scalars
//!    `dk`, `hk`, derive `Dv = dk·G`, `Hv = hk·G`, then check that
//!    `lsb_128(x(hk·Dv)) == lsb_128(x(dk·Hv))` (the §4.3 step 28/29 Bus
//!    Key derivation).
//! 4. [`ake_full_self_check`] — full §4.3 AKE end-to-end against an
//!    in-process synthetic-LA-rooted [`crate::MockDrive`]: mints a
//!    synthetic AACS LA root key, signs synthetic Drive + Host
//!    certificates, runs [`crate::host_authenticate`] through the
//!    authenticating [`crate::ake::DriveAuthState`], and asserts both
//!    sides derived the same 128-bit Bus Key. This exercises every
//!    Phase B + Phase C code path in a single call (CDB
//!    construction → ECDSA sign/verify → certificate parse → Bus Key
//!    derivation).
//!
//! All four checks are deterministic, run in a few milliseconds, and use
//! no system resources beyond AES + SHA-1 cycles. They take no real AACS
//! LA key material and produce no real disc cryptographic output — every
//! value is synthesised here from constants embedded in the source.
//!
//! # When to use
//!
//! - At the start of a consumer crate's integration suite, before any
//!   `host_authenticate` call.
//! - From a CLI diagnostic such as `oxideav-bluray --self-check-aacs`.
//! - As a build-time post-install assertion.
//!
//! These are *not* a substitute for actually testing against a real
//! Licensed Drive — they don't exercise the SCSI transport, real AACS LA
//! signatures, or revoked-disc handling. They guarantee only that the
//! in-tree cryptographic primitives + §4.3 state machine round-trip
//! cleanly on this build.

use crate::ake::{
    aacs_la_pub_point, bus_key_from_point, AACS_LA_PUB_X, AACS_LA_PUB_Y, BUS_KEY_LEN,
};
// These items are used only by the `test-util`-gated `ake_full_self_check`.
#[cfg(any(test, feature = "test-util"))]
use crate::ake::{
    build_signed_certificate, host_authenticate, DriveAuthState, HostCredentials, CERT_TYPE_DRIVE,
    CERT_TYPE_HOST,
};
use crate::ec::{scalar_add, scalar_inv, scalar_mul, Point, N, U160};
use crate::error::AacsError;
#[cfg(any(test, feature = "test-util"))]
use crate::mmc::MockDrive;

/// Small deterministic scalar (low 32 bits only); used by every self-check
/// fixture so the output is reproducible across runs without pulling in
/// an RNG.
const fn small_scalar(v: u32) -> U160 {
    U160 {
        limbs: [v, 0, 0, 0, 0],
    }
}

/// Run the Table 2-1 curve-constant + scalar-arithmetic identities.
///
/// Verifies, in order:
/// - `G` lies on `E: y² = x³ - 3x + b`.
/// - `n·G == O` (the order of the base point is exactly `n`).
/// - `2·G == G + G` (point doubling matches affine addition).
/// - `(a + b)·G == a·G + b·G` (scalar-mul distributes over add) for two
///   independent small scalars.
/// - `a · a⁻¹ ≡ 1 (mod n)` for a non-trivial scalar `a` (group-order
///   modular inverse round-trip).
/// - Byte round-trip: `Point::from_coords(G.x.to_bytes(), G.y.to_bytes()) == G`.
///
/// Returns [`AacsError::SelfCheckFailed`] with a per-failure tag on the
/// first mismatch, or `Ok(())` if every identity holds.
pub fn curve_self_check() -> Result<(), AacsError> {
    let g = Point::generator();
    if !g.is_on_curve() {
        return Err(AacsError::SelfCheckFailed {
            what: "generator G not on AACS curve",
        });
    }

    // n·G == O.
    if !g.mul_scalar(&N).is_infinity() {
        return Err(AacsError::SelfCheckFailed {
            what: "n·G != point at infinity",
        });
    }

    // 2·G == G + G.
    let double = g.double();
    let add_self = g.add(&g);
    if double != add_self {
        return Err(AacsError::SelfCheckFailed {
            what: "G.double() != G + G",
        });
    }

    // (a + b)·G == a·G + b·G.
    let a = small_scalar(0x0024_6801);
    let b = small_scalar(0x0013_5790);
    let lhs = g.mul_scalar(&scalar_add(&a, &b));
    let rhs = g.mul_scalar(&a).add(&g.mul_scalar(&b));
    if lhs != rhs {
        return Err(AacsError::SelfCheckFailed {
            what: "(a+b)·G != a·G + b·G",
        });
    }

    // a · a⁻¹ ≡ 1 (mod n).
    let s = small_scalar(0x00ab_cdef);
    let s_inv = scalar_inv(&s);
    if scalar_mul(&s, &s_inv) != U160::ONE {
        return Err(AacsError::SelfCheckFailed {
            what: "scalar a · a⁻¹ != 1 (mod n)",
        });
    }

    // Byte round-trip.
    let bytes = g.to_bytes();
    let mut x = [0u8; 20];
    let mut y = [0u8; 20];
    x.copy_from_slice(&bytes[..20]);
    y.copy_from_slice(&bytes[20..]);
    let recovered = Point::from_coords(&x, &y).ok_or(AacsError::SelfCheckFailed {
        what: "Point::from_coords rejected the encoding of G",
    })?;
    if recovered != g {
        return Err(AacsError::SelfCheckFailed {
            what: "Point byte round-trip lost identity",
        });
    }

    Ok(())
}

/// Verify the bundled AACS LA root public key constants form a valid
/// on-curve secp160r1 point.
///
/// Drift in [`AACS_LA_PUB_X`] / [`AACS_LA_PUB_Y`] would silently break
/// every `Certificate::verify_signature` + `Mkb::verify_*_signature` call
/// that uses [`aacs_la_pub_point`]. A runtime check guards downstream
/// consumers from inheriting a corrupted build.
pub fn aacs_la_pub_self_check() -> Result<(), AacsError> {
    let p =
        Point::from_coords(&AACS_LA_PUB_X, &AACS_LA_PUB_Y).ok_or(AacsError::SelfCheckFailed {
            what: "bundled AACS_LA_PUB coordinates not on curve",
        })?;
    if !p.is_on_curve() {
        return Err(AacsError::SelfCheckFailed {
            what: "AACS_LA_PUB Point::is_on_curve() returned false",
        });
    }
    // The helper must produce the same point.
    let helper = aacs_la_pub_point();
    if helper != p {
        return Err(AacsError::SelfCheckFailed {
            what: "aacs_la_pub_point() disagrees with from_coords(AACS_LA_PUB_*)",
        });
    }
    Ok(())
}

/// Synthetic ECDH-agreement self-check: `lsb_128(x(hk·Dv))` matches
/// `lsb_128(x(dk·Hv))` for `Dv = dk·G`, `Hv = hk·G`.
///
/// Two independent deterministic scalars are fixed in the source so the
/// check is reproducible without a PRNG. Both `dk` and `hk` are non-zero
/// and < `n`, so the resulting points are non-trivial. Returns
/// [`AacsError::SelfCheckFailed`] with the tag `"ECDH bus keys disagree"`
/// on a mismatch.
pub fn ake_ecdh_self_check() -> Result<(), AacsError> {
    let dk = small_scalar(0x0013_5790);
    let hk = small_scalar(0x0024_6801);
    let dv = Point::generator().mul_scalar(&dk);
    let hv = Point::generator().mul_scalar(&hk);
    if dv.is_infinity() || hv.is_infinity() {
        return Err(AacsError::SelfCheckFailed {
            what: "ECDH self-check produced point at infinity",
        });
    }
    let host_bk = bus_key_from_point(&dv.mul_scalar(&hk));
    let drive_bk = bus_key_from_point(&hv.mul_scalar(&dk));
    if host_bk != drive_bk {
        return Err(AacsError::SelfCheckFailed {
            what: "ECDH bus keys disagree",
        });
    }
    if host_bk == [0u8; BUS_KEY_LEN] {
        return Err(AacsError::SelfCheckFailed {
            what: "ECDH bus key is all-zero (degenerate)",
        });
    }
    Ok(())
}

/// End-to-end §4.3 AKE round-trip against a synthetic in-process drive.
///
/// Mints a synthetic AACS LA root key, signs a synthetic Drive
/// Certificate and Host Certificate, wires an authenticating
/// [`DriveAuthState`] into a [`MockDrive`], runs the full §4.3
/// [`host_authenticate`] state machine, and asserts that both sides
/// derive the same 128-bit Bus Key.
///
/// On success the call exercises every Phase B + Phase C code path:
/// CDB construction and parsing, ECDSA sign and verify, certificate
/// parse and structural validation, the §4.3 step 5 → step 29 multi-CDB
/// sequence, and the ECDH x-coordinate Bus Key derivation. A failure at
/// any step surfaces as [`AacsError::SelfCheckFailed`] with a tag
/// pinpointing the failing leg of the handshake.
///
/// Gated behind the `test-util` cargo feature: it depends on the
/// in-process [`MockDrive`] fixture, which is itself `test-util`-gated.
#[cfg(any(test, feature = "test-util"))]
pub fn ake_full_self_check() -> Result<(), AacsError> {
    // Synthetic AACS LA root key — *not* the real one.
    let la_priv = small_scalar(0x0abc_def1);
    let la_pub = Point::generator().mul_scalar(&la_priv);

    // Drive identity.
    let drive_priv = small_scalar(0x0011_2233);
    let drive_pub = Point::generator().mul_scalar(&drive_priv);
    let drive_cert = build_signed_certificate(
        CERT_TYPE_DRIVE,
        0x00,
        &[0xD0, 0x01, 0x02, 0x03, 0x04, 0x05],
        &drive_pub,
        &la_priv,
    );

    // Host identity.
    let host_priv = small_scalar(0x0044_5566);
    let host_pub = Point::generator().mul_scalar(&host_priv);
    let host_cert = build_signed_certificate(
        CERT_TYPE_HOST,
        0x00,
        &[0xA0, 0x06, 0x07, 0x08, 0x09, 0x0A],
        &host_pub,
        &la_priv,
    );

    // Drive-side AKE state (synthetic Dk + Dn).
    let dk = small_scalar(0x0013_5790);
    let mut drive_nonce = [0u8; 20];
    for (i, slot) in drive_nonce.iter_mut().enumerate() {
        *slot = 0xD0 ^ (i as u8);
    }

    let mut drive = MockDrive::with_test_fixture();
    drive.agid_to_return = 1;
    drive.auth = Some(DriveAuthState::new(
        drive_cert,
        drive_priv,
        dk,
        drive_nonce,
        la_pub,
    ));

    let creds = HostCredentials {
        host_cert,
        host_priv,
        aacs_la_pub: la_pub,
    };

    // Host ephemeral secret + nonce.
    let hk = small_scalar(0x0024_6801);
    let mut host_nonce = [0u8; 20];
    for (i, slot) in host_nonce.iter_mut().enumerate() {
        *slot = 0x50 ^ (i as u8);
    }

    let result = host_authenticate(&mut drive, &creds, &host_nonce, &hk).map_err(|_| {
        AacsError::SelfCheckFailed {
            what: "host_authenticate failed on synthetic Phase C fixture",
        }
    })?;

    let drive_bk =
        drive
            .auth
            .as_ref()
            .and_then(|a| a.bus_key)
            .ok_or(AacsError::SelfCheckFailed {
                what: "drive side derived no Bus Key after Hsig verify",
            })?;

    if result.bus_key != drive_bk {
        return Err(AacsError::SelfCheckFailed {
            what: "host and drive Bus Keys disagree after full §4.3 AKE",
        });
    }
    if result.bus_key == [0u8; BUS_KEY_LEN] {
        return Err(AacsError::SelfCheckFailed {
            what: "negotiated Bus Key is all-zero (degenerate)",
        });
    }
    if result.agid != 1 {
        return Err(AacsError::SelfCheckFailed {
            what: "negotiated AGID drifted from the synthetic fixture value",
        });
    }
    Ok(())
}

/// Run every AKE/EC self-check in order and stop at the first failure.
///
/// Convenience wrapper over [`curve_self_check`] →
/// [`aacs_la_pub_self_check`] → [`ake_ecdh_self_check`] →
/// [`ake_full_self_check`]. On success this guarantees the in-tree AACS
/// Phase C cryptographic primitives + §4.3 state machine + the bundled
/// AACS LA root public key constants all round-trip cleanly on this
/// build. On failure the returned error names the first failing leg.
///
/// Gated behind the `test-util` cargo feature because it cascades into
/// [`ake_full_self_check`], which drives the `test-util`-gated
/// [`MockDrive`] fixture. The three pure-math checks
/// ([`curve_self_check`], [`aacs_la_pub_self_check`],
/// [`ake_ecdh_self_check`]) remain callable on the default public API.
#[cfg(any(test, feature = "test-util"))]
pub fn all_self_checks() -> Result<(), AacsError> {
    curve_self_check()?;
    aacs_la_pub_self_check()?;
    ake_ecdh_self_check()?;
    ake_full_self_check()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curve_self_check_passes_on_clean_build() {
        curve_self_check().expect("AACS curve constants must round-trip");
    }

    #[test]
    fn aacs_la_pub_self_check_passes_on_clean_build() {
        aacs_la_pub_self_check().expect("AACS LA public key constants must be on-curve");
    }

    #[test]
    fn ake_ecdh_self_check_passes_on_clean_build() {
        ake_ecdh_self_check().expect("ECDH agreement self-check must pass");
    }

    #[test]
    fn ake_full_self_check_passes_on_clean_build() {
        ake_full_self_check().expect("full §4.3 AKE self-check must pass");
    }

    #[test]
    fn all_self_checks_pass_on_clean_build() {
        all_self_checks().expect("all AKE self-checks must pass");
    }
}
