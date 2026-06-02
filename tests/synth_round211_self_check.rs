//! Round 211 — integration tests for the Phase C self-check entry points.
//!
//! These run the public [`all_self_checks`] sequence end-to-end, then
//! confirm each layer of the cascade is independently callable and
//! returns the same `Ok(())` on a clean build. A regression in any of
//! the AACS 160-bit curve / scalar arithmetic / §4.3 AKE / synthetic
//! Bus-Key derivation paths surfaces here without needing a real
//! Licensed Drive.

use oxideav_aacs::{
    aacs_la_pub_self_check, ake_ecdh_self_check, ake_full_self_check, all_self_checks,
    curve_self_check,
};

#[test]
fn curve_self_check_round_trips_table_2_1_identities() {
    curve_self_check().expect("AACS curve constants self-check must pass on a clean build");
}

#[test]
fn aacs_la_pub_self_check_validates_bundled_constants() {
    aacs_la_pub_self_check()
        .expect("bundled AACS_LA_PUB constants must form a valid on-curve secp160r1 point");
}

#[test]
fn ake_ecdh_self_check_returns_nondegenerate_agreement() {
    ake_ecdh_self_check().expect("synthetic ECDH agreement self-check must pass");
}

#[test]
fn ake_full_self_check_runs_full_4_3_handshake() {
    ake_full_self_check()
        .expect("§4.3 AKE end-to-end self-check must pass against the in-process MockDrive");
}

#[test]
fn all_self_checks_pass_in_one_call() {
    all_self_checks().expect("all_self_checks must succeed on a clean build");
}

#[test]
fn self_checks_are_deterministic() {
    // Self-checks must be idempotent across invocations — no hidden RNG,
    // no stashed state. Running the cascade three times in a row must
    // produce the same Ok(()) outcome each time.
    for _ in 0..3 {
        all_self_checks().expect("repeated all_self_checks invocations must remain Ok");
    }
}
