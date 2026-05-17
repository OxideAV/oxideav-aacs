//! Subset-Difference tree walk tests.
//!
//! We can't cross-check against a published spec vector (the AACS
//! Common spec doesn't include one — see CHANGELOG "documentation
//! gaps surfaced"), so the test strategy is end-to-end:
//!
//! 1. Pick a synthetic Device Key + target subset-difference where
//!    the stored key is one level above the target uv node.
//! 2. Walk one level down via `derive_processing_key`.
//! 3. Independently re-derive the same Processing Key by calling
//!    `aes_g3` ourselves and following the same left/right child
//!    choice + final `aes_g3.processing_key` extraction.
//! 4. Assert equality.
//!
//! This catches any divergence between the "walk down" loop and the
//! per-step formula.

use oxideav_aacs::{aes_g3, applies_to_device, derive_processing_key, SubsetDifference};

#[test]
fn one_level_walk_matches_manual_derivation() {
    // Stored Device Key at uv=0x10000000 with v_mask trailing zeros
    // = 28 (i.e. mask 0xF000_0000).
    let stored_dk = [0xA5u8; 16];
    let stored_uv = 0x1000_0000;
    let stored_v_zeros: u8 = 28;

    // Target subset-difference one level lower: target_v_zeros = 27,
    // i.e. m_v = 0xF800_0000. The walk picks left/right based on
    // bit 27 of target_uv (the bit just above target_v_zeros). Two
    // cases — bit27=0 (left) and bit27=1 (right).
    //
    // To make the trailing-zero count of target_uv exactly equal to
    // target_v_zeros = 27, we OR in a bit at position 27 only when
    // target_bit27 = 1, and at position 27 also serves as the LSB
    // sentinel. For the left-child case (target_bit27 = 0) the
    // target_uv would have all-zero low bits which would make
    // trailing_zeros >= 28; the spec text in §3.2.3 implies that's
    // fine as long as we encode v_mask explicitly. We pass
    // target_v_zeros directly so the walk doesn't have to infer.
    for &target_bit27 in &[0u32, 1] {
        let target_uv = stored_uv | (target_bit27 << 27);
        let target_v_zeros: u8 = 27;

        let got_pk = derive_processing_key(
            &stored_dk,
            stored_uv,
            stored_v_zeros,
            target_uv,
            target_v_zeros,
        )
        .unwrap();

        // Manually derive: aes_g3(stored_dk) then take left/right
        // depending on target_bit27, then aes_g3 again, take
        // processing_key.
        let triple = aes_g3(&stored_dk);
        let intermediate = if target_bit27 == 0 {
            triple.left_child
        } else {
            triple.right_child
        };
        let final_triple = aes_g3(&intermediate);
        assert_eq!(got_pk, final_triple.processing_key);
    }
}

#[test]
fn zero_step_walk_returns_aes_g3_processing_key_directly() {
    // If stored == target, the spec says "is used directly to derive
    // the Processing Key".
    let stored_dk = [0x42u8; 16];
    let pk = derive_processing_key(&stored_dk, 0x1234_5678, 8, 0x1234_5678, 8).unwrap();
    assert_eq!(pk, aes_g3(&stored_dk).processing_key);
}

#[test]
fn applies_test_matches_spec_equation() {
    let sd = SubsetDifference {
        u_mask_zero_bits: 24, // m_u = 0xFF000000
        uv: 0x1101_0000,      // m_v = 0xFFFF0000
    };
    // Device 0x1102_0000: u-prefix matches, v-prefix differs (in the
    // second byte). Spec equation: applies = true.
    assert!(applies_to_device(&sd, 0x1102_0000));
    // Device 0x1101_FFFF: u-prefix matches, v-prefix equals uv's. False.
    assert!(!applies_to_device(&sd, 0x1101_FFFF));
}
