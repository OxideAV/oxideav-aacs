//! AACS On-line / Enhanced-Title permission Title-Key derivation
//! (Blu-ray Disc Pre-recorded Book §4.4.1.5.2, cross-referencing the
//! Introduction and Common Cryptographic Elements Book §5.3).
//!
//! An **Enhanced Title** cannot be played from the disc alone: the
//! player must obtain a *Permission* from a Remote Server before it can
//! recover the Title Key. The transaction (Common §5.3) is:
//!
//! 1. The AACS layer generates a 128-bit `Nonce`.
//! 2. The player sends the `Nonce` (plus `Content ID` / `title_id`, and
//!    payment data) to the Remote Server.
//! 3. On success the server returns a 16-byte **message** — the
//!    Encrypted Title Key — computed for BD-ROM (§4.4.1.5.2) as:
//!
//!    ```text
//!    message = AES-128E(Kvu, Kt XOR Nonce XOR AES_H(Volume ID || title_id))
//!    ```
//!
//! 4. `setPermission(message)` verifies the message by recomputing the
//!    same formula from the values the player already holds
//!    (`Kvu`, `Kt`, `Nonce`, `Volume ID`, `title_id`) and comparing.
//!
//! Here `title_id` is 4 bytes (§4.4.1.5.2), `Volume ID` is 16 bytes,
//! and `AES_H` is the AACS AES-based hash ([`crate::aes::aes_h`]) over
//! the 20-byte concatenation.
//!
//! This module carries no key material — every key is a caller
//! argument; the tests mint synthetic values and round-trip.

use crate::aes::{aes_128_ecb_decrypt, aes_128_ecb_encrypt, aes_h};

/// Byte length of the on-line `title_id` used in the Enhanced Title Key
/// formula (§4.4.1.5.2 — "title_id is 4 bytes").
pub const ONLINE_TITLE_ID_LEN: usize = 4;

/// Length of the Remote-Server permission message / Encrypted Title Key.
pub const PERMISSION_MESSAGE_LEN: usize = 16;

/// `AES_H(Volume ID || title_id)` — the per-title binding hash mixed
/// into the Enhanced Title Key formula. `title_id` is serialized as its
/// 4-byte big-endian form per §4.4.1.5.2.
pub fn title_binding_hash(volume_id: &[u8; 16], title_id: u32) -> [u8; 16] {
    let mut buf = [0u8; 16 + ONLINE_TITLE_ID_LEN];
    buf[..16].copy_from_slice(volume_id);
    buf[16..].copy_from_slice(&title_id.to_be_bytes());
    aes_h(&buf)
}

/// The XOR mask `Kt XOR AES_H(Volume ID || title_id)` combined with the
/// Nonce: returns `plaintext = Kt XOR Nonce XOR AES_H(Volume ID ||
/// title_id)`, the 16-byte block that is AES-128E-encrypted under `Kvu`
/// to form the message.
fn permission_plaintext(
    kt: &[u8; 16],
    nonce: &[u8; 16],
    volume_id: &[u8; 16],
    title_id: u32,
) -> [u8; 16] {
    let h = title_binding_hash(volume_id, title_id);
    let mut p = [0u8; 16];
    for i in 0..16 {
        p[i] = kt[i] ^ nonce[i] ^ h[i];
    }
    p
}

/// **Remote-Server side.** Compute the 16-byte permission message that
/// grants an Enhanced Title (BD-Prerecorded §4.4.1.5.2):
///
/// ```text
/// AES-128E(Kvu, Kt XOR Nonce XOR AES_H(Volume ID || title_id))
/// ```
pub fn enhanced_title_key_message(
    kvu: &[u8; 16],
    kt: &[u8; 16],
    nonce: &[u8; 16],
    volume_id: &[u8; 16],
    title_id: u32,
) -> [u8; 16] {
    let p = permission_plaintext(kt, nonce, volume_id, title_id);
    aes_128_ecb_encrypt(kvu, &p)
}

/// **Player side.** Recover the Title Key `Kt` from a server permission
/// message by inverting the §4.4.1.5.2 formula:
///
/// ```text
/// Kt = AES-128D(Kvu, message) XOR Nonce XOR AES_H(Volume ID || title_id)
/// ```
pub fn recover_enhanced_title_key(
    kvu: &[u8; 16],
    message: &[u8; 16],
    nonce: &[u8; 16],
    volume_id: &[u8; 16],
    title_id: u32,
) -> [u8; 16] {
    let d = aes_128_ecb_decrypt(kvu, message);
    let h = title_binding_hash(volume_id, title_id);
    let mut kt = [0u8; 16];
    for i in 0..16 {
        kt[i] = d[i] ^ nonce[i] ^ h[i];
    }
    kt
}

/// Constant-time equality of two 16-byte blocks (no early-out on the
/// first differing byte).
fn ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut acc = 0u8;
    for i in 0..16 {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

/// **`setPermission()` verification** (§4.4.1.5.2.2). Recompute the
/// permission message from the values the player holds and compare, in
/// constant time, against the `message` received from the Remote
/// Server. Returns `true` when the Permission is valid and the Title
/// may be activated.
pub fn verify_enhanced_permission(
    kvu: &[u8; 16],
    kt: &[u8; 16],
    nonce: &[u8; 16],
    volume_id: &[u8; 16],
    title_id: u32,
    message: &[u8; 16],
) -> bool {
    let expected = enhanced_title_key_message(kvu, kt, nonce, volume_id, title_id);
    ct_eq_16(&expected, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KVU: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    const KT: [u8; 16] = [0xA5; 16];
    const NONCE: [u8; 16] = [
        0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1,
        0xF0,
    ];
    const VOLUME_ID: [u8; 16] = [0x11; 16];

    #[test]
    fn message_recovers_title_key() {
        let msg = enhanced_title_key_message(&KVU, &KT, &NONCE, &VOLUME_ID, 0x0000_002A);
        let kt = recover_enhanced_title_key(&KVU, &msg, &NONCE, &VOLUME_ID, 0x0000_002A);
        assert_eq!(kt, KT);
    }

    #[test]
    fn verify_accepts_correct_message() {
        let msg = enhanced_title_key_message(&KVU, &KT, &NONCE, &VOLUME_ID, 7);
        assert!(verify_enhanced_permission(
            &KVU, &KT, &NONCE, &VOLUME_ID, 7, &msg
        ));
    }

    #[test]
    fn verify_rejects_wrong_nonce_or_title() {
        let msg = enhanced_title_key_message(&KVU, &KT, &NONCE, &VOLUME_ID, 7);
        let mut bad_nonce = NONCE;
        bad_nonce[0] ^= 1;
        assert!(!verify_enhanced_permission(
            &KVU, &KT, &bad_nonce, &VOLUME_ID, 7, &msg
        ));
        // Same nonce, different title_id must not verify.
        assert!(!verify_enhanced_permission(
            &KVU, &KT, &NONCE, &VOLUME_ID, 8, &msg
        ));
    }

    #[test]
    fn nonce_binds_the_message() {
        // Two distinct nonces yield distinct messages for the same Kt.
        let m1 = enhanced_title_key_message(&KVU, &KT, &NONCE, &VOLUME_ID, 1);
        let mut n2 = NONCE;
        n2[15] ^= 0xFF;
        let m2 = enhanced_title_key_message(&KVU, &KT, &n2, &VOLUME_ID, 1);
        assert_ne!(m1, m2);
    }

    #[test]
    fn title_binding_hash_depends_on_title_id() {
        let h1 = title_binding_hash(&VOLUME_ID, 1);
        let h2 = title_binding_hash(&VOLUME_ID, 2);
        assert_ne!(h1, h2);
    }
}
