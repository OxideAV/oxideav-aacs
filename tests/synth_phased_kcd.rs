//! Phase D — Type-4 / Key Conversion Data integration tests.
//!
//! These tests exercise the Common spec §3.2.5.1.4 + BD-Prerecorded
//! §3.8 KCD-post-processing decision path through synthetic, fully
//! self-constructed MKB material (no real-disc keys, no real-disc
//! fixtures).
//!
//! The scenarios pinned here:
//!
//! 1. **Type-4 with valid KCD** — the precursor does NOT verify, the
//!    KCD-converted Media Key does verify, and the VUK ultimately
//!    derives correctly.
//! 2. **Type-4 with wrong KCD** — neither verifies, the helper surfaces
//!    `MediaKeyVerificationFailed`.
//! 3. **"Old MKB" fallback** — Type-4 MKB whose precursor happens to
//!    verify directly. The spec mandates the device must NOT apply KCD
//!    in that case. We pin that the right Vuk is produced and that
//!    supplying KCD makes no difference.
//! 4. **No KCD on a Type-4 MKB whose precursor doesn't verify** —
//!    surfaces `MediaKeyVerificationFailed` (not silent acceptance).
//! 5. **Type-3 path with a KCD argument** — the KCD must be ignored
//!    because the precursor / Km already verifies.

use oxideav_aacs::aes::{aes_128_ecb_encrypt, aes_g};
use oxideav_aacs::keydb::KeyDb;
use oxideav_aacs::subdiff::{
    apply_key_conversion_data, derive_processing_key, media_key_from_processing_key,
    SubsetDifference,
};
use oxideav_aacs::volume::{AacsVolume, DeviceKey};
use oxideav_aacs::{AacsError, Mkb};

/// The single Explicit Subset-Difference entry the synthetic MKB
/// carries. Chosen so that the synthetic device (see
/// [`SYNTH_DEVICE_UV`]) lands in the SD's `(u_mask, v_mask)` mask
/// region per the Common spec §3.2.4 applies-equation:
/// `(D_node & m_u) == (sd.uv & m_u) && (D_node & m_v) != (sd.uv & m_v)`.
const SYNTH_SD_U_MASK_ZEROS: u8 = 24; // m_u = 0xFF00_0000
const SYNTH_SD_UV: u32 = 0x1101_0000; // m_v = 0xFFFF_0000 (low bit at pos 16)
const SYNTH_SD_V_MASK_ZEROS: u8 = 16; // sd.uv.trailing_zeros()

/// The synthetic device's `uv` and `v_mask_zero_bits`. The volume
/// code computes `d_node = (device.uv << 1) | 1` so we shift our
/// target `d_node = 0x1102_0001` (matches SD u-prefix, differs in
/// v-prefix) back into a `device.uv` value.
const SYNTH_DEVICE_UV: u32 = 0x0881_0000; // (0x1102_0001 >> 1) & ~1
const SYNTH_DEVICE_V_ZEROS: u8 = 16; // == SYNTH_SD_V_MASK_ZEROS → zero-step walk

/// Stitch a single-SD MKB on-the-fly. `vd` is the 16-byte Verify
/// Media Key Record ciphertext; tests construct it to pass under
/// either the precursor (forcing the "old MKB" path) or the post-KCD
/// Media Key (forcing the normal path).
fn build_synth_type4_mkb(mkb_type_raw: u32, enc_km: [u8; 16], vd: [u8; 16]) -> Vec<u8> {
    let mut bytes = Vec::new();
    // 0x10 Type and Version (MKBType + Version Number).
    let mut tv = Vec::new();
    tv.extend_from_slice(&mkb_type_raw.to_be_bytes());
    tv.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend(write_record(0x10, &tv));
    // 0x81 Verify Media Key — 16-byte Vd payload.
    bytes.extend(write_record(0x81, &vd));
    // 0x04 Explicit Subset-Difference — one entry (u-mask byte + 4
    // bytes uv big-endian).
    let mut sd_payload = vec![SYNTH_SD_U_MASK_ZEROS];
    sd_payload.extend_from_slice(&SYNTH_SD_UV.to_be_bytes());
    bytes.extend(write_record(0x04, &sd_payload));
    // 0x05 Media Key Data — single 16-byte ciphertext.
    bytes.extend(write_record(0x05, &enc_km));
    // 0x02 End of MKB — signature payload not validated.
    bytes.extend(write_record(0x02, &[0u8; 40]));
    bytes
}

fn write_record(tag: u8, body: &[u8]) -> Vec<u8> {
    let length = 4 + body.len();
    let mut out = vec![
        tag,
        ((length >> 16) & 0xFF) as u8,
        ((length >> 8) & 0xFF) as u8,
        (length & 0xFF) as u8,
    ];
    out.extend_from_slice(body);
    out
}

/// Construct a Verify Media Key Record `Vd` whose decrypted high-order
/// 64 bits equal the spec sentinel under `km`.
fn make_vd_for(km: &[u8; 16]) -> [u8; 16] {
    // [AES-128D(Km, Vd)]_msb_64 == 0x0123_4567_89AB_CDEF, so
    //  Vd = AES-128E(Km, sentinel || trailing).
    let mut plaintext = [0u8; 16];
    plaintext[..8].copy_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
    // Trailing 8 bytes are spec-defined-arbitrary.
    plaintext[8..].copy_from_slice(&[0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49]);
    aes_128_ecb_encrypt(km, &plaintext)
}

/// Compose the precursor `K_mp` (== `K_m` for a Type-3 MKB) that the
/// Subset-Difference walk inside `derive_media_key_from_device_key`
/// produces for the synthetic 1-entry MKB defined above, given the
/// Device Key. `enc_km` is the Media Key Data Record ciphertext.
fn precursor_for(device_key: &[u8; 16], enc_km: &[u8; 16]) -> [u8; 16] {
    let pk = derive_processing_key(
        device_key,
        SYNTH_DEVICE_UV,
        SYNTH_DEVICE_V_ZEROS,
        SYNTH_SD_UV,
        SYNTH_SD_V_MASK_ZEROS,
    )
    .unwrap();
    media_key_from_processing_key(&pk, SYNTH_SD_UV, enc_km)
}

/// Returns `(precursor, enc_km, device, device_key_bytes)`. Test
/// helpers rebuild MKBs with different `Vd` payloads against this
/// fixed synthetic key material.
fn synth_inputs() -> ([u8; 16], [u8; 16], DeviceKey, [u8; 16]) {
    let device_key = [0x33u8; 16];
    let enc_km: [u8; 16] = [0xAA; 16];
    let precursor = precursor_for(&device_key, &enc_km);
    let device = DeviceKey {
        key: device_key,
        uv: SYNTH_DEVICE_UV,
        u_mask_zero_bits: SYNTH_SD_U_MASK_ZEROS,
        v_mask_zero_bits: SYNTH_DEVICE_V_ZEROS,
        device_node: None,
    };
    (precursor, enc_km, device, device_key)
}

/// Sanity-check the synthetic SD configuration so a future change to
/// the SD layout produces an obvious assertion failure rather than a
/// silent "DeviceRevoked" everywhere.
#[test]
fn synth_sd_applies_to_synth_device() {
    use oxideav_aacs::applies_to_device;
    let sd = SubsetDifference {
        u_mask_zero_bits: SYNTH_SD_U_MASK_ZEROS,
        uv: SYNTH_SD_UV,
    };
    let d_node = (SYNTH_DEVICE_UV << 1) | 1;
    assert!(
        applies_to_device(&sd, d_node),
        "synthetic SD must apply to synthetic device d_node=0x{d_node:08X}"
    );
    assert_eq!(SYNTH_SD_UV.trailing_zeros() as u8, SYNTH_SD_V_MASK_ZEROS);
}

#[test]
fn type4_path_applies_kcd_then_verifies_and_derives_vuk() {
    let (precursor, enc_km, device, _) = synth_inputs();
    let kcd: [u8; 16] = [
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xF0, 0x0D, 0xFA, 0xCE, 0x12, 0x34, 0x56,
        0x78,
    ];
    let km = apply_key_conversion_data(&precursor, &kcd);
    // Vd is keyed under the *post-KCD* km, NOT the precursor — this is
    // the normal Type-4 case.
    let vd = make_vd_for(&km);
    // Bit-flip the precursor's Vd-equivalent (sanity: precursor must
    // NOT verify under this Vd).
    let mkb_bytes = build_synth_type4_mkb(0x0004_1003, enc_km, vd);
    let mkb = Mkb::parse(&mkb_bytes).unwrap();
    assert!(!mkb.is_verified_media_key(&precursor));
    assert!(mkb.is_verified_media_key(&km));

    let volume = AacsVolume {
        mkb,
        unit_key_file: oxideav_aacs::unit_key::UnitKeyFile {
            unit_key_block_start_address: 0,
            header: oxideav_aacs::unit_key::UnitKeyFileHeader {
                application_type: 1,
                num_of_bd_directory: 1,
                use_skb_unified_mkb: false,
                bd_directories: Vec::new(),
            },
            cps_units: Vec::new(),
        },
        cps_units: Vec::new(),
        disc_root: std::path::PathBuf::new(),
    };
    let volume_id = [0x77u8; 16];
    let vuk = volume
        .derive_vuk_from_device_key_with_kcd(&device, &volume_id, Some(&kcd))
        .expect("Type-4 + KCD must derive a VUK");
    // Compare to the direct AES-G(km, ID_v).
    let expected = aes_g(&km, &volume_id);
    assert_eq!(vuk.as_bytes(), &expected);
}

#[test]
fn type4_with_wrong_kcd_surfaces_verification_failure() {
    let (precursor, enc_km, device, _) = synth_inputs();
    let real_kcd = [0x11u8; 16];
    let wrong_kcd = [0x22u8; 16];
    let km = apply_key_conversion_data(&precursor, &real_kcd);
    let vd = make_vd_for(&km);
    let mkb_bytes = build_synth_type4_mkb(0x0004_1003, enc_km, vd);
    let mkb = Mkb::parse(&mkb_bytes).unwrap();
    let volume = volume_around(mkb);
    let volume_id = [0x77u8; 16];
    let err = volume
        .derive_vuk_from_device_key_with_kcd(&device, &volume_id, Some(&wrong_kcd))
        .unwrap_err();
    assert!(matches!(err, AacsError::MediaKeyVerificationFailed));
}

#[test]
fn type4_old_mkb_precursor_verifies_directly_kcd_ignored() {
    // The spec's "old MKB" rule: a Type-4 MKB whose precursor already
    // verifies under the Verify Media Key Record represents the case
    // where the KCD hasn't been incorporated into this part of the
    // tree yet. The device must NOT apply KCD; the precursor is the
    // Media Key.
    let (precursor, enc_km, device, _) = synth_inputs();
    let vd = make_vd_for(&precursor);
    let mkb_bytes = build_synth_type4_mkb(0x0004_1003, enc_km, vd);
    let mkb = Mkb::parse(&mkb_bytes).unwrap();
    assert!(mkb.is_verified_media_key(&precursor));
    let volume = volume_around(mkb);
    let volume_id = [0x77u8; 16];
    let real_kcd: [u8; 16] = [
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xF0, 0x0D, 0xFA, 0xCE, 0x12, 0x34, 0x56,
        0x78,
    ];
    let vuk_no_kcd = volume
        .derive_vuk_from_device_key_with_kcd(&device, &volume_id, None)
        .unwrap();
    let vuk_with_kcd = volume
        .derive_vuk_from_device_key_with_kcd(&device, &volume_id, Some(&real_kcd))
        .unwrap();
    // KCD must be ignored when the precursor verifies directly — both
    // branches must produce the same VUK.
    assert_eq!(vuk_no_kcd.as_bytes(), vuk_with_kcd.as_bytes());
    // And the VUK must match AES-G(precursor, ID_v).
    let expected = aes_g(&precursor, &volume_id);
    assert_eq!(vuk_no_kcd.as_bytes(), &expected);
}

#[test]
fn type4_no_kcd_supplied_when_kcd_was_needed_errors() {
    let (precursor, enc_km, device, _) = synth_inputs();
    let real_kcd = [0x99u8; 16];
    let km = apply_key_conversion_data(&precursor, &real_kcd);
    let vd = make_vd_for(&km);
    let mkb_bytes = build_synth_type4_mkb(0x0004_1003, enc_km, vd);
    let mkb = Mkb::parse(&mkb_bytes).unwrap();
    let volume = volume_around(mkb);
    let volume_id = [0x77u8; 16];
    let err = volume
        .derive_vuk_from_device_key_with_kcd(&device, &volume_id, None)
        .unwrap_err();
    assert!(matches!(err, AacsError::MediaKeyVerificationFailed));
}

#[test]
fn type3_path_ignores_supplied_kcd() {
    // Type-3 (canonical MKB): SD walk returns Km directly. Even if
    // a caller passes a KCD argument (e.g. because it's bound through
    // KEYDB.cfg without checking MKB type), the verify path picks the
    // precursor and short-circuits, so KCD doesn't affect the result.
    let (km, enc_km, device, _) = synth_inputs();
    let vd = make_vd_for(&km);
    let mkb_bytes = build_synth_type4_mkb(0x0003_1003, enc_km, vd);
    let mkb = Mkb::parse(&mkb_bytes).unwrap();
    let volume = volume_around(mkb);
    let volume_id = [0x77u8; 16];
    let kcd = [0x44u8; 16];

    let vuk_a = volume
        .derive_vuk_from_device_key(&device, &volume_id)
        .unwrap();
    let vuk_b = volume
        .derive_vuk_from_device_key_with_kcd(&device, &volume_id, Some(&kcd))
        .unwrap();
    assert_eq!(vuk_a.as_bytes(), vuk_b.as_bytes());
}

#[test]
fn kcd_record_loads_from_keydb_disc_record() {
    // Show that the KCD value end-users would pass into
    // derive_vuk_from_device_key_with_kcd typically comes out of
    // KEYDB.cfg's per-disc record. The KCD payload in KEYDB.cfg is the
    // first 16 bytes of the `| KCD |` value (BD-Prerecorded Table 3-11
    // gives KCD as exactly 16 bytes; longer hex strings in the wild
    // include label / version metadata the spec doesn't define).
    let text = "\
| DISCID | 0x0123456789ABCDEF0123456789ABCDEF01234567 ; Synthetic\n\
| KCD | 0xDEADBEEFCAFEBABEF00DFACE12345678AABBCCDD \n\
";
    let db = KeyDb::parse(text).unwrap();
    let did = parse_hex_20("0123456789ABCDEF0123456789ABCDEF01234567");
    let rec = db.disc_record(&did).unwrap();
    let raw = rec.kcd.as_deref().unwrap();
    assert!(raw.len() >= 16);
    let mut kcd16 = [0u8; 16];
    kcd16.copy_from_slice(&raw[..16]);
    assert_eq!(kcd16[0], 0xDE);
    assert_eq!(kcd16[15], 0x78);
}

fn parse_hex_20(s: &str) -> [u8; 20] {
    let mut out = [0u8; 20];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn volume_around(mkb: Mkb) -> AacsVolume {
    AacsVolume {
        mkb,
        unit_key_file: oxideav_aacs::unit_key::UnitKeyFile {
            unit_key_block_start_address: 0,
            header: oxideav_aacs::unit_key::UnitKeyFileHeader {
                application_type: 1,
                num_of_bd_directory: 1,
                use_skb_unified_mkb: false,
                bd_directories: Vec::new(),
            },
            cps_units: Vec::new(),
        },
        cps_units: Vec::new(),
        disc_root: std::path::PathBuf::new(),
    }
}
