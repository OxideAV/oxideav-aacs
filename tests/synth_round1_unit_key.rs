//! Unit_Key_RO.inf parser + title-key unwrap roundtrip.

use oxideav_aacs::{AacsVolume, CpsUnit, TitleKey, UnitKeyFile, Vuk};

/// Build a synthetic Unit_Key_RO.inf with 3 CPS units whose title
/// keys are AES-128E-encrypted under the supplied VUK.
fn build_unit_key_file(vuk: &Vuk, title_keys: &[[u8; 16]]) -> Vec<u8> {
    let kbs: u32 = 0x80;
    let mut out = vec![0u8; kbs as usize];
    out[0..4].copy_from_slice(&kbs.to_be_bytes());
    out[16] = 0x01; // Application_Type
    out[17] = 0x01; // Num_of_BD_Directory
    out[18] = 0x00;
    out[19] = 0x00;
    // First-Playback / Top-Menu / Num_of_Title = (1, 1, 0).
    out[20..22].copy_from_slice(&1u16.to_be_bytes());
    out[22..24].copy_from_slice(&1u16.to_be_bytes());
    out[24..26].copy_from_slice(&0u16.to_be_bytes());

    out.extend_from_slice(&(title_keys.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0u8; 14]);
    for tk in title_keys {
        out.extend_from_slice(&[0u8; 16]); // MAC of PMSN
        out.extend_from_slice(&[0u8; 16]); // MAC of DBN
        let enc = oxideav_aacs::aes::aes_128_ecb_encrypt(vuk.as_bytes(), tk);
        out.extend_from_slice(&enc);
    }
    out
}

#[test]
fn parses_three_cps_units() {
    let vuk = Vuk::from_bytes([0x11u8; 16]);
    let tks = vec![[0xAAu8; 16], [0xBBu8; 16], [0xCCu8; 16]];
    let bytes = build_unit_key_file(&vuk, &tks);
    let parsed = UnitKeyFile::parse(&bytes).unwrap();
    assert_eq!(parsed.cps_units.len(), 3);
    // Verify each encrypted blob is what we put in.
    for (i, tk) in tks.iter().enumerate() {
        let enc = oxideav_aacs::aes::aes_128_ecb_encrypt(vuk.as_bytes(), tk);
        assert_eq!(parsed.cps_units[i].encrypted_cps_unit_key, enc);
    }
}

#[test]
fn unwrap_title_keys_recovers_originals() {
    // Build a minimal AacsVolume in-memory (no disc I/O).
    let vuk = Vuk::from_bytes([0x33u8; 16]);
    let tks = vec![[0xDDu8; 16], [0xEEu8; 16]];
    let bytes = build_unit_key_file(&vuk, &tks);
    let parsed = UnitKeyFile::parse(&bytes).unwrap();
    let cps_units: Vec<CpsUnit> = parsed
        .cps_units
        .iter()
        .enumerate()
        .map(|(i, rec)| CpsUnit {
            id: (i + 1) as u16,
            encrypted_title_key: rec.encrypted_cps_unit_key,
            title_key: None,
        })
        .collect();
    let mut volume = AacsVolume {
        mkb: oxideav_aacs::Mkb::default(),
        unit_key_file: parsed,
        cps_units,
        disc_root: std::path::PathBuf::new(),
    };
    volume.unwrap_title_keys(&vuk).unwrap();
    for (i, tk) in tks.iter().enumerate() {
        assert_eq!(volume.cps_units[i].title_key, Some(TitleKey(*tk)));
    }
}
