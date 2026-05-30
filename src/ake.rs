//! Phase C — Drive-Host Authentication & Key Exchange (AKE).
//!
//! Implements the AACS Common Final 0.953 §4.3 "AACS Drive
//! Authentication Algorithm" (Figure 4-9) on top of the Phase B SCSI
//! MMC drive-command layer ([`crate::mmc`]). The handshake establishes
//! a shared **Bus Key (BK)** between an AACS Host and a Licensed Drive:
//!
//! 1. Host requests an AGID (`REPORT_KEY` Key Format `0x00`).
//! 2. Host generates nonce `Hn`, sends `Hn || Host_Cert`
//!    (`SEND_KEY` `0x01`). Drive verifies the Host Certificate against
//!    `AACS_LApub` and checks the HRL.
//! 3. Host requests `Dn || Drive_Cert` (`REPORT_KEY` `0x01`). Host
//!    verifies the Drive Certificate against `AACS_LApub` and checks
//!    the DRL.
//! 4. Host requests `Dv || Dsig` (`REPORT_KEY` `0x02`). Host verifies
//!    `AACS_Verify(Drive_pub, Dsig, Hn || Dv)`.
//! 5. Host generates `Hk`, computes `Hv = Hk·G`,
//!    `Hsig = AACS_Sign(Host_priv, Dn || Hv)`, sends `Hv || Hsig`
//!    (`SEND_KEY` `0x02`). Drive verifies `Hsig`.
//! 6. Both sides compute the shared Bus Key:
//!    - Host: `BK = [x-coordinate of Hk·Dv]lsb_128` (§4.3 step 29).
//!    - Drive: `BK = [x-coordinate of Dk·Hv]lsb_128` (§4.3 step 28).
//!
//! Certificate layouts are AACS Common Tables 4-1 (Drive) / 4-2 (Host);
//! both are 92 bytes: `Type(1) Flags(1) Length(2) ID(6) Reserved(2)
//! PubKey(40) Sig(40)`, with `Cert_*sig = bytes 52..91` signed over
//! `Cert_* = bytes 0..51`.
//!
//! This is a **clean-room** implementation from the spec text; no
//! external library source was consulted.

use crate::ec::{Point, U160};
use crate::ecdsa::{self, Signature};
use crate::error::AacsError;
use crate::mmc::{
    build_send_key_host_cert_chal, build_send_key_host_key, parse_report_key_agid,
    parse_report_key_drive_cert_chal, parse_report_key_drive_key, DataDirection, DriveCommand,
    ReadDiscStructure, ReportKey, SendKey, DRIVE_CERT_LEN, EC_POINT_LEN, EC_SIG_LEN, HOST_CERT_LEN,
    HOST_NONCE_LEN,
};

// ---------------------------------------------------------------------
// Certificate field layout (AACS Common Tables 4-1 / 4-2)
// ---------------------------------------------------------------------

/// Certificate Type for a first-generation Licensed Drive (`0x01`,
/// Table 4-1 byte 0).
pub const CERT_TYPE_DRIVE: u8 = 0x01;
/// Certificate Type for a first-generation AACS PC Host (`0x02`,
/// Table 4-2 byte 0).
pub const CERT_TYPE_HOST: u8 = 0x02;
/// Length value carried in certificate bytes 2..3 (`0x005C` = 92).
pub const CERT_LENGTH_VALUE: u16 = 0x005C;

/// Offset of the certificate ID (Drive ID / Host ID), 6 bytes.
const CERT_ID_OFFSET: usize = 4;
/// Length of the certificate ID.
pub const CERT_ID_LEN: usize = 6;
/// Offset of the 40-byte public key inside a certificate.
const CERT_PUBKEY_OFFSET: usize = 12;
/// Offset of the 40-byte signature inside a certificate.
const CERT_SIG_OFFSET: usize = 52;
/// Length of the `Cert_*` body that the certificate signature covers
/// (bytes 0..51 inclusive = 52 bytes).
const CERT_SIGNED_BODY_LEN: usize = 52;

/// A parsed AACS certificate (Drive or Host) — a thin view over the
/// 92-byte on-wire form with the public key extracted as a curve point.
#[derive(Debug, Clone)]
pub struct Certificate {
    /// Certificate Type byte ([`CERT_TYPE_DRIVE`] / [`CERT_TYPE_HOST`]).
    pub cert_type: u8,
    /// Flags byte (byte 1: Reserved + DKS + BEC).
    pub flags: u8,
    /// 6-byte Drive ID / Host ID.
    pub id: [u8; CERT_ID_LEN],
    /// 40-byte public key as a validated curve point.
    pub public_key: Point,
    /// The raw 92-byte certificate (kept for re-serialization +
    /// signature verification).
    pub raw: [u8; 92],
}

impl Certificate {
    /// Parse + structurally validate a 92-byte certificate. Checks the
    /// Certificate Type, the Length field, and that the embedded public
    /// key is a point on the AACS curve. Does **not** verify the
    /// AACS LA signature — use [`Certificate::verify_signature`].
    pub fn parse(raw: &[u8; 92], expected_type: u8) -> Result<Certificate, AacsError> {
        let cert_type = raw[0];
        if cert_type != expected_type {
            return Err(AacsError::InvalidValue {
                what: "Certificate Type",
                value: cert_type as u64,
            });
        }
        let length = ((raw[2] as u16) << 8) | raw[3] as u16;
        if length != CERT_LENGTH_VALUE {
            return Err(AacsError::InvalidValue {
                what: "Certificate Length",
                value: length as u64,
            });
        }
        let mut id = [0u8; CERT_ID_LEN];
        id.copy_from_slice(&raw[CERT_ID_OFFSET..CERT_ID_OFFSET + CERT_ID_LEN]);
        let mut x = [0u8; 20];
        let mut y = [0u8; 20];
        x.copy_from_slice(&raw[CERT_PUBKEY_OFFSET..CERT_PUBKEY_OFFSET + 20]);
        y.copy_from_slice(&raw[CERT_PUBKEY_OFFSET + 20..CERT_PUBKEY_OFFSET + 40]);
        let public_key = Point::from_coords(&x, &y).ok_or(AacsError::InvalidValue {
            what: "Certificate public key not on curve",
            value: 0,
        })?;
        Ok(Certificate {
            cert_type,
            flags: raw[1],
            id,
            public_key,
            raw: *raw,
        })
    }

    /// The Bus Encryption Capable (BEC) bit (byte 1 bit 0).
    pub fn bec(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Verify the certificate's AACS LA signature: `AACS_Verify(
    /// AACS_LApub, Cert_sig, Cert_body)` where `Cert_sig = bytes 52..91`
    /// and `Cert_body = bytes 0..51` (Tables 4-1 / 4-2).
    pub fn verify_signature(&self, aacs_la_pub: &Point) -> bool {
        let mut sig: Signature = [0u8; 40];
        sig.copy_from_slice(&self.raw[CERT_SIG_OFFSET..CERT_SIG_OFFSET + 40]);
        ecdsa::verify(aacs_la_pub, &sig, &self.raw[..CERT_SIGNED_BODY_LEN])
    }
}

/// Assemble a 92-byte certificate from its fields and sign the body
/// with the AACS LA private key. Used by the synthetic test fixtures to
/// mint valid Drive / Host certificates; a production system receives
/// already-signed certificates from AACS LA.
pub fn build_signed_certificate(
    cert_type: u8,
    flags: u8,
    id: &[u8; CERT_ID_LEN],
    public_key: &Point,
    aacs_la_priv: &U160,
) -> [u8; 92] {
    let mut raw = [0u8; 92];
    raw[0] = cert_type;
    raw[1] = flags;
    raw[2] = (CERT_LENGTH_VALUE >> 8) as u8;
    raw[3] = CERT_LENGTH_VALUE as u8;
    raw[CERT_ID_OFFSET..CERT_ID_OFFSET + CERT_ID_LEN].copy_from_slice(id);
    raw[CERT_PUBKEY_OFFSET..CERT_PUBKEY_OFFSET + 40].copy_from_slice(&public_key.to_bytes());
    let sig = ecdsa::sign(aacs_la_priv, &raw[..CERT_SIGNED_BODY_LEN]);
    raw[CERT_SIG_OFFSET..CERT_SIG_OFFSET + 40].copy_from_slice(&sig);
    raw
}

// ---------------------------------------------------------------------
// Bus Key
// ---------------------------------------------------------------------

/// Length of the AACS Bus Key (128 bits).
pub const BUS_KEY_LEN: usize = 16;

/// Compute the Bus Key from a shared elliptic-curve point: the least
/// significant 128 bits of the x-coordinate (§4.3 steps 28 / 29).
pub fn bus_key_from_point(shared: &Point) -> [u8; BUS_KEY_LEN] {
    let x = shared.x_u160().to_be_bytes(); // 20-byte big-endian
    let mut bk = [0u8; BUS_KEY_LEN];
    // lsb_128 = the low 16 bytes of the 20-byte big-endian x-coordinate.
    bk.copy_from_slice(&x[4..]);
    bk
}

// ---------------------------------------------------------------------
// Host-side AKE driver
// ---------------------------------------------------------------------

/// Host credentials needed to drive the AKE: the host's signed
/// certificate, its private signing key, and the AACS LA root public
/// key used to validate the drive's certificate.
#[derive(Debug, Clone)]
pub struct HostCredentials {
    /// 92-byte signed Host Certificate (Table 4-2).
    pub host_cert: [u8; 92],
    /// Host private signing scalar (`Host_priv`).
    pub host_priv: U160,
    /// AACS LA root public key (`AACS_LApub`).
    pub aacs_la_pub: Point,
}

/// Outcome of a completed Host-side authentication.
#[derive(Debug, Clone)]
pub struct AkeResult {
    /// The negotiated 128-bit Bus Key.
    pub bus_key: [u8; BUS_KEY_LEN],
    /// The drive's parsed + verified certificate.
    pub drive_cert: Certificate,
    /// Host nonce used (`Hn`).
    pub host_nonce: [u8; HOST_NONCE_LEN],
    /// Drive nonce received (`Dn`).
    pub drive_nonce: [u8; HOST_NONCE_LEN],
    /// AGID granted by the drive.
    pub agid: u8,
}

/// Run the full §4.3 Host-side AKE against any [`DriveCommand`]
/// transport (the in-process [`crate::mmc::MockDrive`] in tests; a real
/// SCSI back-end in production).
///
/// `host_nonce` (`Hn`) and `hk` (the ephemeral host secret scalar) are
/// supplied by the caller so the handshake is deterministic in tests; a
/// production caller draws both from the §2.2 RNG. Returns the shared
/// Bus Key and verified drive certificate on success.
pub fn host_authenticate<D: DriveCommand>(
    drive: &mut D,
    creds: &HostCredentials,
    host_nonce: &[u8; HOST_NONCE_LEN],
    hk: &U160,
) -> Result<AkeResult, AacsError> {
    // Step 5: acquire AGID.
    let agid_resp = drive.execute(
        &ReportKey::aacs_agid().cdb(),
        DataDirection::FromDevice,
        &[],
        8,
    )?;
    let agid = parse_report_key_agid(&agid_resp.data)?.agid;

    // Steps 6-7: send Hn || Host_Cert.
    let mut host_nonce_arr = [0u8; HOST_NONCE_LEN];
    host_nonce_arr.copy_from_slice(host_nonce);
    let mut host_cert_arr = [0u8; HOST_CERT_LEN];
    host_cert_arr.copy_from_slice(&creds.host_cert);
    let chal = build_send_key_host_cert_chal(&host_nonce_arr, &host_cert_arr);
    let sk = SendKey::aacs_host_cert_challenge(agid);
    drive.execute(
        &sk.cdb(),
        DataDirection::ToDevice,
        &chal,
        sk.parameter_list_length,
    )?;

    // Steps 11-13: request Dn || Drive_Cert.
    let dcc = ReportKey::aacs_drive_cert_challenge(agid);
    let resp = drive.execute(
        &dcc.cdb(),
        DataDirection::FromDevice,
        &[],
        dcc.allocation_length,
    )?;
    let dcc_parsed = parse_report_key_drive_cert_chal(&resp.data)?;
    let drive_nonce = dcc_parsed.drive_nonce;

    // Steps 14-15: structurally validate + verify Drive Certificate.
    let drive_cert = Certificate::parse(&dcc_parsed.drive_cert, CERT_TYPE_DRIVE)?;
    if !drive_cert.verify_signature(&creds.aacs_la_pub) {
        return Err(AacsError::DriveCertSignatureInvalid);
    }

    // Steps 17-21: request Dv || Dsig.
    let dk = ReportKey::aacs_drive_key(agid);
    let dk_resp = drive.execute(
        &dk.cdb(),
        DataDirection::FromDevice,
        &[],
        dk.allocation_length,
    )?;
    let dk_parsed = parse_report_key_drive_key(&dk_resp.data)?;

    // Step 22: verify Dsig over (Hn || Dv).
    let mut signed = Vec::with_capacity(HOST_NONCE_LEN + EC_POINT_LEN);
    signed.extend_from_slice(host_nonce);
    signed.extend_from_slice(&dk_parsed.dv);
    let mut dsig: Signature = [0u8; EC_SIG_LEN];
    dsig.copy_from_slice(&dk_parsed.dsig);
    if !ecdsa::verify(&drive_cert.public_key, &dsig, &signed) {
        return Err(AacsError::DriveSignatureInvalid);
    }

    // The drive's Dv point (validated as on-curve).
    let mut dvx = [0u8; 20];
    let mut dvy = [0u8; 20];
    dvx.copy_from_slice(&dk_parsed.dv[..20]);
    dvy.copy_from_slice(&dk_parsed.dv[20..]);
    let dv = Point::from_coords(&dvx, &dvy).ok_or(AacsError::InvalidValue {
        what: "Drive Dv not on curve",
        value: 0,
    })?;

    // Steps 23-26: compute Hv = Hk·G, Hsig = Sign(Host_priv, Dn || Hv).
    let hv = Point::generator().mul_scalar(hk);
    let hv_bytes = hv.to_bytes();
    let mut hsig_msg = Vec::with_capacity(HOST_NONCE_LEN + EC_POINT_LEN);
    hsig_msg.extend_from_slice(&drive_nonce);
    hsig_msg.extend_from_slice(&hv_bytes);
    let hsig = ecdsa::sign(&creds.host_priv, &hsig_msg);
    let hv_arr: [u8; EC_POINT_LEN] = hv_bytes;
    let host_key_param = build_send_key_host_key(&hv_arr, &hsig);
    let sk2 = SendKey::aacs_host_key(agid);
    drive.execute(
        &sk2.cdb(),
        DataDirection::ToDevice,
        &host_key_param,
        sk2.parameter_list_length,
    )?;

    // Step 29: BK = lsb_128(x-coordinate of Hk·Dv).
    let shared = dv.mul_scalar(hk);
    let bus_key = bus_key_from_point(&shared);

    Ok(AkeResult {
        bus_key,
        drive_cert,
        host_nonce: host_nonce_arr,
        drive_nonce,
        agid,
    })
}

// ---------------------------------------------------------------------
// Drive-side AKE state (used by the authenticating MockDrive + a real
// drive emulator)
// ---------------------------------------------------------------------

/// Mutable drive-side state for the §4.3 AKE. Holds the drive's signed
/// certificate + private key, the AACS LA root key for verifying the
/// host certificate, the ephemeral drive secret `Dk`, and the nonces /
/// host material captured across the multi-command exchange. A real
/// Licensed Drive keeps this per-AGID; the mock keeps a single instance.
#[derive(Debug, Clone)]
pub struct DriveAuthState {
    /// 92-byte signed Drive Certificate (Table 4-1).
    pub drive_cert: [u8; 92],
    /// Drive private signing scalar (`Drive_priv`).
    pub drive_priv: U160,
    /// Ephemeral drive secret `Dk` (`Dv = Dk·G`).
    pub dk: U160,
    /// Drive nonce `Dn` returned to the host.
    pub drive_nonce: [u8; HOST_NONCE_LEN],
    /// AACS LA root public key, for verifying the host certificate.
    pub aacs_la_pub: Point,
    /// Host nonce `Hn` captured from the Host Certificate Challenge.
    pub host_nonce: Option<[u8; HOST_NONCE_LEN]>,
    /// Host certificate captured from the Host Certificate Challenge.
    pub host_cert: Option<[u8; 92]>,
    /// Bus Key the drive derived after verifying `Hsig` (`Dk·Hv`).
    pub bus_key: Option<[u8; BUS_KEY_LEN]>,
}

impl DriveAuthState {
    /// Construct a drive-side AKE state from a freshly-minted identity.
    pub fn new(
        drive_cert: [u8; 92],
        drive_priv: U160,
        dk: U160,
        drive_nonce: [u8; HOST_NONCE_LEN],
        aacs_la_pub: Point,
    ) -> Self {
        Self {
            drive_cert,
            drive_priv,
            dk,
            drive_nonce,
            aacs_la_pub,
            host_nonce: None,
            host_cert: None,
            bus_key: None,
        }
    }

    /// Drive-side handling of the Host Certificate Challenge (`SEND_KEY`
    /// `0x01`, §4.3 steps 8-10): verify the host certificate against
    /// `AACS_LApub`, then stash `Hn` for the later `Dsig`.
    pub fn accept_host_cert_challenge(
        &mut self,
        host_nonce: &[u8; HOST_NONCE_LEN],
        host_cert: &[u8; 92],
    ) -> Result<(), AacsError> {
        let cert = Certificate::parse(host_cert, CERT_TYPE_HOST)?;
        if !cert.verify_signature(&self.aacs_la_pub) {
            return Err(AacsError::HostCertSignatureInvalid);
        }
        self.host_nonce = Some(*host_nonce);
        self.host_cert = Some(*host_cert);
        Ok(())
    }

    /// Produce `Dv || Dsig` (§4.3 steps 18-21): `Dv = Dk·G`,
    /// `Dsig = AACS_Sign(Drive_priv, Hn || Dv)`. Requires that the host
    /// certificate challenge was accepted first (so `Hn` is known).
    pub fn drive_key_response(&self) -> Result<([u8; EC_POINT_LEN], Signature), AacsError> {
        let hn = self
            .host_nonce
            .ok_or(AacsError::Truncated("Hn not yet received"))?;
        let dv = Point::generator().mul_scalar(&self.dk).to_bytes();
        let mut msg = Vec::with_capacity(HOST_NONCE_LEN + EC_POINT_LEN);
        msg.extend_from_slice(&hn);
        msg.extend_from_slice(&dv);
        let dsig = ecdsa::sign(&self.drive_priv, &msg);
        Ok((dv, dsig))
    }

    /// Drive-side handling of the Host Key (`SEND_KEY` `0x02`, §4.3
    /// steps 27-28): verify `Hsig = AACS_Sign(Host_priv, Dn || Hv)`
    /// against the host certificate's public key, then derive the Bus
    /// Key `BK = lsb_128(x(Dk·Hv))`.
    pub fn accept_host_key(
        &mut self,
        hv: &[u8; EC_POINT_LEN],
        hsig: &[u8; EC_SIG_LEN],
    ) -> Result<(), AacsError> {
        let host_cert_raw = self
            .host_cert
            .ok_or(AacsError::Truncated("host cert missing"))?;
        let host_cert = Certificate::parse(&host_cert_raw, CERT_TYPE_HOST)?;
        let mut msg = Vec::with_capacity(HOST_NONCE_LEN + EC_POINT_LEN);
        msg.extend_from_slice(&self.drive_nonce);
        msg.extend_from_slice(hv);
        let mut sig: Signature = [0u8; EC_SIG_LEN];
        sig.copy_from_slice(hsig);
        if !ecdsa::verify(&host_cert.public_key, &sig, &msg) {
            return Err(AacsError::HostSignatureInvalid);
        }
        let mut hvx = [0u8; 20];
        let mut hvy = [0u8; 20];
        hvx.copy_from_slice(&hv[..20]);
        hvy.copy_from_slice(&hv[20..]);
        let hv_point = Point::from_coords(&hvx, &hvy).ok_or(AacsError::InvalidValue {
            what: "Host Hv not on curve",
            value: 0,
        })?;
        let shared = hv_point.mul_scalar(&self.dk);
        self.bus_key = Some(bus_key_from_point(&shared));
        Ok(())
    }
}

/// Read the AACS Volume Identifier after a successful AKE and verify the
/// drive's CMAC under the Bus Key (§4.4): the host recomputes
/// `Hm = CMAC(BK, Volume_ID)` and checks it equals the drive's `Dm`.
/// Returns the 16-byte Volume ID on a verified match.
pub fn read_verified_volume_id<D: DriveCommand>(
    drive: &mut D,
    bus_key: &[u8; BUS_KEY_LEN],
    agid: u8,
) -> Result<[u8; 16], AacsError> {
    let rds = ReadDiscStructure::aacs_volume_id(agid);
    let resp = drive.execute(
        &rds.cdb(),
        DataDirection::FromDevice,
        &[],
        rds.allocation_length,
    )?;
    let vid = crate::mmc::parse_volume_id_response(&resp.data)?;
    let hm = crate::aes::aes_128_cmac(bus_key, &vid.volume_id);
    if hm != vid.mac {
        return Err(AacsError::VolumeIdMacInvalid);
    }
    Ok(vid.volume_id)
}

// Keep the imported length constants referenced so a future refactor
// that drops them is a compile error rather than a silent drift.
const _: () = {
    assert!(DRIVE_CERT_LEN == 92);
    assert!(HOST_CERT_LEN == 92);
    assert!(EC_POINT_LEN == 40);
    assert!(EC_SIG_LEN == 40);
    assert!(HOST_NONCE_LEN == 20);
};

/// AACS LA root public key — x-coordinate (20 bytes, big-endian) of
/// the secp160r1 point `AACS_LApub`. Used by every AACS-compliant
/// licensee to verify signatures the AACS LA issues over drive /
/// host certificates and MKB records (§4.1, §3.2.5.1.2/.3/.8). The
/// value is published as a spec constant in the AACS Common Final
/// 0.953 document; it is not a per-licensee secret.
pub const AACS_LA_PUB_X: [u8; 20] = [
    0x63, 0xC2, 0x1D, 0xFF, 0xB2, 0xB2, 0x79, 0x8A, 0x13, 0xB5, 0x8D, 0x61, 0x16, 0x6C, 0x4E, 0x4A,
    0xAC, 0x8A, 0x07, 0x72,
];

/// AACS LA root public key — y-coordinate (20 bytes, big-endian),
/// companion to [`AACS_LA_PUB_X`].
pub const AACS_LA_PUB_Y: [u8; 20] = [
    0x13, 0x7E, 0xC6, 0x38, 0x81, 0x8F, 0xD9, 0x8F, 0xA4, 0xC3, 0x0B, 0x99, 0x67, 0x28, 0xBF, 0x4B,
    0x91, 0x7F, 0x6A, 0x27,
];

/// Construct the AACS LA root public key as an on-curve secp160r1
/// [`Point`]. Panics only if the spec constants drift away from the
/// curve (which would be a build-time error caught by the test
/// [`tests::aacs_la_pub_is_on_curve`]).
pub fn aacs_la_pub_point() -> Point {
    Point::from_coords(&AACS_LA_PUB_X, &AACS_LA_PUB_Y)
        .expect("AACS_LA_PUB constants must lie on secp160r1")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_scalar(v: u32) -> U160 {
        U160 {
            limbs: [v, 0, 0, 0, 0],
        }
    }

    #[test]
    fn certificate_parse_rejects_wrong_type() {
        let la_priv = small_scalar(0x00ab_cdef);
        let cert = build_signed_certificate(
            CERT_TYPE_HOST,
            0,
            &[1, 2, 3, 4, 5, 6],
            &Point::generator().mul_scalar(&small_scalar(42)),
            &la_priv,
        );
        assert!(Certificate::parse(&cert, CERT_TYPE_DRIVE).is_err());
        assert!(Certificate::parse(&cert, CERT_TYPE_HOST).is_ok());
    }

    #[test]
    fn certificate_signature_round_trip() {
        let la_priv = small_scalar(0x0012_3456);
        let la_pub = Point::generator().mul_scalar(&la_priv);
        let cert_priv = small_scalar(0x0065_4321);
        let cert_pub = Point::generator().mul_scalar(&cert_priv);
        let raw =
            build_signed_certificate(CERT_TYPE_DRIVE, 0, &[9, 8, 7, 6, 5, 4], &cert_pub, &la_priv);
        let cert = Certificate::parse(&raw, CERT_TYPE_DRIVE).unwrap();
        assert!(cert.verify_signature(&la_pub));
        // Wrong LA key must reject.
        let wrong_la = Point::generator().mul_scalar(&small_scalar(0x0099_9999));
        assert!(!cert.verify_signature(&wrong_la));
    }

    #[test]
    fn bus_key_is_low_128_bits_of_x() {
        let p = Point::generator().mul_scalar(&small_scalar(12345));
        let bk = bus_key_from_point(&p);
        let x = p.x_u160().to_be_bytes();
        assert_eq!(&bk[..], &x[4..]);
    }

    #[test]
    fn aacs_la_pub_is_on_curve() {
        // The bundled spec constants must construct a valid secp160r1
        // point. A drift in the bytes would silently break every AKE
        // handshake — pin it here.
        assert!(Point::from_coords(&AACS_LA_PUB_X, &AACS_LA_PUB_Y).is_some());
        let _ = aacs_la_pub_point();
    }

    #[test]
    fn ecdh_bus_keys_agree() {
        // Independent of MMC plumbing: Hk·Dv and Dk·Hv share an
        // x-coordinate, so both sides derive the same Bus Key (§4.3
        // steps 28/29).
        let dk = small_scalar(0x0013_5790);
        let hk = small_scalar(0x0024_6801);
        let dv = Point::generator().mul_scalar(&dk);
        let hv = Point::generator().mul_scalar(&hk);
        let host_bk = bus_key_from_point(&dv.mul_scalar(&hk));
        let drive_bk = bus_key_from_point(&hv.mul_scalar(&dk));
        assert_eq!(host_bk, drive_bk);
    }
}
