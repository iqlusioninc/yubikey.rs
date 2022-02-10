//! Integration tests

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, trivial_casts, unused_qualifications)]

use lazy_static::lazy_static;
use log::trace;
use rand_core::{OsRng, RngCore};
use rsa::{hash::Hash::SHA2_256, PaddingScheme, PublicKey};
use sha2::{Digest, Sha256};
use std::{env, sync::Mutex};
use x509::RelativeDistinguishedName;
use yubikey::certificate::Serial;
use yubikey::{
    certificate::{Certificate, PublicKeyInfo},
    piv::{self, AlgorithmId, Key, RetiredSlotId, SlotId},
    Error, MgmKey, PinPolicy, TouchPolicy, YubiKey,
};

lazy_static! {
    /// Provide thread-safe access to a YubiKey
    static ref YUBIKEY: Mutex<YubiKey> = init_yubikey();
}

/// One-time test initialization and setup
fn init_yubikey() -> Mutex<YubiKey> {
    // Only show logs if `RUST_LOG` is set
    if env::var("RUST_LOG").is_ok() {
        env_logger::builder().format_timestamp(None).init();
    }

    let yubikey = YubiKey::open().unwrap();
    trace!("serial: {}", yubikey.serial());
    trace!("version: {}", yubikey.version());

    Mutex::new(yubikey)
}

//
// CCCID support
//

#[test]
#[ignore]
fn test_get_cccid() {
    let mut yubikey = YUBIKEY.lock().unwrap();

    match yubikey.cccid() {
        Ok(cccid) => trace!("CCCID: {:?}", cccid),
        Err(Error::NotFound) => trace!("CCCID not found"),
        Err(err) => panic!("error getting CCCID: {:?}", err),
    }
}

//
// CHUID support
//

#[test]
#[ignore]
fn test_get_chuid() {
    let mut yubikey = YUBIKEY.lock().unwrap();

    match yubikey.chuid() {
        Ok(chuid) => trace!("CHUID: {:?}", chuid),
        Err(Error::NotFound) => trace!("CHUID not found"),
        Err(err) => panic!("error getting CHUID: {:?}", err),
    }
}

//
// Device config support
//

#[test]
#[ignore]
fn test_get_config() {
    let mut yubikey = YUBIKEY.lock().unwrap();
    let config_result = yubikey.config();
    assert!(config_result.is_ok());
    trace!("config: {:?}", config_result.unwrap());
}

//
// Cryptographic key support
//

#[test]
#[ignore]
fn test_list_keys() {
    let mut yubikey = YUBIKEY.lock().unwrap();
    let keys_result = Key::list(&mut yubikey);
    assert!(keys_result.is_ok());
    trace!("keys: {:?}", keys_result.unwrap());
}

//
// PIN support
//

#[test]
#[ignore]
fn test_verify_pin() {
    let mut yubikey = YUBIKEY.lock().unwrap();
    assert!(yubikey.verify_pin(b"000000").is_err());
    assert!(yubikey.verify_pin(b"123456").is_ok());
}

//
// Management key support
//

#[cfg(feature = "untested")]
#[test]
#[ignore]
fn test_set_mgmkey() {
    let mut yubikey = YUBIKEY.lock().unwrap();

    assert!(yubikey.verify_pin(b"123456").is_ok());
    assert!(MgmKey::get_protected(&mut yubikey).is_err());
    assert!(yubikey.authenticate(MgmKey::default()).is_ok());

    // Set a protected management key.
    assert!(MgmKey::generate().set_protected(&mut yubikey).is_ok());
    let protected = MgmKey::get_protected(&mut yubikey).unwrap();
    assert!(yubikey.authenticate(MgmKey::default()).is_err());
    assert!(yubikey.authenticate(protected.clone()).is_ok());

    // Set a manual management key.
    let manual = MgmKey::generate();
    assert!(manual.set_manual(&mut yubikey, false).is_ok());
    assert!(MgmKey::get_protected(&mut yubikey).is_err());
    assert!(yubikey.authenticate(MgmKey::default()).is_err());
    assert!(yubikey.authenticate(protected.clone()).is_err());
    assert!(yubikey.authenticate(manual.clone()).is_ok());

    // Set back to the default management key.
    assert!(MgmKey::set_default(&mut yubikey).is_ok());
    assert!(MgmKey::get_protected(&mut yubikey).is_err());
    assert!(yubikey.authenticate(protected).is_err());
    assert!(yubikey.authenticate(manual).is_err());
    assert!(yubikey.authenticate(MgmKey::default()).is_ok());
}

//
// Certificate support
//

fn generate_self_signed_cert(algorithm: AlgorithmId) -> Certificate {
    let mut yubikey = YUBIKEY.lock().unwrap();

    assert!(yubikey.verify_pin(b"123456").is_ok());
    assert!(yubikey.authenticate(MgmKey::default()).is_ok());

    let slot = SlotId::Retired(RetiredSlotId::R1);

    // Generate a new key in the selected slot.
    let generated = piv::generate(
        &mut yubikey,
        slot,
        algorithm,
        PinPolicy::Default,
        TouchPolicy::Default,
    )
    .unwrap();

    let mut serial = [0u8; 20];
    OsRng.fill_bytes(&mut serial);

    // Generate a self-signed certificate for the new key.
    let extensions: &[x509::Extension<'_, &[u64]>] = &[];
    let cert_result = Certificate::generate_self_signed(
        &mut yubikey,
        slot,
        serial,
        None,
        &[RelativeDistinguishedName::common_name("testSubject")],
        generated,
        extensions,
    );

    assert!(cert_result.is_ok());
    let cert = cert_result.unwrap();
    trace!("cert: {:?}", cert);
    cert
}

#[test]
#[ignore]
fn generate_self_signed_rsa_cert() {
    let cert = generate_self_signed_cert(AlgorithmId::Rsa1024);

    //
    // Verify that the certificate is signed correctly
    //

    let pubkey = match cert.subject_pki() {
        PublicKeyInfo::Rsa { pubkey, .. } => pubkey,
        _ => unreachable!(),
    };

    let data = cert.as_ref();
    let tbs_cert_len = u16::from_be_bytes(data[6..8].try_into().unwrap()) as usize;
    let msg = &data[4..8 + tbs_cert_len];
    let sig = &data[data.len() - 128..];

    let hash = Sha256::digest(msg);

    assert!(pubkey
        .verify(
            PaddingScheme::PKCS1v15Sign {
                hash: Some(SHA2_256)
            },
            &hash,
            sig
        )
        .is_ok());
}

#[test]
#[ignore]
fn generate_self_signed_ec_cert() {
    let cert = generate_self_signed_cert(AlgorithmId::EccP256);

    //
    // Verify that the certificate is signed correctly
    //

    let pubkey = match cert.subject_pki() {
        PublicKeyInfo::EcP256(pubkey) => pubkey,
        _ => unreachable!(),
    };

    let data = cert.as_ref();
    let tbs_cert_len = data[6] as usize;
    let sig_algo_len = data[7 + tbs_cert_len + 1] as usize;
    let sig_start = 7 + tbs_cert_len + 2 + sig_algo_len + 3;
    let msg = &data[4..7 + tbs_cert_len];
    let sig = p256::ecdsa::Signature::from_der(&data[sig_start..]).unwrap();
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(pubkey.as_bytes()).unwrap();

    use p256::ecdsa::signature::Verifier;
    assert!(vk.verify(msg, &sig).is_ok());
}

#[test]
#[ignore]
fn test_serial_string_conversions() {
    //2^152+1
    let serial: [u8; 20] = [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    let s: Serial = Serial::from(serial);
    assert_eq!(
        s.as_x509_int(),
        "5708990770823839524233143877797980545530986497"
    );
    assert_eq!(
        s.as_x509_hex(),
        "01:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01"
    );

    let serial2: [u8; 20] = [
        0xA1, 0xF3, 0x02, 0x30, 0x76, 0x01, 0x32, 0x48, 0x09, 0x9C, 0x10, 0xAA, 0x3F, 0xA0, 0x54,
        0x0D, 0xC0, 0xB7, 0x65, 0x01,
    ];

    let s2: Serial = Serial::from(serial2);
    assert_eq!(
        s2.as_x509_int(),
        "924566785900861696177829411010986812227211191553"
    );
    assert_eq!(
        s2.as_x509_hex(),
        "a1:f3:02:30:76:01:32:48:09:9c:10:aa:3f:a0:54:0d:c0:b7:65:01"
    );

    let serial3: [u8; 20] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0x3F, 0xA0, 0x54,
        0x0D, 0xC0, 0xB7, 0x65, 0x01,
    ];

    let s3: Serial = Serial::from(serial3);
    assert_eq!(s3.as_x509_int(), "3140531249369331492097");
    assert_eq!(s3.as_x509_hex(), "aa:3f:a0:54:0d:c0:b7:65:01");
}
