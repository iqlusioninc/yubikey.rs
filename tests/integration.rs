//! Integration tests

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, trivial_casts, unused_qualifications)]

use lazy_static::lazy_static;
use log::trace;
use rand_core::{OsRng, RngCore};
use rsa::{hash::Hash::SHA2_256, PaddingScheme, PublicKey};
use sha2::{Digest, Sha256};
use std::{env, sync::Mutex};
use yubikey::{
    piv::{self, AlgorithmId, Key, RetiredSlotId, SlotId},
    Error, MgmKey, PinPolicy, TouchPolicy, YubiKey,
};

use der::{Decodable, Encodable};
use p256::ecdsa::signature::Verifier as Verifier256;
use p256::ecdsa::Signature as Signature256;
use p256::ecdsa::VerifyingKey as VerifyingKey256;
use rsa::pkcs8::FromPublicKey;
use rsa::RsaPublicKey;
use x501::name::Name;
use x509::Certificate;
use yubikey::certificate::generate_self_signed;

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
fn test_list_keys() {
    let mut yubikey = YUBIKEY.lock().unwrap();
    let mut buffers = vec![];
    let keys_result = Key::list(&mut yubikey, &mut buffers);
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

fn generate_self_signed_cert(algorithm: AlgorithmId) -> Vec<u8> {
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

    // cn=testSubject
    let name_bytes = [
        0x30, 0x16, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0B, 0x74, 0x65,
        0x73, 0x74, 0x53, 0x75, 0x62, 0x6A, 0x65, 0x63, 0x74,
    ];
    let name = Name::from_der(&name_bytes).unwrap();

    // Generate a self-signed certificate for the new key.
    let cert_result = generate_self_signed(
        &mut yubikey,
        slot,
        &serial,
        None,
        &name,
        generated.as_slice(),
        None,
        algorithm,
    );

    assert!(cert_result.is_ok());
    let cert = cert_result.unwrap();
    trace!("cert: {:?}", cert);
    cert
}

#[test]
#[ignore]
fn generate_self_signed_rsa_cert2048() {
    let certbuf = generate_self_signed_cert(AlgorithmId::Rsa2048);
    let cert = Certificate::from_der(certbuf.as_slice()).unwrap();
    let tbsbuf = cert.tbs_certificate.to_vec().unwrap();
    let hash_to_verify = Sha256::digest(tbsbuf.as_slice()).to_vec();
    let spkibuf = cert
        .tbs_certificate
        .subject_public_key_info
        .to_vec()
        .unwrap();
    let rsa = RsaPublicKey::from_public_key_der(&spkibuf).unwrap();
    let ps = PaddingScheme::PKCS1v15Sign {
        hash: Some(SHA2_256),
    };
    let x = rsa.verify(
        ps,
        hash_to_verify.as_slice(),
        cert.signature.as_bytes().unwrap(),
    );
    if let Err(e) = x {
        panic!(
            "Self-signed certificate signature failed to verify: {:?}",
            e
        );
    }
}

#[test]
#[ignore]
fn generate_self_signed_rsa_cert1024() {
    let certbuf = generate_self_signed_cert(AlgorithmId::Rsa1024);
    let cert = Certificate::from_der(certbuf.as_slice()).unwrap();
    let tbsbuf = cert.tbs_certificate.to_vec().unwrap();
    let hash_to_verify = Sha256::digest(tbsbuf.as_slice()).to_vec();
    let spkibuf = cert
        .tbs_certificate
        .subject_public_key_info
        .to_vec()
        .unwrap();
    let rsa = RsaPublicKey::from_public_key_der(&spkibuf).unwrap();
    let ps = PaddingScheme::PKCS1v15Sign {
        hash: Some(SHA2_256),
    };
    let x = rsa.verify(
        ps,
        hash_to_verify.as_slice(),
        cert.signature.as_bytes().unwrap(),
    );
    if let Err(e) = x {
        panic!(
            "Self-signed certificate signature failed to verify: {:?}",
            e
        );
    }
}

#[test]
#[ignore]
fn generate_self_signed_ec_cert() {
    let certbuf = generate_self_signed_cert(AlgorithmId::EccP256);
    let cert = Certificate::from_der(certbuf.as_slice()).unwrap();
    let tbsbuf = cert.tbs_certificate.to_vec().unwrap();
    let ecdsa = VerifyingKey256::from_sec1_bytes(
        cert.tbs_certificate
            .subject_public_key_info
            .subject_public_key,
    )
    .unwrap();
    let s = Signature256::from_der(cert.signature.as_bytes().unwrap()).unwrap();
    let x = ecdsa.verify(tbsbuf.as_slice(), &s);
    if let Err(e) = x {
        panic!(
            "Self-signed certificate signature failed to verify: {:?}",
            e
        );
    }
}
