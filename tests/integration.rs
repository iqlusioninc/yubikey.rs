//! Integration tests

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, trivial_casts, unused_qualifications)]

use getrandom::getrandom;
use lazy_static::lazy_static;
use log::trace;
use rsa::{hash::Hash::SHA2_256, PaddingScheme, PublicKey};
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::{env, sync::Mutex};
use x509::RelativeDistinguishedName;
use yubikey_piv::{
    certificate::{Certificate, PublicKeyInfo},
    key::{self, AlgorithmId, Key, RetiredSlotId, SlotId},
    policy::{PinPolicy, TouchPolicy},
    Error, MgmKey, YubiKey,
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
fn test_protected_mgmkey() {
    let mut yubikey = YUBIKEY.lock().unwrap();

    assert!(yubikey.verify_pin(b"123456").is_ok());
    assert!(yubikey.authenticate(MgmKey::default()).is_ok());

    // Set a protected management key.
    assert!(MgmKey::generate()
        .unwrap()
        .set_protected(&mut yubikey)
        .is_ok());
    let protected = MgmKey::get_protected(&mut yubikey).unwrap();
    assert!(yubikey.authenticate(MgmKey::default()).is_err());
    assert!(yubikey.authenticate(protected.clone()).is_ok());

    // Set back to the default management key.
    // TODO: This does not clear the previous key from the protected metadata.
    assert!(MgmKey::default().set(&mut yubikey, None).is_ok());
    assert!(yubikey.authenticate(protected).is_err());
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
    let generated = key::generate(
        &mut yubikey,
        slot,
        algorithm,
        PinPolicy::Default,
        TouchPolicy::Default,
    )
    .unwrap();

    let mut serial = [0u8; 20];
    getrandom(&mut serial).unwrap();

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
    let sig = &data[sig_start..];

    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
    let ring_pk = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, pubkey.as_bytes());
    assert!(ring_pk.verify(msg, sig).is_ok());
}
