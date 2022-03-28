//! Integration tests

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, trivial_casts, unused_qualifications)]

use lazy_static::lazy_static;
use log::trace;
use rand_core::{OsRng, RngCore};
use rsa::{hash::Hash::SHA2_256, PaddingScheme, PublicKey};
use sha2::{Digest, Sha256};
use std::{env, str::FromStr, sync::Mutex};
use x509::RelativeDistinguishedName;
use yubikey::{
    certificate::{Certificate, PublicKeyInfo},
    piv::{self, AlgorithmId, Key, ManagementSlotId, RetiredSlotId, SlotId},
    Error, MgmKey, PinPolicy, Serial, TouchPolicy, YubiKey,
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

    let yubikey = if let Ok(serial) = env::var("YUBIKEY_SERIAL") {
        let serial = Serial::from_str(&serial).unwrap();
        YubiKey::open_by_serial(serial).unwrap()
    } else {
        YubiKey::open().unwrap()
    };
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
fn test_slot_id_display() {
    assert_eq!(format!("{}", SlotId::Authentication), "Authentication");
    assert_eq!(format!("{}", SlotId::Signature), "Signature");
    assert_eq!(format!("{}", SlotId::KeyManagement), "KeyManagement");
    assert_eq!(
        format!("{}", SlotId::CardAuthentication),
        "CardAuthentication"
    );
    assert_eq!(format!("{}", SlotId::Attestation), "Attestation");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R1)), "R1");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R2)), "R2");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R3)), "R3");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R4)), "R4");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R5)), "R5");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R6)), "R6");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R7)), "R7");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R8)), "R8");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R9)), "R9");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R10)), "R10");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R11)), "R11");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R12)), "R12");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R13)), "R13");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R14)), "R14");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R15)), "R15");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R16)), "R16");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R17)), "R17");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R18)), "R18");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R19)), "R19");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R20)), "R20");

    assert_eq!(
        format!("{}", SlotId::Management(ManagementSlotId::PIN)),
        "PIN"
    );
    assert_eq!(
        format!("{}", SlotId::Management(ManagementSlotId::PUK)),
        "PUK"
    );
    assert_eq!(
        format!("{}", SlotId::Management(ManagementSlotId::Management)),
        "Management"
    );
}

//
// Metadata
//

#[test]
#[ignore]
fn test_read_metadata() {
    let mut yubikey = YUBIKEY.lock().unwrap();

    assert!(yubikey.verify_pin(b"123456").is_ok());
    assert!(yubikey.authenticate(MgmKey::default()).is_ok());

    let slot = SlotId::Retired(RetiredSlotId::R1);

    // Generate a new key in the selected slot.
    let generated = piv::generate(
        &mut yubikey,
        slot,
        AlgorithmId::EccP256,
        PinPolicy::Default,
        TouchPolicy::Default,
    )
    .unwrap();

    let metadata = piv::metadata(&mut yubikey, slot).unwrap();

    assert_eq!(metadata.public, Some(generated));
}
