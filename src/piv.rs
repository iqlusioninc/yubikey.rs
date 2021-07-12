//! Personal Identity Verification (PIV) cryptographic keys stored in a YubiKey.
//!
//! Support for public-key cryptography using keys stored within the PIV
//! slots of a YubiKey.
//!
//! Supported algorithms:
//!
//! - **Encryption**:
//!   - RSA: `RSA1024`, `RSA2048`
//!   - ECC: `ECCP256`, `ECCP384` (i.e. NIST curves: P-256, P-384)
//! - **Signatures**:
//!   - RSASSA-PKCS#1v1.5: `RSA1024`, `RSA2048`
//!   - ECDSA: `ECCP256`, `ECCP384` (NIST curves: P-256, P-384)

// Adapted from yubico-piv-tool:
// <https://github.com/Yubico/yubico-piv-tool/>
//
// Copyright (c) 2014-2016 Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//   * Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//   * Redistributions in binary form must reproduce the above
//     copyright notice, this list of conditions and the following
//     disclaimer in the documentation and/or other materials provided
//     with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use crate::{
    apdu::{Ins, StatusWords},
    certificate::{self, Certificate, PublicKeyInfo},
    error::{Error, Result},
    policy::{PinPolicy, TouchPolicy},
    serialization::*,
    settings,
    yubikey::YubiKey,
    Buffer, ObjectId,
};
use elliptic_curve::sec1::EncodedPoint as EcPublicKey;
use log::{debug, error, warn};
use rsa::{BigUint, RSAPublicKey};
use std::{convert::TryFrom, str::FromStr};

#[cfg(feature = "untested")]
use {
    crate::CB_OBJ_MAX,
    num_bigint_dig::traits::ModInverse,
    num_integer::Integer,
    num_traits::{FromPrimitive, One},
};

#[cfg(feature = "untested")]
use zeroize::Zeroizing;

const CB_ECC_POINTP256: usize = 65;
const CB_ECC_POINTP384: usize = 97;

const TAG_RSA_MODULUS: u8 = 0x81;
const TAG_RSA_EXP: u8 = 0x82;
const TAG_ECC_POINT: u8 = 0x86;

#[cfg(feature = "untested")]
const KEYDATA_LEN: usize = 1024;

#[cfg(feature = "untested")]
const KEYDATA_RSA_EXP: u64 = 65537;

/// Slot identifiers.
/// <https://developers.yubico.com/PIV/Introduction/Certificate_slots.html>
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SlotId {
    /// This certificate and its associated private key is used to authenticate the card
    /// and the cardholder. This slot is used for things like system login. The end user
    /// PIN is required to perform any private key operations. Once the PIN has been
    /// provided successfully, multiple private key operations may be performed without
    /// additional cardholder consent.
    Authentication,

    /// This certificate and its associated private key is used for digital signatures for
    /// the purpose of document signing, or signing files and executables. The end user
    /// PIN is required to perform any private key operations. The PIN must be submitted
    /// every time immediately before a sign operation, to ensure cardholder participation
    /// for every digital signature generated.
    Signature,

    /// This certificate and its associated private key is used for encryption for the
    /// purpose of confidentiality. This slot is used for things like encrypting e-mails
    /// or files. The end user PIN is required to perform any private key operations. Once
    /// the PIN has been provided successfully, multiple private key operations may be
    /// performed without additional cardholder consent.
    KeyManagement,

    /// This certificate and its associated private key is used to support additional
    /// physical access applications, such as providing physical access to buildings via
    /// PIV-enabled door locks. The end user PIN is NOT required to perform private key
    /// operations for this slot.
    CardAuthentication,

    /// These slots are only available on the YubiKey 4 & 5. They are meant for previously
    /// used Key Management keys to be able to decrypt earlier encrypted documents or
    /// emails. In the YubiKey 4 & 5 all 20 of them are fully available for use.
    Retired(RetiredSlotId),

    /// This slot is only available on YubiKey version 4.3 and newer. It is only used for
    /// attestation of other keys generated on device with instruction `f9`. This slot is
    /// not cleared on reset, but can be overwritten.
    Attestation,
}

impl TryFrom<u8> for SlotId {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x9a => Ok(SlotId::Authentication),
            0x9c => Ok(SlotId::Signature),
            0x9d => Ok(SlotId::KeyManagement),
            0x9e => Ok(SlotId::CardAuthentication),
            0xf9 => Ok(SlotId::Attestation),
            _ => RetiredSlotId::try_from(value).map(SlotId::Retired),
        }
    }
}

impl From<SlotId> for u8 {
    fn from(slot: SlotId) -> u8 {
        match slot {
            SlotId::Authentication => 0x9a,
            SlotId::Signature => 0x9c,
            SlotId::KeyManagement => 0x9d,
            SlotId::CardAuthentication => 0x9e,
            SlotId::Retired(retired) => retired.into(),
            SlotId::Attestation => 0xf9,
        }
    }
}

impl FromStr for SlotId {
    type Err = Error;

    fn from_str(s: &str) -> Result<SlotId> {
        match s {
            "9a" => Ok(SlotId::Authentication),
            "9c" => Ok(SlotId::Signature),
            "9d" => Ok(SlotId::KeyManagement),
            "9e" => Ok(SlotId::CardAuthentication),
            "f9" => Ok(SlotId::Attestation),
            _ => s.parse().map(SlotId::Retired),
        }
    }
}

impl SlotId {
    /// Returns the [`ObjectId`] that corresponds to a given [`SlotId`].
    pub(crate) fn object_id(self) -> ObjectId {
        match self {
            SlotId::Authentication => 0x005f_c105,
            SlotId::Signature => 0x005f_c10a,
            SlotId::KeyManagement => 0x005f_c10b,
            SlotId::CardAuthentication => 0x005f_c101,
            SlotId::Retired(retired) => retired.object_id(),
            SlotId::Attestation => 0x005f_ff01,
        }
    }
}

/// Retired slot IDs.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RetiredSlotId {
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    R16,
    R17,
    R18,
    R19,
    R20,
}

impl TryFrom<u8> for RetiredSlotId {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x82 => Ok(RetiredSlotId::R1),
            0x83 => Ok(RetiredSlotId::R2),
            0x84 => Ok(RetiredSlotId::R3),
            0x85 => Ok(RetiredSlotId::R4),
            0x86 => Ok(RetiredSlotId::R5),
            0x87 => Ok(RetiredSlotId::R6),
            0x88 => Ok(RetiredSlotId::R7),
            0x89 => Ok(RetiredSlotId::R8),
            0x8a => Ok(RetiredSlotId::R9),
            0x8b => Ok(RetiredSlotId::R10),
            0x8c => Ok(RetiredSlotId::R11),
            0x8d => Ok(RetiredSlotId::R12),
            0x8e => Ok(RetiredSlotId::R13),
            0x8f => Ok(RetiredSlotId::R14),
            0x90 => Ok(RetiredSlotId::R15),
            0x91 => Ok(RetiredSlotId::R16),
            0x92 => Ok(RetiredSlotId::R17),
            0x93 => Ok(RetiredSlotId::R18),
            0x94 => Ok(RetiredSlotId::R19),
            0x95 => Ok(RetiredSlotId::R20),
            _ => Err(Error::InvalidObject),
        }
    }
}

impl FromStr for RetiredSlotId {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "82" => Ok(RetiredSlotId::R1),
            "83" => Ok(RetiredSlotId::R2),
            "84" => Ok(RetiredSlotId::R3),
            "85" => Ok(RetiredSlotId::R4),
            "86" => Ok(RetiredSlotId::R5),
            "87" => Ok(RetiredSlotId::R6),
            "88" => Ok(RetiredSlotId::R7),
            "89" => Ok(RetiredSlotId::R8),
            "8a" => Ok(RetiredSlotId::R9),
            "8b" => Ok(RetiredSlotId::R10),
            "8c" => Ok(RetiredSlotId::R11),
            "8d" => Ok(RetiredSlotId::R12),
            "8e" => Ok(RetiredSlotId::R13),
            "8f" => Ok(RetiredSlotId::R14),
            "90" => Ok(RetiredSlotId::R15),
            "91" => Ok(RetiredSlotId::R16),
            "92" => Ok(RetiredSlotId::R17),
            "93" => Ok(RetiredSlotId::R18),
            "94" => Ok(RetiredSlotId::R19),
            "95" => Ok(RetiredSlotId::R20),
            _ => Err(Error::InvalidObject),
        }
    }
}

impl From<RetiredSlotId> for u8 {
    fn from(slot: RetiredSlotId) -> u8 {
        match slot {
            RetiredSlotId::R1 => 0x82,
            RetiredSlotId::R2 => 0x83,
            RetiredSlotId::R3 => 0x84,
            RetiredSlotId::R4 => 0x85,
            RetiredSlotId::R5 => 0x86,
            RetiredSlotId::R6 => 0x87,
            RetiredSlotId::R7 => 0x88,
            RetiredSlotId::R8 => 0x89,
            RetiredSlotId::R9 => 0x8a,
            RetiredSlotId::R10 => 0x8b,
            RetiredSlotId::R11 => 0x8c,
            RetiredSlotId::R12 => 0x8d,
            RetiredSlotId::R13 => 0x8e,
            RetiredSlotId::R14 => 0x8f,
            RetiredSlotId::R15 => 0x90,
            RetiredSlotId::R16 => 0x91,
            RetiredSlotId::R17 => 0x92,
            RetiredSlotId::R18 => 0x93,
            RetiredSlotId::R19 => 0x94,
            RetiredSlotId::R20 => 0x95,
        }
    }
}

impl RetiredSlotId {
    /// Returns the [`ObjectId`] that corresponds to a given [`RetiredSlotId`].
    pub(crate) fn object_id(self) -> ObjectId {
        match self {
            RetiredSlotId::R1 => 0x005f_c10d,
            RetiredSlotId::R2 => 0x005f_c10e,
            RetiredSlotId::R3 => 0x005f_c10f,
            RetiredSlotId::R4 => 0x005f_c110,
            RetiredSlotId::R5 => 0x005f_c111,
            RetiredSlotId::R6 => 0x005f_c112,
            RetiredSlotId::R7 => 0x005f_c113,
            RetiredSlotId::R8 => 0x005f_c114,
            RetiredSlotId::R9 => 0x005f_c115,
            RetiredSlotId::R10 => 0x005f_c116,
            RetiredSlotId::R11 => 0x005f_c117,
            RetiredSlotId::R12 => 0x005f_c118,
            RetiredSlotId::R13 => 0x005f_c119,
            RetiredSlotId::R14 => 0x005f_c11a,
            RetiredSlotId::R15 => 0x005f_c11b,
            RetiredSlotId::R16 => 0x005f_c11c,
            RetiredSlotId::R17 => 0x005f_c11d,
            RetiredSlotId::R18 => 0x005f_c11e,
            RetiredSlotId::R19 => 0x005f_c11f,
            RetiredSlotId::R20 => 0x005f_c120,
        }
    }
}

/// Personal Identity Verification (PIV) key slots
pub const SLOTS: [SlotId; 24] = [
    SlotId::Authentication,
    SlotId::Signature,
    SlotId::KeyManagement,
    SlotId::Retired(RetiredSlotId::R1),
    SlotId::Retired(RetiredSlotId::R2),
    SlotId::Retired(RetiredSlotId::R3),
    SlotId::Retired(RetiredSlotId::R4),
    SlotId::Retired(RetiredSlotId::R5),
    SlotId::Retired(RetiredSlotId::R6),
    SlotId::Retired(RetiredSlotId::R7),
    SlotId::Retired(RetiredSlotId::R8),
    SlotId::Retired(RetiredSlotId::R9),
    SlotId::Retired(RetiredSlotId::R10),
    SlotId::Retired(RetiredSlotId::R11),
    SlotId::Retired(RetiredSlotId::R12),
    SlotId::Retired(RetiredSlotId::R13),
    SlotId::Retired(RetiredSlotId::R14),
    SlotId::Retired(RetiredSlotId::R15),
    SlotId::Retired(RetiredSlotId::R16),
    SlotId::Retired(RetiredSlotId::R17),
    SlotId::Retired(RetiredSlotId::R18),
    SlotId::Retired(RetiredSlotId::R19),
    SlotId::Retired(RetiredSlotId::R20),
    SlotId::CardAuthentication,
];

/// Algorithm identifiers
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlgorithmId {
    /// 1024-bit RSA.
    Rsa1024,

    /// 2048-bit RSA.
    Rsa2048,

    /// ECDSA with the NIST P256 curve.
    EccP256,

    /// ECDSA with the NIST P384 curve.
    EccP384,
}

impl TryFrom<u8> for AlgorithmId {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x06 => Ok(AlgorithmId::Rsa1024),
            0x07 => Ok(AlgorithmId::Rsa2048),
            0x11 => Ok(AlgorithmId::EccP256),
            0x14 => Ok(AlgorithmId::EccP384),
            _ => Err(Error::AlgorithmError),
        }
    }
}

impl From<AlgorithmId> for u8 {
    fn from(id: AlgorithmId) -> u8 {
        match id {
            AlgorithmId::Rsa1024 => 0x06,
            AlgorithmId::Rsa2048 => 0x07,
            AlgorithmId::EccP256 => 0x11,
            AlgorithmId::EccP384 => 0x14,
        }
    }
}

impl AlgorithmId {
    /// Writes the `AlgorithmId` in the format the YubiKey expects during key generation.
    pub(crate) fn write(self, buf: &mut [u8]) -> Result<usize> {
        Tlv::write(buf, 0x80, &[self.into()])
    }

    #[cfg(feature = "untested")]
    #[cfg_attr(docsrs, doc(cfg(feature = "untested")))]
    fn get_elem_len(self) -> usize {
        match self {
            AlgorithmId::Rsa1024 => 64,
            AlgorithmId::Rsa2048 => 128,
            AlgorithmId::EccP256 => 32,
            AlgorithmId::EccP384 => 48,
        }
    }

    #[cfg(feature = "untested")]
    #[cfg_attr(docsrs, doc(cfg(feature = "untested")))]
    fn get_param_tag(self) -> u8 {
        match self {
            AlgorithmId::Rsa1024 | AlgorithmId::Rsa2048 => 0x01,
            AlgorithmId::EccP256 | AlgorithmId::EccP384 => 0x6,
        }
    }
}

/// PIV cryptographic keys stored in a YubiKey
#[derive(Clone, Debug)]
pub struct Key {
    /// Card slot
    slot: SlotId,

    /// Cert
    cert: Certificate,
}

impl Key {
    /// List Personal Identity Verification (PIV) keys stored in a YubiKey
    pub fn list(yubikey: &mut YubiKey) -> Result<Vec<Self>> {
        let mut keys = vec![];
        let txn = yubikey.begin_transaction()?;

        for slot in SLOTS.iter().cloned() {
            let buf = match certificate::read_certificate(&txn, slot) {
                Ok(b) => b,
                Err(e) => {
                    debug!("error reading certificate in slot {:?}: {}", slot, e);
                    continue;
                }
            };

            if !buf.is_empty() {
                let cert = Certificate::from_bytes(buf)?;
                keys.push(Key { slot, cert });
            }
        }

        Ok(keys)
    }

    /// Get the slot ID for this key
    pub fn slot(&self) -> SlotId {
        self.slot
    }

    /// Get the certificate for this key
    pub fn certificate(&self) -> &Certificate {
        &self.cert
    }
}

/// Generate new key.
pub fn generate(
    yubikey: &mut YubiKey,
    slot: SlotId,
    algorithm: AlgorithmId,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
) -> Result<PublicKeyInfo> {
    // Keygen messages
    // TODO(tarcieri): extract these into an I18N-handling type?
    const SZ_SETTING_ROCA: &str = "Enable_Unsafe_Keygen_ROCA";
    const SZ_ROCA_ALLOW_USER: &str =
        "was permitted by an end-user configuration setting, but is not recommended.";
    const SZ_ROCA_ALLOW_ADMIN: &str =
        "was permitted by an administrator configuration setting, but is not recommended.";
    const SZ_ROCA_BLOCK_USER: &str = "was blocked due to an end-user configuration setting.";
    const SZ_ROCA_BLOCK_ADMIN: &str = "was blocked due to an administrator configuration setting.";
    const SZ_ROCA_DEFAULT: &str = "was permitted by default, but is not recommended.  The default behavior will change in a future Yubico release.";

    let setting_roca: settings::SettingValue;

    match algorithm {
        AlgorithmId::Rsa1024 | AlgorithmId::Rsa2048 => {
            if yubikey.version.major == 4
                && (yubikey.version.minor < 3
                    || yubikey.version.minor == 3 && (yubikey.version.patch < 5))
            {
                setting_roca = settings::SettingValue::get(SZ_SETTING_ROCA, true);

                let psz_msg = match setting_roca.source {
                    settings::SettingSource::User => {
                        if setting_roca.value {
                            SZ_ROCA_ALLOW_USER
                        } else {
                            SZ_ROCA_BLOCK_USER
                        }
                    }
                    settings::SettingSource::Admin => {
                        if setting_roca.value {
                            SZ_ROCA_ALLOW_ADMIN
                        } else {
                            SZ_ROCA_BLOCK_ADMIN
                        }
                    }
                    _ => SZ_ROCA_DEFAULT,
                };

                warn!(
                    "YubiKey serial number {} is affected by vulnerability CVE-2017-15361 \
                     (ROCA) and should be replaced. On-chip key generation {}  See \
                     YSA-2017-01 <https://www.yubico.com/support/security-advisories/ysa-2017-01/> \
                     for additional information on device replacement and mitigation assistance",
                    yubikey.serial, psz_msg
                );

                if !setting_roca.value {
                    return Err(Error::NotSupported);
                }
            }
        }
        _ => (),
    }

    let txn = yubikey.begin_transaction()?;

    let templ = [0, Ins::GenerateAsymmetric.code(), 0, slot.into()];

    let mut in_data = [0u8; 11];
    let mut offset = Tlv::write_as(&mut in_data, 0xac, 3, |buf| {
        assert_eq!(algorithm.write(buf).expect("large enough"), 3);
    })?;

    let pin_len = pin_policy.write(&mut in_data[offset..])?;
    in_data[1] += pin_len as u8;
    offset += pin_len;

    let touch_len = touch_policy.write(&mut in_data[offset..])?;
    in_data[1] += touch_len as u8;
    offset += touch_len;

    let response = txn.transfer_data(&templ, &in_data[..offset], 1024)?;

    if !response.is_success() {
        let err_msg = "failed to generate new key";

        match response.status_words() {
            StatusWords::IncorrectSlotError => {
                error!("{} (incorrect slot)", err_msg);
                return Err(Error::KeyError);
            }
            StatusWords::IncorrectParamError => {
                match pin_policy {
                    PinPolicy::Default => match touch_policy {
                        TouchPolicy::Default => error!("{} (algorithm not supported?)", err_msg),
                        _ => error!("{} (touch policy not supported?)", err_msg),
                    },
                    _ => error!("{} (pin policy not supported?)", err_msg),
                }

                return Err(Error::AlgorithmError);
            }
            StatusWords::SecurityStatusError => {
                error!("{} (not authenticated)", err_msg);
                return Err(Error::AuthenticationError);
            }
            other => {
                error!("{} (error {:?})", err_msg, other);
                return Err(Error::GenericError);
            }
        }
    }

    // TODO(str4d): Response is wrapped in an ASN.1 TLV:
    //
    //    0x7f 0x49 -> Application | Constructed | 0x49
    match algorithm {
        AlgorithmId::Rsa1024 | AlgorithmId::Rsa2048 => {
            // It appears that the inner application-specific value returned by the
            // YubiKey is constructed such that RSA pubkeys can be parsed in two ways:
            //
            // - Use a full ASN.1 parser on the entire datastructure:
            //
            //     RSA 1024:
            //     [127, 73, 129, 136, 129, 129, 128, [ 128 octets ], 130,  3, 1, 0, 1]
            //     | tag   | len:136 |0x81| len:128 |    modulus    |0x82|len3|  exp  |
            //
            //     RSA 2048:
            //     [127, 73, 130, 1, 9, 129, 130, 1, 0, [ 256 octets ], 130,  3, 1, 0, 1]
            //     | tag   | len:265  |0x81| len:256  |    modulus    |0x82|len3|  exp  |
            //
            // - Skip the first 5 bytes and use crate::serialize::get_length during TLV
            //   parsing (which treats 128 as a single-byte definite length instead of an
            //   indefinite length):
            //
            //     RSA 1024:
            //     [127, 73, 129, 136, 129, 129, 128, [ 128 octets ], 130,  3, 1, 0, 1]
            //     |                      |0x81|len128|   modulus   |0x82|len3|  exp  |
            //
            //     RSA 2048:
            //     [127, 73, 130, 1, 9, 129, 130, 1, 0, [ 256 octets ], 130,  3, 1, 0, 1]
            //     |                  |0x81| len:256  |    modulus    |0x82|len3|  exp  |
            //
            // Because of the above, treat this for now as a 2-byte ASN.1 tag with a
            // 3-byte length.
            let data = &response.data()[5..];

            let (data, modulus_tlv) = Tlv::parse(data)?;
            if modulus_tlv.tag != TAG_RSA_MODULUS {
                error!("Failed to parse public key structure (modulus)");
                return Err(Error::ParseError);
            }
            let modulus = modulus_tlv.value.to_vec();

            let (_, exp_tlv) = Tlv::parse(data)?;
            if exp_tlv.tag != TAG_RSA_EXP {
                error!("failed to parse public key structure (public exponent)");
                return Err(Error::ParseError);
            }
            let exp = exp_tlv.value.to_vec();

            Ok(PublicKeyInfo::Rsa {
                algorithm,
                pubkey: RSAPublicKey::new(
                    BigUint::from_bytes_be(&modulus),
                    BigUint::from_bytes_be(&exp),
                )
                .map_err(|_| Error::InvalidObject)?,
            })
        }
        AlgorithmId::EccP256 | AlgorithmId::EccP384 => {
            // 2-byte ASN.1 tag, 1-byte length (because all supported EC pubkey lengths
            // are shorter than 128 bytes, fitting into a definite short ASN.1 length).
            let data = &response.data()[3..];

            let len = if let AlgorithmId::EccP256 = algorithm {
                CB_ECC_POINTP256
            } else {
                CB_ECC_POINTP384
            };

            let (_, tlv) = Tlv::parse(data)?;

            if tlv.tag != TAG_ECC_POINT {
                error!("failed to parse public key structure");
                return Err(Error::ParseError);
            }

            // the curve point should always be determined by the curve
            if tlv.value.len() != len {
                error!("unexpected length");
                return Err(Error::AlgorithmError);
            }

            let point = tlv.value.to_vec();

            if let AlgorithmId::EccP256 = algorithm {
                EcPublicKey::from_bytes(point).map(PublicKeyInfo::EcP256)
            } else {
                EcPublicKey::from_bytes(point).map(PublicKeyInfo::EcP384)
            }
            .map_err(|_| Error::InvalidObject)
        }
    }
}

#[cfg(feature = "untested")]
#[cfg_attr(docsrs, doc(cfg(feature = "untested")))]
fn write_key(
    yubikey: &mut YubiKey,
    slot: SlotId,
    params: Vec<&[u8]>,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
    algorithm: AlgorithmId,
) -> Result<()> {
    let mut key_data = Buffer::new(vec![0u8; KEYDATA_LEN]);
    let templ = [0, Ins::ImportKey.code(), algorithm.into(), slot.into()];
    let mut offset = 0;

    let elem_len = algorithm.get_elem_len();
    let param_tag = algorithm.get_param_tag();

    for (i, param) in params.into_iter().enumerate() {
        offset += Tlv::write_as(
            &mut key_data[offset..],
            param_tag + (i as u8),
            elem_len,
            |buf| {
                let padding = elem_len - param.len();
                for b in &mut buf[..padding] {
                    *b = 0;
                }
                buf[padding..].copy_from_slice(param);
            },
        )?;
    }

    offset += pin_policy.write(&mut key_data[offset..])?;
    offset += touch_policy.write(&mut key_data[offset..])?;

    let txn = yubikey.begin_transaction()?;

    let status_words = txn
        .transfer_data(&templ, &key_data[..offset], 256)?
        .status_words();

    match status_words {
        StatusWords::Success => Ok(()),
        StatusWords::SecurityStatusError => Err(Error::AuthenticationError),
        _ => Err(Error::GenericError),
    }
}

/// The key data that makes up an RSA key.
#[cfg(feature = "untested")]
#[cfg_attr(docsrs, doc(cfg(feature = "untested")))]
pub struct RsaKeyData {
    /// The secret prime `p`.
    p: Buffer,
    /// The secret prime, `q`.
    q: Buffer,
    /// D mod (P-1)
    dp: Buffer,
    /// D mod (Q-1)
    dq: Buffer,
    /// Q^-1 mod P
    qinv: Buffer,
}

#[cfg(feature = "untested")]
impl RsaKeyData {
    /// Generates a new RSA key data set from two randomly generated, secret, primes.
    ///
    /// Panics if `secret_p` or `secret_q` are invalid primes.
    pub fn new(secret_p: &[u8], secret_q: &[u8]) -> Self {
        let p = BigUint::from_bytes_be(secret_p);
        let q = BigUint::from_bytes_be(secret_q);

        let totient = {
            let p_t = &p - BigUint::one();
            let q_t = &p - BigUint::one();

            p_t.lcm(&q_t)
        };

        let exp = BigUint::from_u64(KEYDATA_RSA_EXP).unwrap();

        let d = exp.mod_inverse(&totient).unwrap();
        let d = d.to_biguint().unwrap();

        // We calculate the optimization values ahead of time, instead of making the user
        // do so.

        let dp = &d % (&p - BigUint::one());
        let dq = &d % (&q - BigUint::one());

        let qinv = q.clone().mod_inverse(&p).unwrap();
        let (_, qinv) = qinv.to_bytes_be();

        RsaKeyData {
            p: Zeroizing::new(p.to_bytes_be()),
            q: Zeroizing::new(q.to_bytes_be()),
            dp: Zeroizing::new(dp.to_bytes_be()),
            dq: Zeroizing::new(dq.to_bytes_be()),
            qinv: Zeroizing::new(qinv),
        }
    }

    fn total_len(&self) -> usize {
        self.p.len() + self.q.len() + self.dp.len() + self.qinv.len()
    }
}

/// Imports a private RSA encryption or signing key into the YubiKey.
///
/// Errors if `algorithm` isn't `AlgorithmId::Rsa1024` or `AlgorithmId::Rsa2048`.
#[cfg(feature = "untested")]
#[cfg_attr(docsrs, doc(cfg(feature = "untested")))]
pub fn import_rsa_key(
    yubikey: &mut YubiKey,
    slot: SlotId,
    algorithm: AlgorithmId,
    key_data: RsaKeyData,
    touch_policy: TouchPolicy,
    pin_policy: PinPolicy,
) -> Result<()> {
    match algorithm {
        AlgorithmId::Rsa1024 | AlgorithmId::Rsa2048 => (),
        _ => return Err(Error::AlgorithmError),
    }

    if key_data.total_len() > KEYDATA_LEN {
        return Err(Error::SizeError);
    }

    let params = vec![
        key_data.p.as_slice(),
        key_data.q.as_slice(),
        key_data.dp.as_slice(),
        key_data.dq.as_slice(),
        key_data.qinv.as_slice(),
    ];

    write_key(yubikey, slot, params, pin_policy, touch_policy, algorithm)?;

    Ok(())
}

/// Imports a private ECC encryption or signing key into the YubiKey.
///
/// Errors if `algorithm` isn't `AlgorithmId::EccP256` or ` AlgorithmId::EccP384`.
#[cfg(feature = "untested")]
#[cfg_attr(docsrs, doc(cfg(feature = "untested")))]
pub fn import_ecc_key(
    yubikey: &mut YubiKey,
    slot: SlotId,
    algorithm: AlgorithmId,
    key_data: &[u8],
    touch_policy: TouchPolicy,
    pin_policy: PinPolicy,
) -> Result<()> {
    match algorithm {
        AlgorithmId::EccP256 | AlgorithmId::EccP384 => (),
        _ => return Err(Error::AlgorithmError),
    }

    if key_data.len() > KEYDATA_LEN {
        return Err(Error::SizeError);
    }

    let params = vec![key_data];

    write_key(yubikey, slot, params, pin_policy, touch_policy, algorithm)?;

    Ok(())
}

/// Generate an attestation certificate for a stored key.
///
/// <https://developers.yubico.com/PIV/Introduction/PIV_attestation.html>
#[cfg(feature = "untested")]
#[cfg_attr(docsrs, doc(cfg(feature = "untested")))]
pub fn attest(yubikey: &mut YubiKey, key: SlotId) -> Result<Buffer> {
    let templ = [0, Ins::Attest.code(), key.into(), 0];
    let txn = yubikey.begin_transaction()?;
    let response = txn.transfer_data(&templ, &[], CB_OBJ_MAX)?;

    if !response.is_success() {
        if response.status_words() == StatusWords::NotSupportedError {
            return Err(Error::NotSupported);
        } else {
            return Err(Error::GenericError);
        }
    }

    if response.data()[0] != 0x30 {
        return Err(Error::GenericError);
    }

    Ok(Buffer::new(response.data().into()))
}

/// Sign data using a PIV key.
pub fn sign_data(
    yubikey: &mut YubiKey,
    raw_in: &[u8],
    algorithm: AlgorithmId,
    key: SlotId,
) -> Result<Buffer> {
    let txn = yubikey.begin_transaction()?;

    // don't attempt to reselect in crypt operations to avoid problems with PIN_ALWAYS
    txn.authenticated_command(raw_in, algorithm, key, false)
}

/// Decrypt data using a PIV key.
#[cfg(feature = "untested")]
#[cfg_attr(docsrs, doc(cfg(feature = "untested")))]
pub fn decrypt_data(
    yubikey: &mut YubiKey,
    input: &[u8],
    algorithm: AlgorithmId,
    key: SlotId,
) -> Result<Buffer> {
    let txn = yubikey.begin_transaction()?;

    // don't attempt to reselect in crypt operations to avoid problems with PIN_ALWAYS
    txn.authenticated_command(input, algorithm, key, true)
}
