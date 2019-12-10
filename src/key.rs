//! PIV cryptographic keys stored in a YubiKey.
//!
//! Supported algorithms:
//!
//! - **Encryption**: `RSA1024`, `RSA2048`, `ECCP256`, `ECCP384`
//! - **Signatures**:
//!   - RSASSA-PKCS#1v1.5: `RSA1024`, `RSA2048`
//!   - ECDSA: `ECCP256`, `ECCP384`

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
    certificate::{self, Certificate},
    error::Error,
    yubikey::YubiKey,
    ObjectId,
};
use log::debug;
use std::convert::TryFrom;

#[cfg(feature = "untested")]
use crate::{
    apdu::{Ins, StatusWords},
    policy::{PinPolicy, TouchPolicy},
    serialization::*,
    settings, Buffer, CB_OBJ_MAX,
};
#[cfg(feature = "untested")]
use log::{error, warn};
#[cfg(feature = "untested")]
use zeroize::Zeroizing;

#[cfg(feature = "untested")]
const CB_ECC_POINTP256: usize = 65;
#[cfg(feature = "untested")]
const CB_ECC_POINTP384: usize = 97;

#[cfg(feature = "untested")]
const TAG_RSA_MODULUS: u8 = 0x81;
#[cfg(feature = "untested")]
const TAG_RSA_EXP: u8 = 0x82;
#[cfg(feature = "untested")]
const TAG_ECC_POINT: u8 = 0x86;

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

    fn try_from(value: u8) -> Result<Self, Self::Error> {
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

impl TryFrom<String> for SlotId {
    type Error = Error;

    fn try_from(s: String) -> Result<SlotId, Error> {
        match s.as_ref() {
            "9a" => Ok(SlotId::Authentication),
            "9c" => Ok(SlotId::Signature),
            "9d" => Ok(SlotId::KeyManagement),
            "9e" => Ok(SlotId::CardAuthentication),
            "f9" => Ok(SlotId::Attestation),
            _ => RetiredSlotId::try_from(s).map(SlotId::Retired),
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

    fn try_from(value: u8) -> Result<Self, Self::Error> {
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

impl TryFrom<String> for RetiredSlotId {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_ref() {
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

    fn try_from(value: u8) -> Result<Self, Self::Error> {
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

#[cfg(feature = "untested")]
impl AlgorithmId {
    /// Writes the `AlgorithmId` in the format the YubiKey expects during key generation.
    pub(crate) fn write(self, buf: &mut [u8]) -> usize {
        buf[0] = 0x80;
        buf[1] = 0x01;
        buf[2] = self.into();
        3
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
    pub fn list(yubikey: &mut YubiKey) -> Result<Vec<Self>, Error> {
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
                let cert = Certificate::new(buf)?;
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

/// Information about a generated key
// TODO(tarcieri): this could use some more work
#[cfg(feature = "untested")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GeneratedKey {
    /// RSA keys
    Rsa {
        /// RSA algorithm
        algorithm: AlgorithmId,

        /// Modulus
        modulus: Vec<u8>,

        /// Exponent
        exp: Vec<u8>,
    },
    /// ECC keys
    Ecc {
        /// ECC algorithm
        algorithm: AlgorithmId,

        /// Public curve point (i.e. public key)
        point: Vec<u8>,
    },
}

#[cfg(feature = "untested")]
impl GeneratedKey {
    /// Get the algorithm
    pub fn algorithm(&self) -> AlgorithmId {
        *match self {
            GeneratedKey::Rsa { algorithm, .. } => algorithm,
            GeneratedKey::Ecc { algorithm, .. } => algorithm,
        }
    }
}

/// Generate key
#[cfg(feature = "untested")]
#[allow(clippy::cognitive_complexity)]
pub fn generate(
    yubikey: &mut YubiKey,
    slot: SlotId,
    algorithm: AlgorithmId,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
) -> Result<GeneratedKey, Error> {
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

    let setting_roca: settings::BoolValue;

    match algorithm {
        AlgorithmId::Rsa1024 | AlgorithmId::Rsa2048 => {
            if yubikey.version.major == 4
                && (yubikey.version.minor < 3
                    || yubikey.version.minor == 3 && (yubikey.version.patch < 5))
            {
                setting_roca = settings::BoolValue::get(SZ_SETTING_ROCA, true);

                let psz_msg = match setting_roca.source {
                    settings::Source::User => {
                        if setting_roca.value {
                            SZ_ROCA_ALLOW_USER
                        } else {
                            SZ_ROCA_BLOCK_USER
                        }
                    }
                    settings::Source::Admin => {
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
    in_data[0] = 0xac;
    in_data[1] = 3; // length sans this 2-byte header
    assert_eq!(algorithm.write(&mut in_data[2..]), 3);
    let mut offset = 5;

    let pin_len = pin_policy.write(&mut in_data[offset..]);
    in_data[1] += pin_len as u8;
    offset += pin_len;

    let touch_len = touch_policy.write(&mut in_data[offset..]);
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

    match algorithm {
        AlgorithmId::Rsa1024 | AlgorithmId::Rsa2048 => {
            let (data, modulus_tlv) = Tlv::parse(response.data())?;
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

            Ok(GeneratedKey::Rsa {
                algorithm,
                modulus,
                exp,
            })
        }
        AlgorithmId::EccP256 | AlgorithmId::EccP384 => {
            let len = if let AlgorithmId::EccP256 = algorithm {
                CB_ECC_POINTP256
            } else {
                CB_ECC_POINTP384
            };

            let (_, tlv) = Tlv::parse(response.data())?;

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
            Ok(GeneratedKey::Ecc { algorithm, point })
        }
    }
}

/// Import a private encryption or signing key into the YubiKey
// TODO(tarcieri): refactor this into separate methods per key type
#[cfg(feature = "untested")]
#[allow(clippy::too_many_arguments)]
pub fn import(
    yubikey: &mut YubiKey,
    key: SlotId,
    algorithm: AlgorithmId,
    p: Option<&[u8]>,
    q: Option<&[u8]>,
    dp: Option<&[u8]>,
    dq: Option<&[u8]>,
    qinv: Option<&[u8]>,
    ec_data: Option<&[u8]>,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
) -> Result<(), Error> {
    let mut key_data = Zeroizing::new(vec![0u8; 1024]);
    let templ = [0, Ins::ImportKey.code(), algorithm.into(), key.into()];

    let (elem_len, params, param_tag) = match algorithm {
        AlgorithmId::Rsa1024 | AlgorithmId::Rsa2048 => match (p, q, dp, dq, qinv) {
            (Some(p), Some(q), Some(dp), Some(dq), Some(qinv)) => {
                if p.len() + q.len() + dp.len() + dq.len() + qinv.len() >= key_data.len() {
                    return Err(Error::SizeError);
                }

                (
                    match algorithm {
                        AlgorithmId::Rsa1024 => 64,
                        AlgorithmId::Rsa2048 => 128,
                        _ => unreachable!(),
                    },
                    vec![p, q, dp, dq, qinv],
                    0x01,
                )
            }
            _ => return Err(Error::GenericError),
        },
        AlgorithmId::EccP256 | AlgorithmId::EccP384 => match ec_data {
            Some(ec_data) => {
                if ec_data.len() >= key_data.len() {
                    // This can never be true, but check to be explicit.
                    return Err(Error::SizeError);
                }

                (
                    match algorithm {
                        AlgorithmId::EccP256 => 32,
                        AlgorithmId::EccP384 => 48,
                        _ => unreachable!(),
                    },
                    vec![ec_data],
                    0x06,
                )
            }
            _ => return Err(Error::GenericError),
        },
    };

    let mut offset = 0;

    for (i, param) in params.into_iter().enumerate() {
        key_data[offset] = param_tag + i as u8;
        offset += 1;

        offset += set_length(&mut key_data[offset..], elem_len);

        let padding = elem_len - param.len();
        let remaining = key_data.len() - offset;

        if padding > remaining {
            return Err(Error::AlgorithmError);
        }

        for b in &mut key_data[offset..offset + padding] {
            *b = 0;
        }
        offset += padding;
        key_data[offset..offset + param.len()].copy_from_slice(param);
        offset += param.len();
    }

    offset += pin_policy.write(&mut key_data[offset..]);
    offset += touch_policy.write(&mut key_data[offset..]);

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

/// Generate an attestation certificate for a stored key.
/// <https://developers.yubico.com/PIV/Introduction/PIV_attestation.html>
#[cfg(feature = "untested")]
pub fn attest(yubikey: &mut YubiKey, key: SlotId) -> Result<Buffer, Error> {
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

/// Sign data using a PIV key
#[cfg(feature = "untested")]
pub fn sign_data(
    yubikey: &mut YubiKey,
    raw_in: &[u8],
    algorithm: AlgorithmId,
    key: SlotId,
) -> Result<Buffer, Error> {
    let txn = yubikey.begin_transaction()?;

    // don't attempt to reselect in crypt operations to avoid problems with PIN_ALWAYS
    txn.authenticated_command(raw_in, algorithm, key, false)
}

/// Decrypt data using a PIV key
#[cfg(feature = "untested")]
pub fn decrypt_data(
    yubikey: &mut YubiKey,
    input: &[u8],
    algorithm: AlgorithmId,
    key: SlotId,
) -> Result<Buffer, Error> {
    let txn = yubikey.begin_transaction()?;

    // don't attempt to reselect in crypt operations to avoid problems with PIN_ALWAYS
    txn.authenticated_command(input, algorithm, key, true)
}
