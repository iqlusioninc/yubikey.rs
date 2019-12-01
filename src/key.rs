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
    apdu::{Ins, StatusWords},
    certificate::{self, Certificate},
    consts::*,
    error::Error,
    policy::{PinPolicy, TouchPolicy},
    serialization::*,
    settings,
    yubikey::YubiKey,
    Buffer, ObjectId,
};
use log::{debug, error, warn};
use std::convert::TryFrom;

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

/// Information about a generated key
// TODO(tarcieri): this could use some more work
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
#[allow(clippy::cognitive_complexity)]
pub fn generate(
    yubikey: &mut YubiKey,
    slot: SlotId,
    algorithm: AlgorithmId,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
) -> Result<GeneratedKey, Error> {
    let mut in_data = [0u8; 11];
    let mut templ = [0, Ins::GenerateAsymmetric.code(), 0, 0];
    let setting_roca: settings::BoolValue;

    match algorithm {
        AlgorithmId::Rsa1024 | AlgorithmId::Rsa2048 => {
            if yubikey.device_model() == DEVTYPE_YK4
                && yubikey.version.major == 4
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

    templ[3] = slot.into();

    let mut offset = 5;
    in_data[..offset].copy_from_slice(&[
        0xac,
        3, // length sans this 2-byte header
        YKPIV_ALGO_TAG,
        1,
        algorithm.into(),
    ]);

    if in_data[4] == 0 {
        error!("unexpected algorithm");
        return Err(Error::AlgorithmError);
    }

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
                error!("{} (error {:x})", err_msg, other.code());
                return Err(Error::GenericError);
            }
        }
    }

    let data = Buffer::new(response.data().into());

    match algorithm {
        AlgorithmId::Rsa1024 | AlgorithmId::Rsa2048 => {
            let mut offset = 5;
            let mut len = 0;

            if data[offset] != TAG_RSA_MODULUS {
                error!("Failed to parse public key structure (modulus)");
                return Err(Error::ParseError);
            }

            offset += 1;
            offset += get_length(&data[offset..], &mut len);
            let modulus = data[offset..(offset + len)].to_vec();
            offset += len;

            if data[offset] != TAG_RSA_EXP {
                error!("failed to parse public key structure (public exponent)");
                return Err(Error::ParseError);
            }

            offset += 1;
            offset += get_length(&data[offset..], &mut len);
            let exp = data[offset..(offset + len)].to_vec();
            Ok(GeneratedKey::Rsa {
                algorithm,
                modulus,
                exp,
            })
        }
        AlgorithmId::EccP256 | AlgorithmId::EccP384 => {
            let mut offset = 3;

            let len = if let AlgorithmId::EccP256 = algorithm {
                CB_ECC_POINTP256
            } else {
                CB_ECC_POINTP384
            };

            if data[offset] != TAG_ECC_POINT {
                error!("failed to parse public key structure");
                return Err(Error::ParseError);
            }
            offset += 1;

            // the curve point should always be determined by the curve
            let len_byte = data[offset];
            offset += 1;

            if len_byte as usize != len {
                error!("unexpected length");
                return Err(Error::AlgorithmError);
            }

            let point = data[offset..(offset + len)].to_vec();
            Ok(GeneratedKey::Ecc { algorithm, point })
        }
    }
}
