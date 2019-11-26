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
    apdu::StatusWords,
    certificate::{self, Certificate},
    consts::*,
    error::Error,
    serialization::*,
    settings,
    yubikey::YubiKey,
    AlgorithmId, Buffer, ObjectId,
};
use log::{debug, error, warn};

/// Slot identifiers.
/// <https://developers.yubico.com/PIV/Introduction/Certificate_slots.html>
// TODO(tarcieri): replace these with enums
pub type SlotId = u8;

/// Get the [`ObjectId`] that corresponds to a given [`SlotId`]
// TODO(tarcieri): factor this into a slot ID enum
pub(crate) fn slot_object(slot: SlotId) -> Result<ObjectId, Error> {
    let id = match slot {
        YKPIV_KEY_AUTHENTICATION => YKPIV_OBJ_AUTHENTICATION,
        YKPIV_KEY_SIGNATURE => YKPIV_OBJ_SIGNATURE,
        YKPIV_KEY_KEYMGM => YKPIV_OBJ_KEY_MANAGEMENT,
        YKPIV_KEY_CARDAUTH => YKPIV_OBJ_CARD_AUTH,
        YKPIV_KEY_ATTESTATION => YKPIV_OBJ_ATTESTATION,
        slot if slot >= YKPIV_KEY_RETIRED1 && (slot <= YKPIV_KEY_RETIRED20) => {
            YKPIV_OBJ_RETIRED1 + (slot - YKPIV_KEY_RETIRED1) as u32
        }
        _ => return Err(Error::InvalidObject),
    };

    Ok(id)
}

/// Personal Identity Verification (PIV) key slots
pub const SLOTS: [u8; 24] = [
    YKPIV_KEY_AUTHENTICATION,
    YKPIV_KEY_SIGNATURE,
    YKPIV_KEY_KEYMGM,
    YKPIV_KEY_RETIRED1,
    YKPIV_KEY_RETIRED2,
    YKPIV_KEY_RETIRED3,
    YKPIV_KEY_RETIRED4,
    YKPIV_KEY_RETIRED5,
    YKPIV_KEY_RETIRED6,
    YKPIV_KEY_RETIRED7,
    YKPIV_KEY_RETIRED8,
    YKPIV_KEY_RETIRED9,
    YKPIV_KEY_RETIRED10,
    YKPIV_KEY_RETIRED11,
    YKPIV_KEY_RETIRED12,
    YKPIV_KEY_RETIRED13,
    YKPIV_KEY_RETIRED14,
    YKPIV_KEY_RETIRED15,
    YKPIV_KEY_RETIRED16,
    YKPIV_KEY_RETIRED17,
    YKPIV_KEY_RETIRED18,
    YKPIV_KEY_RETIRED19,
    YKPIV_KEY_RETIRED20,
    YKPIV_KEY_CARDAUTH,
];

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
                    debug!("error reading certificate in slot {}: {}", slot, e);
                    continue;
                }
            };

            let cert = Certificate::new(buf)?;
            keys.push(Key { slot, cert });
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
    pin_policy: u8,
    touch_policy: u8,
) -> Result<GeneratedKey, Error> {
    let mut in_data = [0u8; 11];
    let mut templ = [0, YKPIV_INS_GENERATE_ASYMMETRIC, 0, 0];
    let setting_roca: settings::BoolValue;

    if yubikey.device_model() == DEVTYPE_YK4
        && (algorithm == YKPIV_ALGO_RSA1024 || algorithm == YKPIV_ALGO_RSA2048)
        && yubikey.version.major == 4
        && (yubikey.version.minor < 3 || yubikey.version.minor == 3 && (yubikey.version.patch < 5))
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

    match algorithm {
        YKPIV_ALGO_RSA1024 | YKPIV_ALGO_RSA2048 | YKPIV_ALGO_ECCP256 | YKPIV_ALGO_ECCP384 => (),
        _ => {
            error!("invalid algorithm specified");
            return Err(Error::GenericError);
        }
    }

    let txn = yubikey.begin_transaction()?;

    templ[3] = slot;

    let mut offset = 5;
    in_data[..offset].copy_from_slice(&[
        0xac,
        3, // length sans this 2-byte header
        YKPIV_ALGO_TAG,
        1,
        algorithm,
    ]);

    if in_data[4] == 0 {
        error!("unexpected algorithm");
        return Err(Error::AlgorithmError);
    }

    if pin_policy != YKPIV_PINPOLICY_DEFAULT {
        in_data[1] += 3;
        in_data[offset..(offset + 3)].copy_from_slice(&[YKPIV_PINPOLICY_TAG, 1, pin_policy]);
        offset += 3;
    }

    if touch_policy != YKPIV_TOUCHPOLICY_DEFAULT {
        in_data[1] += 3;
        in_data[offset..(offset + 3)].copy_from_slice(&[YKPIV_TOUCHPOLICY_TAG, 1, touch_policy]);
    }

    let response = txn.transfer_data(&templ, &in_data[..offset], 1024)?;

    if !response.is_success() {
        let err_msg = "failed to generate new key";

        match response.status_words() {
            StatusWords::IncorrectSlotError => {
                error!("{} (incorrect slot)", err_msg);
                return Err(Error::KeyError);
            }
            StatusWords::IncorrectParamError => {
                if pin_policy != YKPIV_PINPOLICY_DEFAULT {
                    error!("{} (pin policy not supported?)", err_msg);
                } else if touch_policy != YKPIV_TOUCHPOLICY_DEFAULT {
                    error!("{} (touch policy not supported?)", err_msg);
                } else {
                    error!("{} (algorithm not supported?)", err_msg);
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
        YKPIV_ALGO_RSA1024 | YKPIV_ALGO_RSA2048 => {
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
        YKPIV_ALGO_ECCP256 | YKPIV_ALGO_ECCP384 => {
            let mut offset = 3;

            let len = if algorithm == YKPIV_ALGO_ECCP256 {
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
        _ => {
            error!("wrong algorithm");
            Err(Error::AlgorithmError)
        }
    }
}
