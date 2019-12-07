//! Management Key (MGM) for authenticating to the YubiKey management applet

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

use crate::{consts::*, error::Error};
use getrandom::getrandom;
use log::error;
use std::convert::{TryFrom, TryInto};
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "untested")]
use crate::{metadata, yubikey::YubiKey};
#[cfg(feature = "untested")]
use des::{
    block_cipher_trait::{generic_array::GenericArray, BlockCipher},
    TdesEde3,
};
#[cfg(feature = "untested")]
use hmac::Hmac;
#[cfg(feature = "untested")]
use pbkdf2::pbkdf2;
#[cfg(feature = "untested")]
use sha1::Sha1;

/// Default MGM key configured on all YubiKeys
const DEFAULT_MGM_KEY: [u8; DES_LEN_3DES] = [
    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
];

/// Management Key (MGM) key types (manual/derived/protected)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MgmType {
    /// Manual
    Manual = 0,

    /// Derived
    Derived = 1,

    /// Protected
    Protected = 2,
}

/// Management Key (MGM).
///
/// This key is used to authenticate to the management applet running on
/// a YubiKey in order to perform administrative functions.
///
/// The only supported algorithm for MGM keys is 3DES.
#[derive(Clone)]
pub struct MgmKey([u8; DES_LEN_3DES]);

impl MgmKey {
    /// Generate a random MGM key
    pub fn generate() -> Result<Self, Error> {
        let mut key_bytes = [0u8; DES_LEN_3DES];

        if getrandom(&mut key_bytes).is_err() {
            return Err(Error::RandomnessError);
        }

        MgmKey::new(key_bytes)
    }

    /// Create an MGM key from byte slice.
    ///
    /// Returns an error if the slice is the wrong size or the key is weak.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        bytes.as_ref().try_into()
    }

    /// Create an MGM key from the given byte array.
    ///
    /// Returns an error if the key is weak.
    pub fn new(key_bytes: [u8; DES_LEN_3DES]) -> Result<Self, Error> {
        if is_weak_key(&key_bytes) {
            error!(
                "blacklisting key '{:?}' since it's weak (with odd parity)",
                &key_bytes
            );

            return Err(Error::KeyError);
        }

        Ok(MgmKey(key_bytes))
    }

    /// Get derived management key (MGM)
    #[cfg(feature = "untested")]
    pub fn get_derived(yubikey: &mut YubiKey, pin: &[u8]) -> Result<Self, Error> {
        let txn = yubikey.begin_transaction()?;

        // recover management key
        let data = metadata::read(&txn, TAG_ADMIN)?;
        let salt = metadata::get_item(&data, TAG_ADMIN_SALT)?;

        if salt.len() != CB_ADMIN_SALT {
            error!(
                "derived MGM salt exists, but is incorrect size: {} (expected {})",
                salt.len(),
                CB_ADMIN_SALT
            );

            return Err(Error::GenericError);
        }

        let mut mgm = [0u8; DES_LEN_3DES];
        pbkdf2::<Hmac<Sha1>>(pin, &salt, ITER_MGM_PBKDF2, &mut mgm);

        MgmKey::from_bytes(mgm)
    }

    /// Get protected management key (MGM)
    #[cfg(feature = "untested")]
    pub fn get_protected(yubikey: &mut YubiKey) -> Result<Self, Error> {
        let txn = yubikey.begin_transaction()?;

        let data = metadata::read(&txn, TAG_PROTECTED).map_err(|e| {
            error!("could not read protected data (err: {:?})", e);
            e
        })?;

        let item = metadata::get_item(&data, TAG_PROTECTED_MGM).map_err(|e| {
            error!("could not read protected MGM from metadata (err: {:?})", e);
            e
        })?;

        if item.len() != DES_LEN_3DES {
            error!(
                "protected data contains MGM, but is the wrong size: {} (expected {})",
                item.len(),
                DES_LEN_3DES
            );

            return Err(Error::AuthenticationError);
        }

        MgmKey::from_bytes(item)
    }

    /// Set the management key (MGM)
    #[cfg(feature = "untested")]
    pub fn set(&self, yubikey: &mut YubiKey, touch: Option<u8>) -> Result<(), Error> {
        let txn = yubikey.begin_transaction()?;
        txn.set_mgm_key(&self, touch)
    }

    /// Set protected management key (MGM)
    #[cfg(feature = "untested")]
    pub fn set_protected(&self, yubikey: &mut YubiKey) -> Result<(), Error> {
        let mut data = Zeroizing::new(vec![0u8; CB_BUF_MAX]);

        let txn = yubikey.begin_transaction()?;

        txn.set_mgm_key(self, None).map_err(|e| {
            // log a warning, since the device mgm key is corrupt or we're in
            // a state where we can't set the mgm key
            error!("could not set new derived mgm key, err = {}", e);
            e
        })?;

        // after this point, we've set the mgm key, so the function should
        // succeed, regardless of being able to set the metadata

        // set the new mgm key in protected data
        let buffer = match metadata::read(&txn, TAG_PROTECTED) {
            Ok(b) => b,
            Err(_) => {
                // set current metadata blob size to zero, we'll add to the blank blob
                Zeroizing::new(vec![])
            }
        };
        let mut cb_data = buffer.len();
        data[..cb_data].copy_from_slice(&buffer);

        if let Err(e) = metadata::set_item(
            data.as_mut_slice(),
            &mut cb_data,
            CB_OBJ_MAX,
            TAG_PROTECTED_MGM,
            self.as_ref(),
        ) {
            error!("could not set protected mgm item, err = {:?}", e);
        } else {
            metadata::write(&txn, TAG_PROTECTED, &data).map_err(|e| {
                error!("could not write protected data, err = {:?}", e);
                e
            })?;
        }

        // set the protected mgm flag in admin data
        cb_data = data.len();

        let mut flags_1 = [0u8; 1];

        if let Ok(buffer) = metadata::read(&txn, TAG_ADMIN) {
            if let Ok(item) = metadata::get_item(&buffer, TAG_ADMIN_FLAGS_1) {
                if item.len() == flags_1.len() {
                    flags_1.copy_from_slice(item);
                } else {
                    error!(
                        "admin data flags are an incorrect size: {} (expected {})",
                        item.len(),
                        flags_1.len()
                    );
                }
            } else {
                // flags are not set
                error!("admin data exists, but flags are not present");
            }

            // remove any existing salt
            if let Err(e) =
                metadata::set_item(&mut data, &mut cb_data, CB_OBJ_MAX, TAG_ADMIN_SALT, &[])
            {
                error!("could not unset derived mgm salt (err = {})", e)
            }
        } else {
            cb_data = 0;
        }

        flags_1[0] |= ADMIN_FLAGS_1_PROTECTED_MGM;

        if let Err(e) = metadata::set_item(
            data.as_mut_slice(),
            &mut cb_data,
            CB_OBJ_MAX,
            TAG_ADMIN_FLAGS_1,
            &flags_1,
        ) {
            error!("could not set admin flags item, err = {}", e);
        } else if let Err(e) = metadata::write(&txn, TAG_ADMIN, &data[..cb_data]) {
            error!("could not write admin data, err = {}", e);
        }

        Ok(())
    }

    /// Encrypt with 3DES key
    #[cfg(feature = "untested")]
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub(crate) fn encrypt(&self, input: &[u8; DES_LEN_DES]) -> [u8; DES_LEN_DES] {
        let mut output = input.to_owned();
        TdesEde3::new(GenericArray::from_slice(&self.0))
            .encrypt_block(GenericArray::from_mut_slice(&mut output));
        output
    }

    /// Decrypt with 3DES key
    #[cfg(feature = "untested")]
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub(crate) fn decrypt(&self, input: &[u8; DES_LEN_DES]) -> [u8; DES_LEN_DES] {
        let mut output = input.to_owned();
        TdesEde3::new(GenericArray::from_slice(&self.0))
            .decrypt_block(GenericArray::from_mut_slice(&mut output));
        output
    }
}

impl AsRef<[u8; DES_LEN_3DES]> for MgmKey {
    fn as_ref(&self) -> &[u8; DES_LEN_3DES] {
        &self.0
    }
}

impl Default for MgmKey {
    fn default() -> Self {
        MgmKey(DEFAULT_MGM_KEY)
    }
}

impl Drop for MgmKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<'a> TryFrom<&'a [u8]> for MgmKey {
    type Error = Error;

    fn try_from(key_bytes: &'a [u8]) -> Result<Self, Error> {
        Self::new(key_bytes.try_into().map_err(|_| Error::SizeError)?)
    }
}

/// Weak and semi weak DES keys as taken from:
/// %A D.W. Davies
/// %A W.L. Price
/// %T Security for Computer Networks
/// %I John Wiley & Sons
/// %D 1984
const WEAK_DES_KEYS: &[[u8; DES_LEN_DES]] = &[
    // weak keys
    [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01],
    [0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE],
    [0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E],
    [0xE0, 0xE0, 0xE0, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1],
    // semi-weak keys
    [0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE],
    [0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01],
    [0x1F, 0xE0, 0x1F, 0xE0, 0x0E, 0xF1, 0x0E, 0xF1],
    [0xE0, 0x1F, 0xE0, 0x1F, 0xF1, 0x0E, 0xF1, 0x0E],
    [0x01, 0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1],
    [0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1, 0x01],
    [0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E, 0xFE],
    [0xFE, 0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E],
    [0x01, 0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E],
    [0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E, 0x01],
    [0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1, 0xFE],
    [0xFE, 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1],
];

/// Is this 3DES key weak?
///
/// This check is performed automatically when the key is instantiated to
/// ensure no such keys are used.
fn is_weak_key(key: &[u8; DES_LEN_3DES]) -> bool {
    // set odd parity of key
    let mut tmp = Zeroizing::new([0u8; DES_LEN_3DES]);

    for i in 0..DES_LEN_3DES {
        // count number of set bits in byte, excluding the low-order bit - SWAR method
        let mut c = key[i] & 0xFE;

        c = (c & 0x55) + ((c >> 1) & 0x55);
        c = (c & 0x33) + ((c >> 2) & 0x33);
        c = (c & 0x0F) + ((c >> 4) & 0x0F);

        // if count is even, set low key bit to 1, otherwise 0
        tmp[i] = (key[i] & 0xFE) | (if c & 0x01 == 0x01 { 0x00 } else { 0x01 });
    }

    // check odd parity key against table by DES key block
    let mut is_weak = false;

    for weak_key in WEAK_DES_KEYS.iter() {
        if weak_key == &tmp[0..DES_LEN_DES]
            || weak_key == &tmp[DES_LEN_DES..2 * DES_LEN_DES]
            || weak_key == &tmp[2 * DES_LEN_DES..3 * DES_LEN_DES]
        {
            is_weak = true;
            break;
        }
    }

    is_weak
}
