//! YubiKey-related types and communication support

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
    apdu::{Apdu, Ins},
    cccid::Ccc,
    chuid::ChuId,
    config::Config,
    error::Error,
    mgm::MgmKey,
    readers::{Reader, Readers},
    transaction::Transaction,
};
use log::{error, info};
use pcsc::Card;
use std::{
    convert::{TryFrom, TryInto},
    fmt::{self, Display},
    str::FromStr,
};

#[cfg(feature = "untested")]
use crate::{
    apdu::StatusWords, metadata::AdminData, transaction::ChangeRefAction, Buffer, ObjectId,
    MGMT_AID, TAG_ADMIN_FLAGS_1, TAG_ADMIN_TIMESTAMP,
};
use getrandom::getrandom;
#[cfg(feature = "untested")]
use secrecy::ExposeSecret;
#[cfg(feature = "untested")]
use std::time::{SystemTime, UNIX_EPOCH};

/// Flag for PUK blocked
pub(crate) const ADMIN_FLAGS_1_PUK_BLOCKED: u8 = 0x01;

/// 3DES authentication
pub(crate) const ALGO_3DES: u8 = 0x03;

/// Card management key
pub(crate) const KEY_CARDMGM: u8 = 0x9b;

const TAG_DYN_AUTH: u8 = 0x7c;

/// Cached YubiKey PIN
pub type CachedPin = secrecy::SecretVec<u8>;

/// YubiKey Serial Number
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Serial(pub u32);

impl From<u32> for Serial {
    fn from(num: u32) -> Serial {
        Serial(num)
    }
}

impl From<Serial> for u32 {
    fn from(serial: Serial) -> u32 {
        serial.0
    }
}

impl FromStr for Serial {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        u32::from_str(s).map(Serial).map_err(|_| Error::ParseError)
    }
}

impl Display for Serial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// YubiKey Version
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Version {
    /// Major version component
    pub major: u8,

    /// Minor version component
    pub minor: u8,

    /// Patch version component
    pub patch: u8,
}

impl Version {
    /// Parse a version from bytes
    pub fn new(bytes: [u8; 3]) -> Version {
        Version {
            major: bytes[0],
            minor: bytes[1],
            patch: bytes[2],
        }
    }
}

impl Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// YubiKey Device: this is the primary API for opening a session and
/// performing various operations.
///
/// Almost all functionality in this library will require an open session
/// with a YubiKey which is represented by this type.
// TODO(tarcieri): reduce coupling to internal fields via `pub(crate)`
#[cfg_attr(not(feature = "untested"), allow(dead_code))]
pub struct YubiKey {
    pub(crate) card: Card,
    pub(crate) name: String,
    pub(crate) pin: Option<CachedPin>,
    pub(crate) version: Version,
    pub(crate) serial: Serial,
}

impl YubiKey {
    /// Open a connection to a YubiKey.
    ///
    /// Returns an error if there is more than one YubiKey detected.
    ///
    /// If you need to operate in environments with more than one YubiKey
    /// attached to the same system, use [`YubiKey::open_by_serial`] or
    /// [`yubikey::Readers`][`Readers`] to select from the available
    /// PC/SC readers.
    pub fn open() -> Result<Self, Error> {
        let mut readers = Readers::open().map_err(|e| match e {
            Error::PcscError {
                inner: Some(pcsc::Error::NoReadersAvailable),
            } => Error::NotFound,
            other => other,
        })?;
        let mut reader_iter = readers.iter()?;

        if let Some(reader) = reader_iter.next() {
            if reader_iter.next().is_some() {
                error!("multiple YubiKeys detected!");
                return Err(Error::PcscError { inner: None });
            }

            return reader.open();
        }

        error!("no YubiKey detected!");
        Err(Error::NotFound)
    }

    /// Open a YubiKey with a specific serial number.
    pub fn open_by_serial(serial: Serial) -> Result<Self, Error> {
        let mut readers = Readers::open().map_err(|e| match e {
            Error::PcscError {
                inner: Some(pcsc::Error::NoReadersAvailable),
            } => Error::NotFound,
            other => other,
        })?;

        for reader in readers.iter()? {
            let yubikey = match reader.open() {
                Ok(yk) => yk,
                Err(_) => continue,
            };

            if serial == yubikey.serial() {
                return Ok(yubikey);
            }
        }

        error!("no YubiKey detected with serial: {}", serial);
        Err(Error::NotFound)
    }

    /// Reconnect to a YubiKey
    #[cfg(feature = "untested")]
    pub fn reconnect(&mut self) -> Result<(), Error> {
        info!("trying to reconnect to current reader");

        self.card.reconnect(
            pcsc::ShareMode::Shared,
            pcsc::Protocols::T1,
            pcsc::Disposition::ResetCard,
        )?;

        let pin = self
            .pin
            .as_ref()
            .map(|p| Buffer::new(p.expose_secret().clone()));

        let txn = Transaction::new(&mut self.card)?;
        txn.select_application()?;

        if let Some(p) = &pin {
            txn.verify_pin(p)?;
        }

        Ok(())
    }

    /// Begin a transaction.
    pub(crate) fn begin_transaction(&mut self) -> Result<Transaction<'_>, Error> {
        // TODO(tarcieri): reconnect support
        Transaction::new(&mut self.card)
    }

    /// Get the name of the associated PC/SC card reader
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the YubiKey's PIV application version.
    ///
    /// This always uses the cached version queried when the key is initialized.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Get YubiKey device serial number.
    ///
    /// This always uses the cached version queried when the key is initialized.
    pub fn serial(&self) -> Serial {
        self.serial
    }

    /// Get device configuration.
    pub fn config(&mut self) -> Result<Config, Error> {
        Config::get(self)
    }

    /// Get CHUID
    pub fn chuid(&mut self) -> Result<ChuId, Error> {
        ChuId::get(self)
    }

    /// Get CCCID
    pub fn cccid(&mut self) -> Result<Ccc, Error> {
        Ccc::get(self)
    }

    /// Authenticate to the card using the provided management key (MGM).
    pub fn authenticate(&mut self, mgm_key: MgmKey) -> Result<(), Error> {
        let txn = self.begin_transaction()?;

        // get a challenge from the card
        let challenge = Apdu::new(Ins::Authenticate)
            .params(ALGO_3DES, KEY_CARDMGM)
            .data(&[TAG_DYN_AUTH, 0x02, 0x80, 0x00])
            .transmit(&txn, 261)?;

        if !challenge.is_success() || challenge.data().len() < 12 {
            return Err(Error::AuthenticationError);
        }

        // send a response to the cards challenge and a challenge of our own.
        let response = mgm_key.decrypt(challenge.data()[4..12].try_into().unwrap());

        let mut data = [0u8; 22];
        data[0] = TAG_DYN_AUTH;
        data[1] = 20; // 2 + 8 + 2 +8
        data[2] = 0x80;
        data[3] = 8;
        data[4..12].copy_from_slice(&response);
        data[12] = 0x81;
        data[13] = 8;

        if getrandom(&mut data[14..22]).is_err() {
            error!("failed getting randomness for authentication");
            return Err(Error::RandomnessError);
        }

        let mut challenge = [0u8; 8];
        challenge.copy_from_slice(&data[14..22]);

        let authentication = Apdu::new(Ins::Authenticate)
            .params(ALGO_3DES, KEY_CARDMGM)
            .data(&data)
            .transmit(&txn, 261)?;

        if !authentication.is_success() {
            return Err(Error::AuthenticationError);
        }

        // compare the response from the card with our challenge
        let response = mgm_key.encrypt(&challenge);

        use subtle::ConstantTimeEq;
        if response.ct_eq(&authentication.data()[4..12]).unwrap_u8() != 1 {
            return Err(Error::AuthenticationError);
        }

        Ok(())
    }

    /// Deauthenticate
    #[cfg(feature = "untested")]
    pub fn deauthenticate(&mut self) -> Result<(), Error> {
        let txn = self.begin_transaction()?;

        let status_words = Apdu::new(Ins::SelectApplication)
            .p1(0x04)
            .data(MGMT_AID)
            .transmit(&txn, 255)?
            .status_words();

        if !status_words.is_success() {
            error!(
                "Failed selecting mgmt application: {:04x}",
                status_words.code()
            );
            return Err(Error::GenericError);
        }

        Ok(())
    }

    /// Verify device PIN.
    pub fn verify_pin(&mut self, pin: &[u8]) -> Result<(), Error> {
        {
            let txn = self.begin_transaction()?;
            txn.verify_pin(pin)?;
        }

        if !pin.is_empty() {
            self.pin = Some(CachedPin::new(pin.into()))
        }

        Ok(())
    }

    /// Get the number of PIN retries
    pub fn get_pin_retries(&mut self) -> Result<u8, Error> {
        let txn = self.begin_transaction()?;

        // Force a re-select to unverify, because once verified the spec dictates that
        // subsequent verify calls will return a "verification not needed" instead of
        // the number of tries left...
        txn.select_application()?;

        // WRONG_PIN is expected on successful query.
        match txn.verify_pin(&[]) {
            Ok(()) => Ok(0), // TODO(tarcieri): verify this matches `yubico-piv-tool`
            Err(Error::WrongPin { tries }) => Ok(tries),
            Err(e) => Err(e),
        }
    }

    /// Set the number of PIN retries
    #[cfg(feature = "untested")]
    pub fn set_pin_retries(&mut self, pin_tries: u8, puk_tries: u8) -> Result<(), Error> {
        // Special case: if either retry count is 0, it's a successful no-op
        if pin_tries == 0 || puk_tries == 0 {
            return Ok(());
        }

        let txn = self.begin_transaction()?;

        let templ = [0, Ins::SetPinRetries.code(), pin_tries, puk_tries];

        let status_words = txn.transfer_data(&templ, &[], 255)?.status_words();

        match status_words {
            StatusWords::Success => Ok(()),
            StatusWords::AuthBlockedError => Err(Error::AuthenticationError),
            StatusWords::SecurityStatusError => Err(Error::AuthenticationError),
            _ => Err(Error::GenericError),
        }
    }

    /// Change the Personal Identification Number (PIN).
    ///
    /// The default PIN code is 123456
    #[cfg(feature = "untested")]
    pub fn change_pin(&mut self, current_pin: &[u8], new_pin: &[u8]) -> Result<(), Error> {
        {
            let txn = self.begin_transaction()?;
            txn.change_ref(ChangeRefAction::ChangePin, current_pin, new_pin)?;
        }

        if !new_pin.is_empty() {
            self.pin = Some(CachedPin::new(new_pin.into()));
        }

        Ok(())
    }

    /// Set PIN last changed
    #[cfg(feature = "untested")]
    pub fn set_pin_last_changed(yubikey: &mut YubiKey) -> Result<(), Error> {
        let txn = yubikey.begin_transaction()?;

        let mut admin_data = AdminData::read(&txn)?;

        // TODO(tarcieri): double check this is little endian
        let tnow = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_le_bytes();

        admin_data
            .set_item(TAG_ADMIN_TIMESTAMP, &tnow)
            .map_err(|e| {
                error!("could not set pin timestamp, err = {}", e);
                e
            })?;

        admin_data.write(&txn).map_err(|e| {
            error!("could not write admin data, err = {}", e);
            e
        })?;

        Ok(())
    }

    /// Change the PIN Unblocking Key (PUK). PUKs are codes for resetting
    /// lost/forgotten PINs, or devices that have become blocked because of too
    /// many failed attempts.
    ///
    /// The PUK is part of the PIV standard that the YubiKey follows.
    ///
    /// The default PUK code is 12345678.
    #[cfg(feature = "untested")]
    pub fn change_puk(&mut self, current_puk: &[u8], new_puk: &[u8]) -> Result<(), Error> {
        let txn = self.begin_transaction()?;
        txn.change_ref(ChangeRefAction::ChangePuk, current_puk, new_puk)
    }

    /// Block PUK: permanently prevent the PIN from becoming unblocked
    #[cfg(feature = "untested")]
    pub fn block_puk(yubikey: &mut YubiKey) -> Result<(), Error> {
        let mut puk = [0x30, 0x42, 0x41, 0x44, 0x46, 0x30, 0x30, 0x44];
        let mut tries_remaining: i32 = -1;
        let mut flags = [0];

        let txn = yubikey.begin_transaction()?;

        while tries_remaining != 0 {
            // 2 -> change puk
            let res = txn.change_ref(ChangeRefAction::ChangePuk, &puk, &puk);

            match res {
                Ok(()) => puk[0] += 1,
                Err(Error::WrongPin { tries }) => {
                    tries_remaining = tries as i32;
                    continue;
                }
                Err(e) => {
                    // depending on the firmware, tries may not be set to zero when the PUK is blocked,
                    // instead, the return code will be PIN_LOCKED and tries will be unset
                    if e != Error::PinLocked {
                        continue;
                    }
                    tries_remaining = 0;
                }
            }
        }

        // Attempt to set the "PUK blocked" flag in admin data.

        let mut admin_data = if let Ok(admin_data) = AdminData::read(&txn) {
            if let Ok(item) = admin_data.get_item(TAG_ADMIN_FLAGS_1) {
                if item.len() == flags.len() {
                    flags.copy_from_slice(item)
                } else {
                    error!(
                        "admin flags exist, but are incorrect size: {} (expected {})",
                        item.len(),
                        flags.len()
                    );
                }
            }

            admin_data
        } else {
            AdminData::default()
        };

        flags[0] |= ADMIN_FLAGS_1_PUK_BLOCKED;

        if admin_data.set_item(TAG_ADMIN_FLAGS_1, &flags).is_ok() {
            if admin_data.write(&txn).is_err() {
                error!("could not write admin metadata");
            }
        } else {
            error!("could not set admin flags");
        }

        Ok(())
    }

    /// Unblock a Personal Identification Number (PIN) using a previously
    /// configured PIN Unblocking Key (PUK).
    #[cfg(feature = "untested")]
    pub fn unblock_pin(&mut self, puk: &[u8], new_pin: &[u8]) -> Result<(), Error> {
        let txn = self.begin_transaction()?;
        txn.change_ref(ChangeRefAction::UnblockPin, puk, new_pin)
    }

    /// Fetch an object from the YubiKey
    #[cfg(feature = "untested")]
    pub fn fetch_object(&mut self, object_id: ObjectId) -> Result<Buffer, Error> {
        let txn = self.begin_transaction()?;
        txn.fetch_object(object_id)
    }

    /// Save an object
    #[cfg(feature = "untested")]
    pub fn save_object(&mut self, object_id: ObjectId, indata: &mut [u8]) -> Result<(), Error> {
        let txn = self.begin_transaction()?;
        txn.save_object(object_id, indata)
    }

    /// Get an auth challenge
    #[cfg(feature = "untested")]
    pub fn get_auth_challenge(&mut self) -> Result<[u8; 8], Error> {
        let txn = self.begin_transaction()?;

        let response = Apdu::new(Ins::Authenticate)
            .params(ALGO_3DES, KEY_CARDMGM)
            .data(&[0x7c, 0x02, 0x81, 0x00])
            .transmit(&txn, 261)?;

        if !response.is_success() {
            return Err(Error::AuthenticationError);
        }

        Ok(response.data()[4..12].try_into().unwrap())
    }

    /// Verify an auth response
    #[cfg(feature = "untested")]
    pub fn verify_auth_response(&mut self, response: [u8; 8]) -> Result<(), Error> {
        let mut data = [0u8; 12];
        data[0] = 0x7c;
        data[1] = 0x0a;
        data[2] = 0x82;
        data[3] = 0x08;
        data[4..12].copy_from_slice(&response);

        let txn = self.begin_transaction()?;

        // send the response to the card and a challenge of our own.
        let status_words = Apdu::new(Ins::Authenticate)
            .params(ALGO_3DES, KEY_CARDMGM)
            .data(&data)
            .transmit(&txn, 261)?
            .status_words();

        if !status_words.is_success() {
            return Err(Error::AuthenticationError);
        }

        Ok(())
    }

    /// Reset YubiKey.
    ///
    /// WARNING: this is a destructive operation which will destroy all keys!
    ///
    /// The reset function is only available when both pins are blocked.
    #[cfg(feature = "untested")]
    pub fn reset_device(&mut self) -> Result<(), Error> {
        let templ = [0, Ins::Reset.code(), 0, 0];
        let txn = self.begin_transaction()?;
        let status_words = txn.transfer_data(&templ, &[], 255)?.status_words();

        if !status_words.is_success() {
            return Err(Error::GenericError);
        }

        Ok(())
    }
}

impl<'a> TryFrom<&'a Reader<'_>> for YubiKey {
    type Error = Error;

    fn try_from(reader: &'a Reader<'_>) -> Result<Self, Error> {
        let mut card = reader.connect().map_err(|e| {
            error!("error connecting to reader '{}': {}", reader.name(), e);
            e
        })?;

        info!("connected to reader: {}", reader.name());

        let (version, serial) = {
            let txn = Transaction::new(&mut card)?;
            txn.select_application()?;

            let v = txn.get_version()?;
            let s = txn.get_serial(v)?;
            (v, s)
        };

        let yubikey = YubiKey {
            card,
            name: String::from(reader.name()),
            pin: None,
            version,
            serial,
        };

        Ok(yubikey)
    }
}
