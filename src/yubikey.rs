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

#![allow(non_snake_case, non_upper_case_globals)]
#![allow(clippy::too_many_arguments, clippy::missing_safety_doc)]

use crate::{
    apdu::APDU, consts::*, error::Error, key::SlotId, metadata, mgm::MgmKey, response::StatusWords,
    serialization::*, transaction::Transaction, Buffer, ObjectId,
};
use getrandom::getrandom;
use log::{error, info, warn};
use pcsc::{Card, Context};
use std::{
    convert::TryInto,
    fmt::{self, Display},
    ptr, slice,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

/// PIV Application ID
pub const AID: [u8; 5] = [0xa0, 0x00, 0x00, 0x03, 0x08];

/// MGMT Application ID.
/// <https://developers.yubico.com/PIV/Introduction/Admin_access.html>
pub const MGMT_AID: [u8; 8] = [0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];

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

/// YubiKey Device: this is the primary API for opening a session and
/// performing various operations.
///
/// Almost all functionality in this library will require an open session
/// with a YubiKey which is represented by this type.
// TODO(tarcieri): reduce coupling to internal fields via `pub(crate)`
pub struct YubiKey {
    pub(crate) card: Card,
    pub(crate) pin: Option<Buffer>,
    pub(crate) is_neo: bool,
    pub(crate) version: Version,
    pub(crate) serial: Serial,
}

impl YubiKey {
    /// Open a connection to a YubiKey, optionally giving the name
    /// (needed if e.g. there are multiple YubiKeys connected).
    pub fn open(name: Option<&[u8]>) -> Result<YubiKey, Error> {
        let context = Context::establish(pcsc::Scope::System)?;
        let mut card = Self::connect(&context, name)?;

        let mut is_neo = false;
        let version: Version;
        let serial: Serial;

        {
            let txn = Transaction::new(&mut card)?;
            let mut atr_buf = [0; CB_ATR_MAX];
            let atr = txn.get_attribute(pcsc::Attribute::AtrString, &mut atr_buf)?;
            if atr == YKPIV_ATR_NEO_R3 {
                is_neo = true;
            }

            txn.select_application()?;

            // now that the PIV application is selected, retrieve the version
            // and serial number.  Previously the NEO/YK4 required switching
            // to the yk applet to retrieve the serial, YK5 implements this
            // as a PIV applet command.  Unfortunately, this change requires
            // that we retrieve the version number first, so that get_serial
            // can determine how to get the serial number, which for the NEO/Yk4
            // will result in another selection of the PIV applet.

            version = txn.get_version().map_err(|e| {
                warn!("failed to retrieve version: '{}'", e);
                e
            })?;

            serial = txn.get_serial(version).map_err(|e| {
                warn!("failed to retrieve serial number: '{}'", e);
                e
            })?;
        }

        let yubikey = YubiKey {
            card,
            pin: None,
            is_neo,
            version,
            serial,
        };

        Ok(yubikey)
    }

    /// Connect to a YubiKey.
    fn connect(context: &Context, name: Option<&[u8]>) -> Result<Card, Error> {
        // ensure PC/SC context is valid
        context.is_valid()?;

        let buffer_len = context.list_readers_len()?;
        let mut buffer = vec![0u8; buffer_len];

        for reader in context.list_readers(&mut buffer)? {
            if let Some(wanted) = name {
                if reader.to_bytes() != wanted {
                    warn!(
                        "skipping reader '{}' since it doesn't match '{}'",
                        reader.to_string_lossy(),
                        String::from_utf8_lossy(wanted)
                    );

                    continue;
                }
            }

            info!("trying to connect to reader '{}'", reader.to_string_lossy());

            return Ok(context.connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::T1)?);
        }

        error!("error: no usable reader found");
        Err(Error::PcscError { inner: None })
    }

    /// Reconnect to a YubiKey
    pub fn reconnect(&mut self) -> Result<(), Error> {
        info!("trying to reconnect to current reader");

        self.card.reconnect(
            pcsc::ShareMode::Shared,
            pcsc::Protocols::T1,
            pcsc::Disposition::ResetCard,
        )?;

        // TODO(tarcieri): zeroize pin!
        let pin = self.pin.clone();

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
        Ok(Transaction::new(&mut self.card)?)
    }

    /// Authenticate to the card using the provided management key (MGM).
    pub fn authenticate(&mut self, mgm_key: MgmKey) -> Result<(), Error> {
        let txn = self.begin_transaction()?;

        // get a challenge from the card
        let challenge = APDU::new(YKPIV_INS_AUTHENTICATE)
            .params(YKPIV_ALGO_3DES, YKPIV_KEY_CARDMGM)
            .data(&[0x7c, 0x02, 0x80, 0x00])
            .transmit(&txn, 261)?;

        if !challenge.is_success() || challenge.buffer().len() < 12 {
            return Err(Error::AuthenticationError);
        }

        // send a response to the cards challenge and a challenge of our own.
        let response = mgm_key.decrypt(challenge.buffer()[4..12].try_into().unwrap());

        let mut data = [0u8; 22];
        data[0] = 0x7c;
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

        let authentication = APDU::new(YKPIV_INS_AUTHENTICATE)
            .params(YKPIV_ALGO_3DES, YKPIV_KEY_CARDMGM)
            .data(&data)
            .transmit(&txn, 261)?;

        if !authentication.is_success() {
            return Err(Error::AuthenticationError);
        }

        // compare the response from the card with our challenge
        let response = mgm_key.encrypt(&challenge);

        use subtle::ConstantTimeEq;
        if response.ct_eq(&authentication.buffer()[4..12]).unwrap_u8() != 1 {
            return Err(Error::AuthenticationError);
        }

        Ok(())
    }

    /// Sign data using a PIV key
    pub fn sign_data(
        &mut self,
        raw_in: &[u8],
        sign_out: &mut [u8],
        out_len: &mut usize,
        algorithm: u8,
        key: SlotId,
    ) -> Result<(), Error> {
        let txn = self.begin_transaction()?;

        // don't attempt to reselect in crypt operations to avoid problems with PIN_ALWAYS
        txn.authenticated_command(raw_in, sign_out, out_len, algorithm, key, false)
    }

    /// Decrypt data using a PIV key
    pub fn decrypt_data(
        &mut self,
        input: &[u8],
        out: &mut [u8],
        out_len: &mut usize,
        algorithm: u8,
        key: SlotId,
    ) -> Result<(), Error> {
        let txn = self.begin_transaction()?;

        // don't attempt to reselect in crypt operations to avoid problems with PIN_ALWAYS
        txn.authenticated_command(input, out, out_len, algorithm, key, true)
    }

    /// Get the YubiKey's PIV application version.
    ///
    /// This always uses the cached version queried when the key is initialized.
    pub fn version(&mut self) -> Version {
        self.version
    }

    /// Get YubiKey device serial number.
    ///
    /// This always uses the cached version queried when the key is initialized.
    pub fn get_serial(&mut self) -> Serial {
        self.serial
    }

    /// Verify device PIN.
    pub fn verify_pin(&mut self, pin: &[u8]) -> Result<(), Error> {
        {
            let txn = self.begin_transaction()?;
            txn.verify_pin(pin)?;
        }

        if !pin.is_empty() {
            self.pin = Some(Buffer::new(pin.into()))
        }

        Ok(())
    }

    /// Get the number of PIN retries
    pub fn get_pin_retries(&mut self) -> Result<u32, Error> {
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
    pub fn set_pin_retries(&mut self, pin_tries: usize, puk_tries: usize) -> Result<(), Error> {
        // Special case: if either retry count is 0, it's a successful no-op
        if pin_tries == 0 || puk_tries == 0 {
            return Ok(());
        }

        if pin_tries > 0xff || puk_tries > 0xff || pin_tries < 1 || puk_tries < 1 {
            return Err(Error::RangeError);
        }

        let txn = self.begin_transaction()?;

        let templ = [
            0,
            YKPIV_INS_SET_PIN_RETRIES,
            pin_tries as u8,
            puk_tries as u8,
        ];

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
    pub unsafe fn change_pin(&mut self, current_pin: &[u8], new_pin: &[u8]) -> Result<(), Error> {
        {
            let txn = self.begin_transaction()?;
            txn.change_pin(0, current_pin, new_pin)?;
        }

        if !new_pin.is_empty() {
            self.pin = Some(Buffer::new(new_pin.into()));
        }

        Ok(())
    }

    /// Set PIN last changed
    pub unsafe fn set_pin_last_changed(yubikey: &mut YubiKey) -> Result<(), Error> {
        let mut data = [0u8; YKPIV_OBJ_MAX_SIZE];
        let max_size = yubikey.obj_size_max();
        let txn = yubikey.begin_transaction()?;

        let buffer = metadata::read(&txn, TAG_ADMIN)?;
        let mut cb_data = buffer.len();
        data[..cb_data].copy_from_slice(&buffer);

        // TODO(tarcieri): double check this is little endian
        let tnow = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_le_bytes();

        metadata::set_item(
            &mut data,
            &mut cb_data,
            CB_OBJ_MAX,
            TAG_ADMIN_TIMESTAMP,
            &tnow,
        )
        .map_err(|e| {
            error!("could not set pin timestamp, err = {}", e);
            e
        })?;

        metadata::write(&txn, TAG_ADMIN, &data, max_size).map_err(|e| {
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
    pub unsafe fn change_puk(&mut self, current_puk: &[u8], new_puk: &[u8]) -> Result<(), Error> {
        let txn = self.begin_transaction()?;
        txn.change_pin(2, current_puk, new_puk)
    }

    /// Block PUK: permanently prevent the PIN from becoming unblocked
    pub fn block_puk(yubikey: &mut YubiKey) -> Result<(), Error> {
        let mut puk = [0x30, 0x42, 0x41, 0x44, 0x46, 0x30, 0x30, 0x44];
        let mut tries_remaining: i32 = -1;
        let mut flags = [0];

        let max_size = yubikey.obj_size_max();
        let txn = yubikey.begin_transaction()?;

        while tries_remaining != 0 {
            // 2 -> change puk
            let res = txn.change_pin(2, &puk, &puk);

            match res {
                Ok(()) => puk[0] += 1,
                Err(Error::WrongPin { tries }) => {
                    tries_remaining = tries as i32;
                    continue;
                }
                Err(e) => {
                    if e != Error::PinLocked {
                        continue;
                    }
                    tries_remaining = 0;
                }
            }
        }

        if let Ok(data) = metadata::read(&txn, TAG_ADMIN) {
            if let Ok(item) = metadata::get_item(&data, TAG_ADMIN_FLAGS_1) {
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
        }

        flags[0] |= ADMIN_FLAGS_1_PUK_BLOCKED;
        let mut data = [0u8; YKPIV_OBJ_MAX_SIZE];
        let mut cb_data: usize = data.len();

        if metadata::set_item(
            &mut data,
            &mut cb_data,
            CB_OBJ_MAX,
            TAG_ADMIN_FLAGS_1,
            &flags,
        )
        .is_ok()
        {
            if metadata::write(&txn, TAG_ADMIN, &data[..cb_data], max_size).is_err() {
                error!("could not write admin metadata");
            }
        } else {
            error!("could not set admin flags");
        }

        Ok(())
    }

    /// Unblock a Personal Identification Number (PIN) using a previously
    /// configured PIN Unblocking Key (PUK).
    pub unsafe fn unblock_pin(&mut self, puk: &[u8], new_pin: &[u8]) -> Result<(), Error> {
        let txn = self.begin_transaction()?;
        txn.change_pin(1, puk, new_pin)
    }

    /// Fetch an object from the YubiKey
    pub fn fetch_object(&mut self, object_id: ObjectId) -> Result<Buffer, Error> {
        let txn = self.begin_transaction()?;
        txn.fetch_object(object_id)
    }

    /// Save an object
    pub fn save_object(&mut self, object_id: ObjectId, indata: &mut [u8]) -> Result<(), Error> {
        let txn = self.begin_transaction()?;
        txn.save_object(object_id, indata)
    }

    /// Import a private encryption or signing key into the YubiKey
    // TODO(tarcieri): refactor this into separate methods per key type
    pub fn import_private_key(
        &mut self,
        key: SlotId,
        algorithm: u8,
        p: Option<&[u8]>,
        q: Option<&[u8]>,
        dp: Option<&[u8]>,
        dq: Option<&[u8]>,
        qinv: Option<&[u8]>,
        ec_data: Option<&[u8]>,
        pin_policy: u8,
        touch_policy: u8,
    ) -> Result<(), Error> {
        // TODO(tarcieri): get rid of legacy pointers
        let (p, p_len) = match p {
            Some(slice) => (slice.as_ptr(), slice.len()),
            None => (ptr::null(), 0),
        };

        let (q, q_len) = match q {
            Some(slice) => (slice.as_ptr(), slice.len()),
            None => (ptr::null(), 0),
        };

        let (dp, dp_len) = match dp {
            Some(slice) => (slice.as_ptr(), slice.len()),
            None => (ptr::null(), 0),
        };

        let (dq, dq_len) = match dq {
            Some(slice) => (slice.as_ptr(), slice.len()),
            None => (ptr::null(), 0),
        };

        let (qinv, qinv_len) = match qinv {
            Some(slice) => (slice.as_ptr(), slice.len()),
            None => (ptr::null(), 0),
        };

        let (ec_data, ec_data_len) = match ec_data {
            Some(slice) => (slice.as_ptr(), slice.len()),
            None => (ptr::null(), 0),
        };

        let mut key_data = Zeroizing::new(vec![0u8; 1024]);
        let mut in_ptr: *mut u8 = key_data.as_mut_ptr();
        let templ = [0, YKPIV_INS_IMPORT_KEY, algorithm, key];
        let mut elem_len: u32 = 0;
        let mut params: [*const u8; 5] = [ptr::null(); 5];
        let mut lens = [0usize; 5];
        let n_params: u8;
        let param_tag: i32;

        if key == YKPIV_KEY_CARDMGM
            || key < YKPIV_KEY_RETIRED1
            || key > YKPIV_KEY_RETIRED20 && (key < YKPIV_KEY_AUTHENTICATION)
            || key > YKPIV_KEY_CARDAUTH && (key != YKPIV_KEY_ATTESTATION)
        {
            return Err(Error::KeyError);
        }

        if pin_policy != YKPIV_PINPOLICY_DEFAULT
            && (pin_policy != YKPIV_PINPOLICY_NEVER)
            && (pin_policy != YKPIV_PINPOLICY_ONCE)
            && (pin_policy != YKPIV_PINPOLICY_ALWAYS)
        {
            return Err(Error::GenericError);
        }

        if touch_policy != YKPIV_TOUCHPOLICY_DEFAULT
            && (touch_policy != YKPIV_TOUCHPOLICY_NEVER)
            && (touch_policy != YKPIV_TOUCHPOLICY_ALWAYS)
            && (touch_policy != YKPIV_TOUCHPOLICY_CACHED)
        {
            return Err(Error::GenericError);
        }

        match algorithm {
            YKPIV_ALGO_RSA1024 | YKPIV_ALGO_RSA2048 => {
                if p_len + q_len + dp_len + dq_len + qinv_len >= 1024 {
                    return Err(Error::SizeError);
                } else {
                    if algorithm == YKPIV_ALGO_RSA1024 {
                        elem_len = 64;
                    }

                    if algorithm == YKPIV_ALGO_RSA2048 {
                        elem_len = 128;
                    }

                    if p.is_null() || q.is_null() || dp.is_null() || dq.is_null() || qinv.is_null()
                    {
                        return Err(Error::GenericError);
                    }

                    params[0] = p;
                    lens[0] = p_len;
                    params[1] = q;
                    lens[1] = q_len;
                    params[2] = dp;
                    lens[2] = dp_len;
                    params[3] = dq;
                    lens[3] = dq_len;
                    params[4] = qinv;
                    lens[4] = qinv_len;
                    param_tag = 0x1;
                    n_params = 5u8;
                }
            }
            YKPIV_ALGO_ECCP256 | YKPIV_ALGO_ECCP384 => {
                if ec_data_len >= key_data.len() {
                    return Err(Error::SizeError);
                }

                if algorithm == YKPIV_ALGO_ECCP256 {
                    elem_len = 32;
                } else if algorithm == YKPIV_ALGO_ECCP384 {
                    elem_len = 48;
                }

                if ec_data.is_null() {
                    return Err(Error::GenericError);
                }

                params[0] = ec_data;
                lens[0] = ec_data_len;
                param_tag = 0x6;
                n_params = 1;
            }
            _ => return Err(Error::AlgorithmError),
        }

        for i in 0..n_params {
            unsafe {
                *in_ptr = (param_tag + i as i32) as u8;
                in_ptr = in_ptr.offset(1);

                in_ptr = in_ptr.add(set_length(
                    slice::from_raw_parts_mut(
                        in_ptr,
                        key_data.as_mut_ptr() as usize - in_ptr as usize,
                    ),
                    elem_len as usize,
                ));
            }

            let padding = elem_len as usize - lens[i as usize];
            let remaining = (key_data.as_mut_ptr() as usize) + 1024 - in_ptr as usize;

            if padding > remaining {
                return Err(Error::AlgorithmError);
            }

            unsafe {
                ptr::write_bytes(in_ptr, 0, padding);
                in_ptr = in_ptr.add(padding);
                ptr::copy(params[i as usize], in_ptr, lens[i as usize]);
                in_ptr = in_ptr.add(lens[i as usize]);
            }
        }

        if pin_policy != YKPIV_PINPOLICY_DEFAULT {
            unsafe {
                *in_ptr = YKPIV_PINPOLICY_TAG;
                *in_ptr.add(1) = 0x01;
                *in_ptr.add(2) = pin_policy;
                in_ptr = in_ptr.add(3);
            }
        }

        if touch_policy != YKPIV_TOUCHPOLICY_DEFAULT {
            unsafe {
                *in_ptr = YKPIV_TOUCHPOLICY_TAG;
                *in_ptr.add(1) = 0x01;
                *in_ptr.add(2) = touch_policy;
                in_ptr = in_ptr.add(3);
            }
        }

        let txn = self.begin_transaction()?;
        let len = in_ptr as usize - key_data.as_mut_ptr() as usize;

        let status_words = txn
            .transfer_data(&templ, &key_data[..len], 256)?
            .status_words();

        match status_words {
            StatusWords::Success => Ok(()),
            StatusWords::SecurityStatusError => Err(Error::AuthenticationError),
            _ => Err(Error::GenericError),
        }
    }

    /// Generate an attestation certificate for a stored key.
    /// <https://developers.yubico.com/PIV/Introduction/PIV_attestation.html>
    pub fn attest(&mut self, key: SlotId) -> Result<Buffer, Error> {
        let templ = [0, YKPIV_INS_ATTEST, key, 0];
        let txn = self.begin_transaction()?;
        let response = txn.transfer_data(&templ, &[], CB_OBJ_MAX)?;

        if !response.is_success() {
            if response.status_words() == StatusWords::NotSupportedError {
                return Err(Error::NotSupported);
            } else {
                return Err(Error::GenericError);
            }
        }

        if response.buffer()[0] != 0x30 {
            return Err(Error::GenericError);
        }

        Ok(response.into_buffer())
    }

    /// Get an auth challenge
    pub fn get_auth_challenge(&mut self) -> Result<[u8; 8], Error> {
        let txn = self.begin_transaction()?;

        let response = APDU::new(YKPIV_INS_AUTHENTICATE)
            .params(YKPIV_ALGO_3DES, YKPIV_KEY_CARDMGM)
            .data(&[0x7c, 0x02, 0x81, 0x00])
            .transmit(&txn, 261)?;

        if !response.is_success() {
            return Err(Error::AuthenticationError);
        }

        Ok(response.buffer()[4..12].try_into().unwrap())
    }

    /// Verify an auth response
    pub fn verify_auth_response(&mut self, response: [u8; 8]) -> Result<(), Error> {
        let mut data = [0u8; 12];
        data[0] = 0x7c;
        data[1] = 0x0a;
        data[2] = 0x82;
        data[3] = 0x08;
        data[4..12].copy_from_slice(&response);

        let txn = self.begin_transaction()?;

        // send the response to the card and a challenge of our own.
        let status_words = APDU::new(YKPIV_INS_AUTHENTICATE)
            .params(YKPIV_ALGO_3DES, YKPIV_KEY_CARDMGM)
            .data(&data)
            .transmit(&txn, 261)?
            .status_words();

        if !status_words.is_success() {
            return Err(Error::AuthenticationError);
        }

        Ok(())
    }

    /// Deauthenticate
    pub fn deauthenticate(&mut self) -> Result<(), Error> {
        let txn = self.begin_transaction()?;

        let status_words = APDU::new(YKPIV_INS_SELECT_APPLICATION)
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

    /// Get YubiKey device model
    // TODO(tarcieri): use an emum for this
    pub fn device_model(&self) -> u32 {
        if self.is_neo {
            DEVTYPE_NEOr3
        } else {
            // TODO(tarcieri): YK5?
            DEVTYPE_YK4
        }
    }

    /// Reset YubiKey.
    ///
    /// WARNING: this is a destructive operation which will destroy all keys!
    pub fn reset_device(&mut self) -> Result<(), Error> {
        let templ = [0, YKPIV_INS_RESET, 0, 0];
        let txn = self.begin_transaction()?;
        let status_words = txn.transfer_data(&templ, &[], 255)?.status_words();

        if !status_words.is_success() {
            return Err(Error::GenericError);
        }

        Ok(())
    }

    /// Get max object size supported by this device
    pub(crate) fn obj_size_max(&self) -> usize {
        if self.is_neo {
            CB_OBJ_MAX_NEO
        } else {
            CB_OBJ_MAX
        }
    }
}
