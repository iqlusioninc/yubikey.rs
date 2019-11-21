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
    apdu::APDU,
    consts::*,
    error::Error,
    internal::{des_decrypt, des_encrypt, yk_des_is_weak_key, DesKey},
};
use getrandom::getrandom;
use libc::{c_char, free, malloc, memcmp, memcpy, memmove, memset, strlen, strncasecmp};
use log::{error, info, trace, warn};
use std::{ffi::CStr, os::raw::c_void, ptr, slice};
use zeroize::Zeroize;

extern "C" {
    fn SCardBeginTransaction(hCard: i32) -> i32;
    fn SCardConnect(
        hContext: i32,
        szReader: *const c_char,
        dwShareMode: u32,
        dwPreferredProtocols: u32,
        phCard: *mut i32,
        pdwActiveProtocol: *mut u32,
    ) -> i32;
    fn SCardDisconnect(hCard: i32, dwDisposition: u32) -> i32;
    fn SCardEndTransaction(hCard: i32, dwDisposition: u32) -> i32;
    fn SCardEstablishContext(
        dwScope: u32,
        pvReserved1: *const c_void,
        pvReserved2: *const c_void,
        phContext: *mut i32,
    ) -> i32;
    fn SCardIsValidContext(hContext: i32) -> i32;
    fn SCardListReaders(
        hContext: i32,
        mszGroups: *const c_char,
        mszReaders: *mut c_char,
        pcchReaders: *mut u32,
    ) -> i32;
    fn SCardReconnect(
        hCard: i32,
        dwShareMode: u32,
        dwPreferredProtocols: u32,
        dwInitialization: u32,
        pdwActiveProtocol: *mut u32,
    ) -> i32;
    fn SCardReleaseContext(hContext: i32) -> i32;
    fn SCardStatus(
        hCard: i32,
        mszReaderNames: *mut u8,
        pcchReaderLen: *mut u32,
        pdwState: *mut u32,
        pdwProtocol: *mut u32,
        pbAtr: *mut u8,
        pcbAtrLen: *mut u32,
    ) -> i32;
    fn SCardTransmit(
        hCard: i32,
        pioSendPci: *const c_void,
        pbSendBuffer: *const c_char,
        cbSendLength: u32,
        pioRecvPci: *const c_void,
        pbRecvBuffer: *mut u8,
        pcbRecvLength: *mut u32,
    ) -> i32;
}

/// TEMPORARY PLACEHOLDER for SCARD PCI_T1
// TODO(tarcieri): PLACEHOLDER!
pub const SCARD_PCI_T1: *const c_void = ptr::null();

/// TEMPORARY PLACEHOLDER for SCARD success value
// TODO(tarcieri): PLACEHOLDER!
pub const SCARD_S_SUCCESS: i32 = 0;

/// PIV Application ID
pub const AID: [u8; 5] = [0xa0, 0x00, 0x00, 0x03, 0x08];

/// MGMT Application ID
pub const MGMT_AID: [u8; 8] = [0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];

/// Default authentication key
pub const DEFAULT_AUTH_KEY: &[u8; DES_LEN_3DES] = b"\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08";

/// YubiKey PIV version
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Version {
    /// Major version component
    pub major: u8,

    /// Minor version component
    pub minor: u8,

    /// Patch version component
    pub patch: u8,
}

/// YubiKey PIV state
// TODO(tarcieri): reduce coupling to internal fields via `pub(crate)`
#[derive(Copy, Clone, Debug)]
pub struct YubiKey {
    pub(crate) context: i32,
    pub(crate) card: i32,
    pub(crate) pin: *mut u8,
    pub(crate) is_neo: bool,
    pub(crate) ver: Version,
    pub(crate) serial: u32,
}

impl YubiKey {
    /// Initialize YubiKey client instance
    pub fn ykpiv_init() -> Self {
        YubiKey {
            context: -1,
            card: 0,
            pin: ptr::null_mut(),
            is_neo: false,
            ver: Version {
                major: 0,
                minor: 0,
                patch: 0,
            },
            serial: 0,
        }
    }

    /// Cleanup YubiKey session
    pub(crate) unsafe fn _ykpiv_done(&mut self, disconnect: bool) -> Result<(), Error> {
        if disconnect {
            self.ykpiv_disconnect();
        }

        let _ = self._cache_pin(ptr::null(), 0);
        Ok(())
    }

    /// Cleanup YubiKey session with external card upon completion
    // TODO(tarcieri): make this a `Drop` handler
    pub unsafe fn ykpiv_done_with_external_card(&mut self) -> Result<(), Error> {
        self._ykpiv_done(false)
    }

    /// Cleanup YubiKey session upon completion
    pub unsafe fn ykpiv_done(&mut self) -> Result<(), Error> {
        self._ykpiv_done(true)
    }

    /// Disconnect a YubiKey session
    pub unsafe fn ykpiv_disconnect(&mut self) {
        if self.card != 0 {
            SCardDisconnect(self.card, 0x1);
            self.card = 0i32;
        }

        if SCardIsValidContext(self.context) == 0x0 {
            SCardReleaseContext(self.context);
            self.context = -1i32;
        }
    }

    /// Select application
    pub(crate) unsafe fn _ykpiv_select_application(&mut self) -> Result<(), Error> {
        let mut data = [0u8; 255];
        let mut recv_len = data.len() as u32;
        let mut sw = 0i32;

        let apdu = APDU::new(YKPIV_INS_SELECT_APPLICATION)
            .p1(0x04)
            .data(&AID)
            .to_bytes();

        if let Err(e) = self._send_data(apdu.as_slice(), data.as_mut_ptr(), &mut recv_len, &mut sw)
        {
            error!("failed communicating with card: \'{}\'", e);
            return Err(e);
        }

        if sw != SW_SUCCESS {
            error!("failed selecting application: {:04x}", sw);
            return Err(Error::GenericError);
        }

        // now that the PIV application is selected, retrieve the version
        // and serial number.  Previously the NEO/YK4 required switching
        // to the yk applet to retrieve the serial, YK5 implements this
        // as a PIV applet command.  Unfortunately, this change requires
        // that we retrieve the version number first, so that get_serial
        // can determine how to get the serial number, which for the NEO/Yk4
        // will result in another selection of the PIV applet.

        if let Err(e) = self._ykpiv_get_version() {
            warn!("failed to retrieve version: \'{}\'", e);
        }

        if let Err(e) = self._ykpiv_get_serial(false) {
            warn!("failed to retrieve serial number: \'{}\'", e);
        }

        Ok(())
    }

    /// Ensure an application is selected (presently noop)
    pub(crate) unsafe fn _ykpiv_ensure_application_selected(&mut self) -> Result<(), Error> {
        // TODO(tarcieri): ENABLE_APPLICATION_RESELECTION support?
        //
        // Original C code below:
        //
        //    #if ENABLE_APPLICATION_RESELECTION
        //      if (NULL == self) {
        //        return YKPIV_GENERIC_ERROR;
        //      }
        //
        //      res = ykpiv_verify(self, NULL, 0);
        //
        //      if ((YKPIV_OK != res) && (YKPIV_WRONG_PIN != res)) {
        //        res = _ykpiv_select_application(self);
        //      }
        //      else {
        //        res = YKPIV_OK;
        //      }
        //
        //      return res;
        //    #else
        //      (void)self;
        //      return res;
        //    #endif

        Ok(())
    }

    /// Connect to the YubiKey
    pub(crate) unsafe fn _ykpiv_connect(
        &mut self,
        context: usize,
        card: usize,
    ) -> Result<(), Error> {
        // if the context has changed, and the new context is not valid, return an error
        if context != self.context as (usize) && (0x0i32 != SCardIsValidContext(context as (i32))) {
            return Err(Error::PcscError);
        }

        // if card handle has changed, determine if handle is valid (less efficient, but complete)
        if card != self.card as usize {
            let mut reader = [0u8; YKPIV_OBJ_MAX_SIZE];
            let mut reader_len = reader.len() as u32;
            let mut atr = [0u8; 33];
            let mut atr_len = atr.len() as u32;

            // Cannot set the reader len to NULL. Confirmed in OSX 10.10,
            // so we have to retrieve it even though we don't need it.
            if SCardStatus(
                card as i32,
                reader.as_mut_ptr(),
                &mut reader_len,
                ptr::null_mut(),
                ptr::null_mut(),
                atr.as_mut_ptr(),
                &mut atr_len,
            ) != 0
            {
                return Err(Error::PcscError);
            }

            self.is_neo = (atr_len as usize == YKPIV_ATR_NEO_R3.len() - 1)
                && (memcmp(
                    YKPIV_ATR_NEO_R3.as_ptr() as *const c_void,
                    atr.as_mut_ptr() as *const c_void,
                    atr_len as usize,
                ) == 0);
        }

        self.context = context as i32;
        self.card = card as i32;

        // Do not select the applet here, as we need to accommodate commands that are
        // sensitive to re-select (custom apdu/auth). All commands that can handle explicit
        // selection already check the applet state and select accordingly anyway.
        // ykpiv_verify_select is supplied for those who want to select explicitly.
        //
        // The applet _is_ selected by ykpiv_connect(), but is not selected when bypassing
        // it with ykpiv_connect_with_external_card().

        Ok(())
    }

    /// Connect to an external card
    pub unsafe fn ykpiv_connect_with_external_card(
        &mut self,
        context: usize,
        card: usize,
    ) -> Result<(), Error> {
        self._ykpiv_connect(context, card)
    }

    /// Connect to a YubiKey
    pub unsafe fn ykpiv_connect(&mut self, wanted: *const c_char) -> Result<(), Error> {
        let mut active_protocol: u32 = 0;
        let mut reader_buf: [c_char; 2048] = [0; 2048];
        let mut num_readers = reader_buf.len();
        let mut reader_ptr: *mut c_char;
        let mut card: i32 = -1i32;

        self.ykpiv_list_readers(reader_buf.as_mut_ptr(), &mut num_readers)?;

        reader_ptr = reader_buf.as_mut_ptr();

        while *reader_ptr != 0 {
            if !wanted.is_null() {
                let mut ptr = reader_ptr;
                let mut found = false;

                while *ptr != 0 {
                    if strlen(ptr) < strlen(wanted) {
                        break;
                    }

                    if strncasecmp(ptr, wanted, strlen(wanted)) == 0 {
                        found = true;
                        break;
                    }

                    ptr = ptr.add(1);
                }

                if !found {
                    warn!(
                        "skipping reader \'{}\' since it doesn\'t match \'{}\'",
                        CStr::from_ptr(reader_ptr).to_string_lossy(),
                        CStr::from_ptr(wanted).to_string_lossy()
                    );

                    continue;
                }
            }

            info!(
                "trying to connect to reader \'{}\'",
                CStr::from_ptr(reader_ptr).to_string_lossy()
            );

            let rc = SCardConnect(
                self.context,
                reader_ptr,
                0x2u32,
                0x2u32,
                &mut card,
                &mut active_protocol,
            );

            if rc != 0x0 {
                error!("SCardConnect failed, rc={}", rc);
            } else {
                // at this point, card should not equal self->card,
                // to allow _ykpiv_connect() to determine device type
                if self
                    ._ykpiv_connect(self.context as (usize), card as (usize))
                    .is_err()
                {
                    break;
                }
            }

            reader_ptr = reader_ptr.add(strlen(reader_ptr) + 1);
        }

        if *reader_ptr == b'\0' as c_char {
            error!("error: no usable reader found");
            SCardReleaseContext(self.context);
            self.context = -1;
            return Err(Error::PcscError);
        }

        // Select applet.  This is done here instead of in _ykpiv_connect() because
        // you may not want to select the applet when connecting to a card handle that
        // was supplied by an external library.
        self._ykpiv_begin_transaction()?;

        let res = self._ykpiv_select_application();
        let _ = self._ykpiv_end_transaction();
        res
    }

    /// List readers
    pub unsafe fn ykpiv_list_readers(
        &mut self,
        readers: *mut c_char,
        len: *mut usize,
    ) -> Result<(), Error> {
        let mut num_readers: u32 = 0u32;
        let mut rc: i32;

        if SCardIsValidContext(self.context) != 0 {
            rc = SCardEstablishContext(0x2, ptr::null(), ptr::null(), &mut self.context);

            if rc != 0 {
                error!("error: SCardEstablishContext failed, rc={}", rc);
                return Err(Error::PcscError);
            }
        }

        rc = SCardListReaders(self.context, ptr::null(), ptr::null_mut(), &mut num_readers);

        if rc != 0 {
            error!("error: SCardListReaders failed, rc={}", rc);
            SCardReleaseContext(self.context);
            self.context = -1i32;
            return Err(Error::PcscError);
        }

        if num_readers as (usize) > *len {
            num_readers = *len as (u32);
        } else if num_readers as (usize) < *len {
            *len = num_readers as (usize);
        }

        rc = SCardListReaders(self.context, ptr::null(), readers, &mut num_readers);

        if rc != 0 {
            error!("error: SCardListReaders failed, rc={}", rc);
            SCardReleaseContext(self.context);
            self.context = -1i32;
            return Err(Error::PcscError);
        }

        *len = num_readers as usize;
        Ok(())
    }

    /// Reconnect to a YubiKey
    pub(crate) unsafe fn reconnect(&mut self) -> Result<(), Error> {
        info!("trying to reconnect to current reader");

        let mut active_protocol: u32 = 0;
        let rc = SCardReconnect(self.card, 0x2u32, 0x2u32, 0x1u32, &mut active_protocol);

        if rc != 0x0 {
            error!("SCardReconnect failed, rc={}", rc);
            return Err(Error::PcscError);
        }

        self._ykpiv_select_application()?;

        if !self.pin.is_null() {
            self.ykpiv_verify(self.pin as *const c_char).map(|_| ())
        } else {
            Ok(())
        }
    }

    /// Begin a transaction
    pub(crate) unsafe fn _ykpiv_begin_transaction(&mut self) -> Result<(), Error> {
        let mut rc = SCardBeginTransaction(self.card);

        if rc as usize & 0xffff_ffff == 0x8010_0068 {
            self.reconnect()?;
            rc = SCardBeginTransaction(self.card);
        }

        if rc != 0 {
            error!("failed to begin pcsc transaction, rc={}", rc);
            return Err(Error::PcscError);
        }

        Ok(())
    }

    /// End a transaction
    pub(crate) unsafe fn _ykpiv_end_transaction(&mut self) -> Result<(), Error> {
        let rc = SCardEndTransaction(self.card, 0x0);

        if rc != 0x0 {
            error!("failed to end pcsc transaction, rc={}", rc);
            return Err(Error::PcscError);
        }

        Ok(())
    }

    /// Transfer data
    pub(crate) unsafe fn _ykpiv_transfer_data(
        &mut self,
        templ: *const u8,
        in_data: *const u8,
        in_len: isize,
        mut out_data: *mut u8,
        out_len: *mut usize,
        sw: *mut i32,
    ) -> Result<(), Error> {
        let mut _currentBlock;
        let mut in_ptr: *const u8 = in_data;
        let max_out = *out_len;
        let mut res: Result<(), Error>;
        let mut recv_len: u32;

        *out_len = 0;

        loop {
            let mut this_size: usize = 0xff;
            let mut data = [0u8; 261];
            recv_len = data.len() as u32;

            let cla = if in_ptr.offset(0xff) < in_data.offset(in_len) {
                0x10
            } else {
                this_size = in_data.offset(in_len) as usize - in_ptr as usize;
                *templ
            };

            trace!("going to send {} bytes in this go", this_size);

            let apdu = APDU::new(*templ.offset(1))
                .cla(cla)
                .params(*templ.offset(2), *templ.offset(3))
                .data(slice::from_raw_parts(in_ptr, this_size))
                .to_bytes();

            res = self._send_data(apdu.as_slice(), data.as_mut_ptr(), &mut recv_len, sw);

            if res.is_err() {
                _currentBlock = 24;
                break;
            }

            if *sw != SW_SUCCESS && (*sw >> 8 != 0x61) {
                _currentBlock = 24;
                break;
            }

            if (*out_len)
                .wrapping_add(recv_len as (usize))
                .wrapping_sub(2usize)
                > max_out
            {
                _currentBlock = 21;
                break;
            }

            if !out_data.is_null() {
                memcpy(
                    out_data as (*mut c_void),
                    data.as_mut_ptr() as (*const c_void),
                    recv_len.wrapping_sub(2u32) as (usize),
                );
                out_data = out_data.offset(recv_len.wrapping_sub(2u32) as (isize));
                *out_len = (*out_len).wrapping_add(recv_len.wrapping_sub(2u32) as (usize));
            }

            in_ptr = in_ptr.add(this_size);

            if in_ptr >= in_data.offset(in_len) {
                _currentBlock = 10;
                break;
            }
        }

        if _currentBlock == 10 {
            loop {
                if *sw >> 8 != 0x61 {
                    _currentBlock = 24;
                    break;
                }

                let mut data = [0u8; 261];
                recv_len = data.len() as u32;

                trace!(
                    "The card indicates there is {} bytes more data for us.",
                    *sw & 0xff
                );

                let apdu = APDU::new(YKPIV_INS_GET_RESPONSE_APDU).to_bytes();

                res = self._send_data(apdu.as_slice(), data.as_mut_ptr(), &mut recv_len, sw);

                if res.is_err() {
                    _currentBlock = 24;
                    break;
                }
                if *sw != SW_SUCCESS && (*sw >> 8 != 0x61) {
                    _currentBlock = 24;
                    break;
                }
                if (*out_len).wrapping_add(recv_len as (usize)).wrapping_sub(2) > max_out {
                    _currentBlock = 18;
                    break;
                }

                if out_data.is_null() {
                    continue;
                }

                memcpy(
                    out_data as (*mut c_void),
                    data.as_mut_ptr() as (*const c_void),
                    recv_len.wrapping_sub(2) as (usize),
                );

                out_data = out_data.offset(recv_len.wrapping_sub(2) as (isize));
                *out_len = (*out_len).wrapping_add(recv_len.wrapping_sub(2) as (usize));
            }

            if _currentBlock != 24 {
                error!(
                    "Output buffer to small, wanted to write {}, max was {}.",
                    (*out_len).wrapping_add(recv_len as usize).wrapping_sub(2),
                    max_out
                );

                return Err(Error::SizeError);
            }
        } else if _currentBlock == 21 {
            error!(
                "Output buffer to small, wanted to write {}, max was {}.",
                (*out_len).wrapping_add(recv_len as usize).wrapping_sub(2),
                max_out
            );

            return Err(Error::SizeError);
        }

        res
    }

    /// Transfer data
    pub unsafe fn ykpiv_transfer_data(
        &mut self,
        templ: *const u8,
        in_data: *const u8,
        in_len: isize,
        out_data: *mut u8,
        out_len: *mut usize,
        sw: *mut i32,
    ) -> Result<(), Error> {
        if let Err(e) = self._ykpiv_begin_transaction() {
            *out_len = 0;
            return Err(e);
        }

        let res = self._ykpiv_transfer_data(templ, in_data, in_len, out_data, out_len, sw);
        let _ = self._ykpiv_end_transaction();
        res
    }

    /// Send data
    pub(crate) unsafe fn _send_data(
        &mut self,
        apdu: impl AsRef<[u8]>,
        data: *mut u8,
        recv_len: *mut u32,
        sw: *mut i32,
    ) -> Result<(), Error> {
        let send_len = apdu.as_ref().len() as u32;
        let apdu_ptr = apdu.as_ref().as_ptr();
        let mut tmp_len = *recv_len;

        trace!("> {:?}", apdu.as_ref());

        let rc = SCardTransmit(
            self.card,
            SCARD_PCI_T1,
            apdu_ptr as *const i8,
            send_len,
            ptr::null(),
            data,
            &mut tmp_len,
        );

        if rc != SCARD_S_SUCCESS {
            error!("error: SCardTransmit failed, rc={:08x}", rc);
            return Err(Error::PcscError);
        }

        *recv_len = tmp_len;
        trace!("< {:?}", slice::from_raw_parts(data, *recv_len as usize));

        if *recv_len >= 2 {
            *sw = *data.offset((*recv_len).wrapping_sub(2) as (isize)) as (i32) << 8
                | *data.offset((*recv_len).wrapping_sub(1) as (isize)) as (i32);
        } else {
            *sw = 0;
        }

        Ok(())
    }

    /// Authenticate to the card
    pub unsafe fn ykpiv_authenticate(
        &mut self,
        key: Option<&[u8; DES_LEN_3DES]>,
    ) -> Result<(), Error> {
        let mut res = Ok(());

        self._ykpiv_begin_transaction()?;

        if self._ykpiv_ensure_application_selected().is_ok() {
            // use the provided mgm key to authenticate; if it hasn't been provided, use default
            let mgm_key = DesKey::from_bytes(*key.unwrap_or(DEFAULT_AUTH_KEY));

            // get a challenge from the card
            let apdu = APDU::new(YKPIV_INS_AUTHENTICATE)
                .params(YKPIV_ALGO_3DES, YKPIV_KEY_CARDMGM)
                .data(&[0x7c, 0x02, 0x80, 0x00])
                .to_bytes();

            let mut data = [0u8; 261];
            let mut recv_len = data.len() as u32;
            let mut sw: i32 = 0;

            res = self._send_data(apdu.as_slice(), data.as_mut_ptr(), &mut recv_len, &mut sw);

            if res.is_err() {
                let _ = self._ykpiv_end_transaction();
                return res;
            } else if sw != SW_SUCCESS {
                let _ = self._ykpiv_end_transaction();
                return Err(Error::AuthenticationError);
            }

            let mut challenge = [0u8; 8];
            challenge.copy_from_slice(&data[4..12]);

            // send a response to the cards challenge and a challenge of our own.
            let mut response = [0u8; 8];
            des_decrypt(&mgm_key, &challenge, &mut response);

            recv_len = data.len() as u32;

            let mut data = [0u8; 22];
            data[0] = 0x7c;
            data[1] = 20; // 2 + 8 + 2 +8
            data[2] = 0x80;
            data[3] = 8;
            data[4..12].copy_from_slice(&response);
            data[12] = 0x81;
            data[13] = 8;

            if getrandom(&mut data[14..22]).is_err() {
                error!("failed getting randomness for authentication.");
                let _ = self._ykpiv_end_transaction();
                return Err(Error::RandomnessError);
            }

            challenge.copy_from_slice(&data[14..22]);

            let apdu = APDU::new(YKPIV_INS_AUTHENTICATE)
                .params(YKPIV_ALGO_3DES, YKPIV_KEY_CARDMGM)
                .data(&data)
                .to_bytes();

            res = self._send_data(apdu.as_slice(), data.as_mut_ptr(), &mut recv_len, &mut sw);

            if res.is_err() {
                let _ = self._ykpiv_end_transaction();
                return res;
            } else if sw != SW_SUCCESS {
                let _ = self._ykpiv_end_transaction();
                return Err(Error::AuthenticationError);
            }

            // compare the response from the card with our challenge
            des_encrypt(&mgm_key, &challenge, &mut response);

            // TODO(tarcieri): constant time comparison!
            if response == data[4..12] {
                res = Ok(());
            } else {
                res = Err(Error::AuthenticationError);
            }
        }

        let _ = self._ykpiv_end_transaction();
        res
    }

    /// Set the management key (MGM)
    pub unsafe fn ykpiv_set_mgmkey(&mut self, new_key: &[u8; DES_LEN_3DES]) -> Result<(), Error> {
        self.ykpiv_set_mgmkey2(new_key, 0)
    }

    /// Set the management key (MGM)
    pub(crate) unsafe fn ykpiv_set_mgmkey2(
        &mut self,
        new_key: &[u8; DES_LEN_3DES],
        touch: u8,
    ) -> Result<(), Error> {
        let mut res = Ok(());

        self._ykpiv_begin_transaction()?;

        if self._ykpiv_ensure_application_selected().is_ok() {
            if yk_des_is_weak_key(new_key) {
                error!(
                    "won't set new key '{:?}' since it's weak (with odd parity)",
                    new_key
                );

                let _ = self._ykpiv_end_transaction();
                return Err(Error::KeyError);
            }

            let p2 = match touch {
                0 => 0xff,
                1 => 0xfe,
                _ => {
                    let _ = self._ykpiv_end_transaction();
                    return Err(Error::GenericError);
                }
            };

            let mut data = [0u8; DES_LEN_3DES + 3];
            data[0] = YKPIV_ALGO_3DES;
            data[1] = YKPIV_KEY_CARDMGM;
            data[2] = DES_LEN_3DES as u8;
            data[3..3 + DES_LEN_3DES].copy_from_slice(new_key);

            let apdu = APDU::new(YKPIV_INS_SET_MGMKEY)
                .params(0xff, p2)
                .data(&data)
                .to_bytes();

            let mut data = [0u8; 261];
            let mut recv_len = data.len() as u32;
            let mut sw: i32 = 0;
            res = self._send_data(apdu.as_slice(), data.as_mut_ptr(), &mut recv_len, &mut sw);

            if res.is_ok() && sw != SW_SUCCESS {
                res = Err(Error::GenericError);
            }
        }

        res
    }

    /// Authenticate to the YubiKey
    pub(crate) unsafe fn _general_authenticate(
        &mut self,
        sign_in: *const u8,
        in_len: usize,
        out: *mut u8,
        out_len: *mut usize,
        algorithm: u8,
        key: u8,
        decipher: bool,
    ) -> Result<(), Error> {
        let mut _currentBlock;
        let mut indata = [0u8; 1024];
        let mut dataptr: *mut u8 = indata.as_mut_ptr();
        let mut data = [0u8; 1024];
        let templ = [0, YKPIV_INS_AUTHENTICATE, algorithm, key];
        let mut recv_len = data.len();
        let mut sw: i32 = 0;
        let bytes: usize;
        let mut len: usize = 0;

        match algorithm {
            YKPIV_ALGO_RSA1024 | YKPIV_ALGO_RSA2048 => {
                let key_len = if algorithm == YKPIV_ALGO_RSA1024 {
                    128
                } else {
                    256
                };

                if in_len != key_len {
                    return Err(Error::SizeError);
                } else {
                    _currentBlock = 16;
                }
            }
            YKPIV_ALGO_ECCP256 | YKPIV_ALGO_ECCP384 => {
                let key_len = if algorithm == YKPIV_ALGO_ECCP256 {
                    32
                } else {
                    48
                };

                if (!decipher && (in_len > key_len)) || (decipher && (in_len != (key_len * 2) + 1))
                {
                    return Err(Error::SizeError);
                }
            }
            _ => return Err(Error::AlgorithmError),
        }

        if in_len < 0x80 {
            bytes = 1;
        } else if in_len < 0xff {
            bytes = 2;
        } else {
            bytes = 3;
        }

        *dataptr = 0x7c;
        dataptr = dataptr.add(_ykpiv_set_length(dataptr, in_len + bytes + 3));
        *dataptr = 0x82;
        *dataptr.add(1) = 0x00;
        *dataptr.add(2) =
            if (algorithm == YKPIV_ALGO_ECCP256 || algorithm == YKPIV_ALGO_ECCP384) && decipher {
                0x85
            } else {
                0x81
            };
        dataptr = dataptr.add(3 + _ykpiv_set_length(dataptr, in_len));
        memcpy(dataptr as *mut c_void, sign_in as *const c_void, in_len);
        dataptr = dataptr.add(in_len);

        if let Err(e) = self.ykpiv_transfer_data(
            templ.as_ptr(),
            indata.as_mut_ptr(),
            dataptr as isize - indata.as_mut_ptr() as isize,
            data.as_mut_ptr(),
            &mut recv_len,
            &mut sw,
        ) {
            error!("sign command failed to communicate");
            return Err(e);
        }

        if sw != SW_SUCCESS {
            error!("Failed sign command with code {:x}", sw);

            if sw == SW_ERR_SECURITY_STATUS {
                return Err(Error::AuthenticationError);
            } else {
                return Err(Error::GenericError);
            }
        }

        // skip the first 7c tag
        if data[0] != 0x7c {
            error!("failed parsing signature reply (0x7c byte)");
            return Err(Error::ParseError);
        }

        dataptr = data.as_mut_ptr().add(1);
        dataptr = dataptr.add(_ykpiv_get_length(dataptr, &mut len));

        // skip the 82 tag
        if *dataptr != 0x82 {
            error!("failed parsing signature reply (0x82 byte)");
            return Err(Error::ParseError);
        }

        dataptr = dataptr.add(1);
        dataptr = dataptr.add(_ykpiv_get_length(dataptr, &mut len));

        if len > *out_len {
            error!("wrong size on output buffer");
            return Err(Error::SizeError);
        }

        *out_len = len;
        memcpy(out as (*mut c_void), dataptr as (*const c_void), len);
        Ok(())
    }

    /// Sign data using a PIV key
    pub unsafe fn ykpiv_sign_data(
        &mut self,
        raw_in: *const u8,
        in_len: usize,
        sign_out: *mut u8,
        out_len: *mut usize,
        algorithm: u8,
        key: u8,
    ) -> Result<(), Error> {
        self._ykpiv_begin_transaction()?;

        // don't attempt to reselect in crypt operations to avoid problems with PIN_ALWAYS

        let res =
            self._general_authenticate(raw_in, in_len, sign_out, out_len, algorithm, key, false);

        let _ = self._ykpiv_end_transaction();
        res
    }

    /// Decrypt data using a PIV key
    pub unsafe fn ykpiv_decrypt_data(
        &mut self,
        input: *const u8,
        input_len: usize,
        out: *mut u8,
        out_len: *mut usize,
        algorithm: u8,
        key: u8,
    ) -> Result<(), Error> {
        self._ykpiv_begin_transaction()?;

        // don't attempt to reselect in crypt operations to avoid problems with PIN_ALWAYS

        let res = self._general_authenticate(input, input_len, out, out_len, algorithm, key, true);
        let _ = self._ykpiv_end_transaction();
        res
    }

    /// Get the version of the PIV application installed on the YubiKey
    pub(crate) unsafe fn _ykpiv_get_version(&mut self) -> Result<Version, Error> {
        let mut data = [0u8; 261];
        let mut recv_len = data.len() as u32;
        let mut sw: i32 = 0;

        // get version from self if already from device
        if self.ver.major != 0 || self.ver.minor != 0 || self.ver.patch != 0 {
            return Ok(self.ver);
        }

        // get version from device
        let apdu = APDU::new(YKPIV_INS_GET_VERSION).to_bytes();

        self._send_data(apdu.as_slice(), data.as_mut_ptr(), &mut recv_len, &mut sw)?;

        if sw != SW_SUCCESS {
            return Err(Error::GenericError);
        }

        if recv_len < 3 {
            return Err(Error::SizeError);
        }

        self.ver.major = data[0];
        self.ver.minor = data[1];
        self.ver.patch = data[2];

        Ok(self.ver)
    }

    /// Get the YubiKey's PIV application version as a string
    pub unsafe fn ykpiv_get_version(&mut self) -> Result<String, Error> {
        let mut res = Err(Error::GenericError);

        self._ykpiv_begin_transaction()?;

        if self._ykpiv_ensure_application_selected().is_ok() {
            res = self._ykpiv_get_version();
        }

        let _ = self._ykpiv_end_transaction();
        res.map(|ver| format!("{}.{}.{}", ver.major, ver.minor, ver.patch))
    }

    /// Get YubiKey device serial number
    ///
    /// NOTE: caller must make sure that this is wrapped in a transaction for synchronized operation
    pub(crate) unsafe fn _ykpiv_get_serial(&mut self, f_force: bool) -> Result<u32, Error> {
        let yk_applet = [0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x01];
        let mut data = [0u8; 255];
        let mut recv_len = data.len() as u32;
        let mut sw: i32 = 0;
        let p_temp: *mut u8;

        if !f_force && self.serial != 0 {
            return Ok(self.serial);
        }

        if self.ver.major < 5 {
            // get serial from neo/yk4 devices using the otp applet
            let mut temp = [0u8; 255];
            recv_len = temp.len() as u32;

            let apdu = APDU::new(YKPIV_INS_SELECT_APPLICATION)
                .p1(0x04)
                .data(&yk_applet)
                .to_bytes();

            if let Err(e) =
                self._send_data(apdu.as_slice(), temp.as_mut_ptr(), &mut recv_len, &mut sw)
            {
                error!("failed communicating with card: '{}'", e);
                return Err(e);
            }

            if sw != SW_SUCCESS {
                error!("failed selecting yk application: {:04x}", sw);
                return Err(Error::GenericError);
            }

            recv_len = temp.len() as u32;
            let apdu = APDU::new(0x01).p1(0x10).to_bytes();

            if let Err(e) =
                self._send_data(apdu.as_slice(), data.as_mut_ptr(), &mut recv_len, &mut sw)
            {
                error!("failed communicating with card: '{}'", e);
                return Err(e);
            }

            if sw != SW_SUCCESS {
                error!("failed retrieving serial number: {:04x}", sw);
                return Err(Error::GenericError);
            }

            recv_len = temp.len() as u32;
            let apdu = APDU::new(YKPIV_INS_SELECT_APPLICATION)
                .p1(0x04)
                .data(&AID)
                .to_bytes();

            if let Err(e) =
                self._send_data(apdu.as_slice(), temp.as_mut_ptr(), &mut recv_len, &mut sw)
            {
                error!("failed communicating with card: '{}'", e);
                return Err(e);
            }

            if sw != SW_SUCCESS {
                error!("failed selecting application: {:04x}", sw);
                return Err(Error::GenericError);
            }
        } else {
            // get serial from yk5 and later devices using the f8 command
            let apdu = APDU::new(YKPIV_INS_GET_SERIAL).to_bytes();

            if let Err(e) =
                self._send_data(apdu.as_slice(), data.as_mut_ptr(), &mut recv_len, &mut sw)
            {
                error!("failed communicating with card: '{}'", e);
                return Err(e);
            }

            if sw != SW_SUCCESS {
                error!("failed retrieving serial number: {:04x}", sw);
                return Err(Error::GenericError);
            }
        }

        // check that we received enough data for the serial number
        if recv_len < 4 {
            return Err(Error::SizeError);
        }

        // TODO(tarcieri): replace pointers and casts with proper references!
        #[allow(trivial_casts)]
        {
            p_temp = &mut self.serial as (*mut u32) as (*mut u8);
        }

        *p_temp = data[3];
        *p_temp.add(1) = data[2];
        *p_temp.add(2) = data[1];
        *p_temp.add(3) = data[0];

        Ok(self.serial)
    }

    /// Get YubiKey device serial number
    pub unsafe fn ykpiv_get_serial(&mut self) -> Result<u32, Error> {
        let mut res = Err(Error::GenericError);

        self._ykpiv_begin_transaction()?;

        if self._ykpiv_ensure_application_selected().is_ok() {
            res = self._ykpiv_get_serial(false);
        }

        let _ = self._ykpiv_end_transaction();
        res
    }

    /// Cache PIN in memory
    // TODO(tarcieri): better security around the cached PIN
    pub(crate) unsafe fn _cache_pin(
        &mut self,
        pin: *const c_char,
        len: usize,
    ) -> Result<(), Error> {
        if !pin.is_null() && (self.pin as *const c_char == pin) {
            return Ok(());
        }

        if !self.pin.is_null() {
            // Zeroize the old cached PIN
            let old_len = strlen(self.pin as *const c_char);
            let pin_slice = slice::from_raw_parts_mut(self.pin, old_len);
            pin_slice.zeroize();

            free(self.pin as (*mut c_void));
            self.pin = ptr::null_mut();
        }

        if !pin.is_null() && len > 0 {
            self.pin = malloc(len + 1) as (*mut u8);

            if self.pin.is_null() {
                return Err(Error::MemoryError);
            }

            memcpy(self.pin as (*mut c_void), pin as (*const c_void), len);
            *self.pin.add(len) = 0u8;
        }

        Ok(())
    }

    /// Verify device PIN
    ///
    /// Returns the number of tries remaining both on success and on a wrong PIN.
    pub unsafe fn ykpiv_verify(&mut self, pin: *const c_char) -> Result<i32, Error> {
        self.ykpiv_verify_select(pin, if !pin.is_null() { strlen(pin) } else { 0 }, false)
    }

    /// Verify device PIN
    ///
    /// Returns the number of tries remaining both on success and on a wrong PIN.
    pub(crate) unsafe fn _verify(
        &mut self,
        pin: *const c_char,
        pin_len: usize,
    ) -> Result<i32, Error> {
        let mut data = [0u8; 261];
        let mut recv_len = data.len() as u32;
        let mut sw: i32 = 0;

        if pin_len > CB_PIN_MAX {
            return Err(Error::SizeError);
        }

        let mut apdu = APDU::new(YKPIV_INS_VERIFY);
        apdu.params(0x00, 0x80);

        if !pin.is_null() {
            let mut data = [0xFF; CB_PIN_MAX];

            memcpy(
                data.as_mut_ptr() as *mut c_void,
                pin as *const c_void,
                pin_len,
            );

            apdu.data(data);
        }

        let res = self._send_data(
            apdu.to_bytes().as_slice(),
            data.as_mut_ptr(),
            &mut recv_len,
            &mut sw,
        );

        if let Err(e) = res {
            return Err(e);
        }

        if sw == SW_SUCCESS {
            if !pin.is_null() && (pin_len != 0) {
                // Intentionally ignore errors.  If the PIN fails to save, it will only
                // be a problem if a reconnect is attempted.  Failure deferred until then.
                let _ = self._cache_pin(pin, pin_len);
            }

            Ok(sw & 0xf)
        } else if sw >> 8 == 0x63 {
            Err(Error::WrongPin { tries: sw & 0xf })
        } else if sw == SW_ERR_AUTH_BLOCKED {
            Err(Error::WrongPin { tries: 0 })
        } else {
            Err(Error::GenericError)
        }
    }

    /// Verify and select application
    ///
    /// Returns the number of tries remaining both on success and on a wrong PIN.
    pub unsafe fn ykpiv_verify_select(
        &mut self,
        pin: *const c_char,
        pin_len: usize,
        force_select: bool,
    ) -> Result<i32, Error> {
        let mut res = Ok(-1);

        self._ykpiv_begin_transaction()?;

        if force_select {
            if let Err(e) = self._ykpiv_ensure_application_selected() {
                res = Err(e);
            }
        }

        if res.is_ok() {
            res = self._verify(pin, pin_len);
        }

        let _ = self._ykpiv_end_transaction();
        res
    }

    /// Get the number of PIN retries
    pub unsafe fn ykpiv_get_pin_retries(&mut self) -> Result<i32, Error> {
        // Force a re-select to unverify, because once verified the spec dictates that
        // subsequent verify calls will return a "verification not needed" instead of
        // the number of tries left...
        self._ykpiv_select_application()?;

        let ykrc = self.ykpiv_verify(ptr::null());

        // WRONG_PIN is expected on successful query.
        match ykrc {
            Ok(tries) | Err(Error::WrongPin { tries }) => Ok(tries),
            Err(e) => Err(e),
        }
    }

    /// Set the number of PIN retries
    pub unsafe fn ykpiv_set_pin_retries(
        &mut self,
        pin_tries: i32,
        puk_tries: i32,
    ) -> Result<(), Error> {
        let mut res = Ok(());
        let mut templ = [0, YKPIV_INS_SET_PIN_RETRIES, 0, 0];
        let mut data = [0u8; 255];
        let mut recv_len: usize = data.len();
        let mut sw: i32 = 0i32;

        // Special case: if either retry count is 0, it's a successful no-op
        if pin_tries == 0 || puk_tries == 0 {
            return Ok(());
        }

        if pin_tries > 0xff || puk_tries > 0xff || pin_tries < 1 || puk_tries < 1 {
            return Err(Error::RangeError);
        }

        templ[2] = pin_tries as (u8);
        templ[3] = puk_tries as (u8);

        self._ykpiv_begin_transaction()?;

        if self._ykpiv_ensure_application_selected().is_ok() {
            res = self.ykpiv_transfer_data(
                templ.as_ptr(),
                ptr::null(),
                0,
                data.as_mut_ptr(),
                &mut recv_len,
                &mut sw,
            );

            if res.is_ok() {
                res = match sw {
                    SW_SUCCESS => Ok(()),
                    SW_ERR_AUTH_BLOCKED => Err(Error::AuthenticationError),
                    SW_ERR_SECURITY_STATUS => Err(Error::AuthenticationError),
                    _ => Err(Error::GenericError),
                };
            }
        }

        let _ = self._ykpiv_end_transaction();
        res
    }

    /// Change the PIN
    pub(crate) unsafe fn _ykpiv_change_pin(
        &mut self,
        action: i32,
        current_pin: *const c_char,
        current_pin_len: usize,
        new_pin: *const c_char,
        new_pin_len: usize,
    ) -> Result<(), Error> {
        let mut sw: i32 = 0;
        let mut templ = [0, YKPIV_INS_CHANGE_REFERENCE, 0, 0x80];
        let mut indata = [0u8; 16];
        let mut data = [0u8; 255];
        let mut recv_len: usize = data.len();

        if current_pin_len > 8 || new_pin_len > 8 {
            return Err(Error::SizeError);
        }

        if action == CHREF_ACT_UNBLOCK_PIN {
            templ[1] = YKPIV_INS_RESET_RETRY;
        } else if action == CHREF_ACT_CHANGE_PUK {
            templ[3] = 0x81;
        }

        memcpy(
            indata.as_mut_ptr() as (*mut c_void),
            current_pin as (*const c_void),
            current_pin_len,
        );

        if current_pin_len < 8 {
            memset(
                indata.as_mut_ptr().add(current_pin_len) as *mut c_void,
                0xff,
                8 - current_pin_len,
            );
        }

        memcpy(
            indata.as_mut_ptr().offset(8) as *mut c_void,
            new_pin as *const c_void,
            new_pin_len,
        );

        if new_pin_len < 8 {
            memset(
                indata.as_mut_ptr().offset(8).add(new_pin_len) as *mut c_void,
                0xff,
                8 - new_pin_len,
            );
        }

        let res = self.ykpiv_transfer_data(
            templ.as_ptr(),
            indata.as_mut_ptr(),
            indata.len() as isize,
            data.as_mut_ptr(),
            &mut recv_len,
            &mut sw,
        );

        indata.zeroize();

        if res.is_err() {
            return res;
        }

        if sw != SW_SUCCESS {
            if sw >> 8 == 0x63 {
                return Err(Error::WrongPin { tries: sw & 0xf });
            }

            if sw == SW_ERR_AUTH_BLOCKED {
                return Err(Error::PinLocked);
            }

            error!("failed changing pin, token response code: {:x}.", sw);
            return Err(Error::GenericError);
        }

        Ok(())
    }

    /// Change the Personal Identification Number (PIN).
    ///
    /// The default PIN code is 123456
    pub unsafe fn ykpiv_change_pin(
        &mut self,
        current_pin: *const c_char,
        current_pin_len: usize,
        new_pin: *const c_char,
        new_pin_len: usize,
    ) -> Result<(), Error> {
        let mut res = Err(Error::GenericError);

        self._ykpiv_begin_transaction()?;

        if self._ykpiv_ensure_application_selected().is_ok() {
            res = self._ykpiv_change_pin(0, current_pin, current_pin_len, new_pin, new_pin_len);

            if res.is_ok() && !new_pin.is_null() {
                // Intentionally ignore errors.  If the PIN fails to save, it will only
                // be a problem if a reconnect is attempted.  Failure deferred until then.
                let _ = self._cache_pin(new_pin, new_pin_len);
            }
        }

        let _ = self._ykpiv_end_transaction();
        res
    }

    /// Change the PIN Unblocking Key (PUK). PUKs are codes for resetting
    /// lost/forgotten PINs, or devices that have become blocked because of too
    /// many failed attempts.
    ///
    /// The PUK is part of the PIV standard that the YubiKey follows.
    ///
    /// The default PUK code is 12345678.
    pub unsafe fn ykpiv_change_puk(
        &mut self,
        current_puk: *const c_char,
        current_puk_len: usize,
        new_puk: *const c_char,
        new_puk_len: usize,
    ) -> Result<(), Error> {
        let mut res = Err(Error::GenericError);

        self._ykpiv_begin_transaction()?;

        if self._ykpiv_ensure_application_selected().is_ok() {
            res = self._ykpiv_change_pin(2, current_puk, current_puk_len, new_puk, new_puk_len);
        }

        let _ = self._ykpiv_end_transaction();
        res
    }

    /// Unblock a Personal Identification Number (PIN) using a previously
    /// configured PIN Unblocking Key (PUK).
    pub unsafe fn ykpiv_unblock_pin(
        &mut self,
        puk: *const c_char,
        puk_len: usize,
        new_pin: *const c_char,
        new_pin_len: usize,
    ) -> Result<(), Error> {
        let mut res = Err(Error::GenericError);

        self._ykpiv_begin_transaction()?;

        if self._ykpiv_ensure_application_selected().is_ok() {
            res = self._ykpiv_change_pin(1, puk, puk_len, new_pin, new_pin_len);
        }

        let _ = self._ykpiv_end_transaction();
        res
    }

    /// Fetch an object from the YubiKey
    pub unsafe fn ykpiv_fetch_object(
        &mut self,
        object_id: i32,
        data: *mut u8,
        len: *mut usize,
    ) -> Result<(), Error> {
        let mut res = Ok(());

        self._ykpiv_begin_transaction()?;

        if self._ykpiv_ensure_application_selected().is_ok() {
            res = self._ykpiv_fetch_object(object_id, data, len);
        }

        let _ = self._ykpiv_end_transaction();
        res
    }

    /// Fetch an object
    pub(crate) unsafe fn _ykpiv_fetch_object(
        &mut self,
        object_id: i32,
        data: *mut u8,
        len: *mut usize,
    ) -> Result<(), Error> {
        let mut sw: i32 = 0;
        let mut indata = [0u8; 5];
        let mut inptr: *mut u8 = indata.as_mut_ptr();
        let templ = [0, YKPIV_INS_GET_DATA, 0x3f, 0xff];

        inptr = set_object(object_id, inptr);

        if inptr.is_null() {
            return Err(Error::InvalidObject);
        }

        self.ykpiv_transfer_data(
            templ.as_ptr(),
            indata.as_mut_ptr(),
            inptr as isize - indata.as_mut_ptr() as isize,
            data,
            len,
            &mut sw,
        )?;

        if sw != SW_SUCCESS {
            return Err(Error::GenericError);
        }

        let mut outlen: usize = 0;

        if *len < 2 || !_ykpiv_has_valid_length(data.offset(1), (*len).wrapping_sub(1)) {
            return Err(Error::SizeError);
        }

        let offs = _ykpiv_get_length(data.offset(1), &mut outlen);

        if offs == 0 {
            return Err(Error::SizeError);
        }

        if outlen.wrapping_add(offs).wrapping_add(1) != *len {
            error!(
                "invalid length indicated in object: total len is {} but indicated length is {}",
                *len, outlen
            );

            return Err(Error::SizeError);
        }

        memmove(
            data as *mut c_void,
            data.add(1).add(offs) as *const c_void,
            outlen,
        );
        *len = outlen;

        Ok(())
    }

    /// Save an object
    pub unsafe fn ykpiv_save_object(
        &mut self,
        object_id: i32,
        indata: *mut u8,
        len: usize,
    ) -> Result<(), Error> {
        let mut res = Ok(());

        self._ykpiv_begin_transaction()?;

        if self._ykpiv_ensure_application_selected().is_ok() {
            res = self._ykpiv_save_object(object_id, indata, len);
        }

        let _ = self._ykpiv_end_transaction();
        res
    }

    /// Save an object
    pub unsafe fn _ykpiv_save_object(
        &mut self,
        object_id: i32,
        indata: *mut u8,
        len: usize,
    ) -> Result<(), Error> {
        let mut data = [0u8; YKPIV_OBJ_MAX_SIZE];
        let mut dataptr: *mut u8 = data.as_mut_ptr();
        let templ = [0, YKPIV_INS_PUT_DATA, 0x3f, 0xff];
        let mut sw: i32 = 0;
        let mut outlen: usize = 0usize;

        if len > CB_OBJ_MAX {
            return Err(Error::SizeError);
        }

        dataptr = set_object(object_id, dataptr);

        if dataptr.is_null() {
            return Err(Error::InvalidObject);
        }
        *{
            let _old = dataptr;
            dataptr = dataptr.offset(1);
            _old
        } = 0x53;

        dataptr = dataptr.add(_ykpiv_set_length(dataptr, len));
        memcpy(dataptr as (*mut c_void), indata as (*const c_void), len);
        dataptr = dataptr.add(len);

        self._ykpiv_transfer_data(
            templ.as_ptr(),
            data.as_mut_ptr(),
            dataptr as isize - data.as_mut_ptr() as isize,
            ptr::null_mut(),
            &mut outlen,
            &mut sw,
        )?;

        match sw {
            SW_SUCCESS => Ok(()),
            SW_ERR_SECURITY_STATUS => Err(Error::AuthenticationError),
            _ => Err(Error::GenericError),
        }
    }

    /// Import a private encryption or signing key into the YubiKey
    pub unsafe fn ykpiv_import_private_key(
        &mut self,
        key: u8,
        algorithm: u8,
        p: *const u8,
        p_len: usize,
        q: *const u8,
        q_len: usize,
        dp: *const u8,
        dp_len: usize,
        dq: *const u8,
        dq_len: usize,
        qinv: *const u8,
        qinv_len: usize,
        ec_data: *const u8,
        ec_data_len: u8,
        pin_policy: u8,
        touch_policy: u8,
    ) -> Result<(), Error> {
        let mut key_data = [0u8; 1024];
        let mut in_ptr: *mut u8 = key_data.as_mut_ptr();
        let templ = [0, YKPIV_INS_IMPORT_KEY, algorithm, key];
        let mut data = [0u8; 256];
        let mut recv_len = data.len();
        let mut elem_len: u32 = 0;
        let mut sw: i32 = 0;
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
                if ec_data_len as (usize) >= key_data.len() {
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
                lens[0] = ec_data_len as usize;
                param_tag = 0x6;
                n_params = 1;
            }
            _ => return Err(Error::AlgorithmError),
        }

        for i in 0..n_params {
            *in_ptr = (param_tag + i as i32) as u8;
            in_ptr = in_ptr.offset(1);

            in_ptr = in_ptr.add(_ykpiv_set_length(in_ptr, elem_len as usize));
            let padding = (elem_len as (usize)).wrapping_sub(lens[i as usize]);
            let remaining = (key_data.as_mut_ptr() as usize) + 1024 - in_ptr as usize;

            if padding > remaining {
                return Err(Error::AlgorithmError);
            }

            memset(in_ptr as *mut c_void, 0, padding);
            in_ptr = in_ptr.add(padding);
            memcpy(
                in_ptr as *mut c_void,
                params[i as usize] as *const c_void,
                lens[i as usize],
            );
            in_ptr = in_ptr.add(lens[i as usize]);
        }

        if pin_policy != YKPIV_PINPOLICY_DEFAULT {
            *in_ptr = YKPIV_PINPOLICY_TAG;
            *in_ptr.add(1) = 0x01;
            *in_ptr.add(2) = pin_policy;
            in_ptr = in_ptr.add(3);
        }

        if touch_policy != YKPIV_TOUCHPOLICY_DEFAULT {
            *in_ptr = YKPIV_TOUCHPOLICY_TAG;
            *in_ptr.add(1) = 0x01;
            *in_ptr.add(2) = touch_policy;
            in_ptr = in_ptr.add(3);
        }

        self._ykpiv_begin_transaction()?;

        let mut res = Ok(());
        if self._ykpiv_ensure_application_selected().is_ok() {
            res = self.ykpiv_transfer_data(
                templ.as_ptr(),
                key_data.as_mut_ptr(),
                in_ptr as isize - key_data.as_mut_ptr() as isize,
                data.as_mut_ptr(),
                &mut recv_len,
                &mut sw,
            );

            if res.is_ok() && sw != SW_SUCCESS {
                res = Err(Error::GenericError);
                if sw == SW_ERR_SECURITY_STATUS {
                    res = Err(Error::AuthenticationError);
                }
            }
        }

        key_data.zeroize();
        let _ = self._ykpiv_end_transaction();
        res
    }

    /// Generate an attestation certificate for a stored key
    pub unsafe fn ykpiv_attest(
        &mut self,
        key: u8,
        data: *mut u8,
        data_len: *mut usize,
    ) -> Result<(), Error> {
        let mut res = Err(Error::GenericError);
        let templ = [0, YKPIV_INS_ATTEST, key, 0];
        let mut sw: i32 = 0;
        let mut ul_data_len: usize;

        if data.is_null() || data_len.is_null() {
            return Err(Error::ArgumentError);
        }

        ul_data_len = *data_len;

        self._ykpiv_begin_transaction()?;

        if self._ykpiv_ensure_application_selected().is_ok() {
            res = self.ykpiv_transfer_data(
                templ.as_ptr(),
                ptr::null(),
                0,
                data,
                &mut ul_data_len,
                &mut sw,
            );

            if res.is_ok() {
                if sw != SW_SUCCESS {
                    res = Err(Error::GenericError);
                    if sw == SW_ERR_NOT_SUPPORTED {
                        res = Err(Error::NotSupported);
                    }
                } else if *data as i32 != 0x30 {
                    res = Err(Error::GenericError);
                } else {
                    *data_len = ul_data_len;
                }
            }
        }

        let _ = self._ykpiv_end_transaction();
        res
    }

    /// Get an auth challenge
    pub unsafe fn ykpiv_auth_getchallenge(&mut self) -> Result<[u8; 8], Error> {
        let mut data = [0u8; 261];
        let mut recv_len = data.len() as u32;
        let mut sw: i32 = 0;
        // TODO(str4d): What should the default value be if the application is not selected?
        let mut res = Ok([0; 8]);

        self._ykpiv_begin_transaction()?;

        if self._ykpiv_ensure_application_selected().is_ok() {
            let apdu = APDU::new(YKPIV_INS_AUTHENTICATE)
                .params(YKPIV_ALGO_3DES, YKPIV_KEY_CARDMGM)
                .data(&[0x7c, 0x02, 0x81, 0x00])
                .to_bytes();

            if let Err(e) =
                self._send_data(apdu.as_slice(), data.as_mut_ptr(), &mut recv_len, &mut sw)
            {
                res = Err(e)
            } else if sw != SW_SUCCESS {
                res = Err(Error::AuthenticationError);
            } else {
                let mut challenge = [0; 8];
                challenge.copy_from_slice(&data[4..12]);
                res = Ok(challenge);
            }
        }

        let _ = self._ykpiv_end_transaction();
        res
    }

    /// Verify an auth response
    pub unsafe fn ykpiv_auth_verifyresponse(&mut self, response: [u8; 8]) -> Result<(), Error> {
        self._ykpiv_begin_transaction()?;

        let mut data = [
            0x7c, 0x0a, 0x82, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        data[4..12].copy_from_slice(&response);

        // send the response to the card and a challenge of our own.
        let apdu = APDU::new(YKPIV_INS_AUTHENTICATE)
            .params(YKPIV_ALGO_3DES, YKPIV_KEY_CARDMGM)
            .data(&data)
            .to_bytes();

        let mut data = [0u8; 261];
        let mut recv_len = data.len() as u32;
        let mut sw: i32 = 0;
        let mut res = self._send_data(apdu.as_slice(), data.as_mut_ptr(), &mut recv_len, &mut sw);

        if res.is_ok() && sw != SW_SUCCESS {
            res = Err(Error::AuthenticationError);
        }

        let _ = self._ykpiv_end_transaction();
        res
    }

    /// Deauthenticate
    pub unsafe fn ykpiv_auth_deauthenticate(&mut self) -> Result<(), Error> {
        let mut data = [0u8; 255];
        let mut recv_len = data.len() as u32;
        let mut sw: i32 = 0;

        self._ykpiv_begin_transaction()?;

        let apdu = APDU::new(YKPIV_INS_SELECT_APPLICATION)
            .p1(0x04)
            .data(MGMT_AID)
            .to_bytes();

        let mut res = self._send_data(apdu.as_slice(), data.as_mut_ptr(), &mut recv_len, &mut sw);

        if let Err(e) = &res {
            error!("failed communicating with card: \'{}\'", e);
        }

        if sw != SW_SUCCESS {
            error!("Failed selecting mgmt application: {:04x}", sw);
            res = Err(Error::GenericError);
        }

        let _ = self._ykpiv_end_transaction();
        res
    }
}

/// Set length
pub(crate) unsafe fn _ykpiv_set_length(buffer: *mut u8, length: usize) -> usize {
    if length < 0x80 {
        *buffer = length as u8;
        1
    } else if length < 0x100 {
        *buffer = 0x81;
        *buffer.add(1) = length as u8;
        2
    } else {
        *buffer = 0x82;
        *buffer.add(1) = ((length >> 8) & 0xff) as u8;
        *buffer.add(2) = (length & 0xff) as u8;
        3
    }
}

/// Get length
pub(crate) unsafe fn _ykpiv_get_length(buffer: *const u8, len: *mut usize) -> usize {
    if *buffer < 0x81 {
        *len = *buffer as usize;
        1
    } else if (*buffer & 0x7f) == 1 {
        *len = *buffer.add(1) as usize;
        2
    } else if (*buffer & 0x7f) == 2 {
        let tmp = *buffer.add(1) as usize;
        *len = (tmp << 8) + *buffer.add(2) as usize;
        3
    } else {
        0
    }
}

/// Is length valid?
pub(crate) unsafe fn _ykpiv_has_valid_length(buffer: *const u8, len: usize) -> bool {
    ((*buffer as i32) < 0x81 && (len > 0))
        || ((*buffer as i32 & 0x7f == 1) && (len > 1))
        || ((*buffer as i32 & 0x7f == 2) && (len > 2))
}

/// Set an object
pub(crate) unsafe fn set_object(object_id: i32, mut buffer: *mut u8) -> *mut u8 {
    *buffer = 0x5c;

    if object_id == YKPIV_OBJ_DISCOVERY as i32 {
        *buffer.add(1) = 1;
        *buffer.add(2) = YKPIV_OBJ_DISCOVERY as u8;
        buffer = buffer.add(3);
    } else if object_id > 0xffff && object_id <= 0x00ff_ffff {
        *buffer.add(1) = 3;
        *buffer.add(2) = ((object_id >> 16) & 0xff) as u8;
        *buffer.add(3) = ((object_id >> 8) & 0xff) as u8;
        *buffer.add(4) = (object_id & 0xff) as u8;
        buffer = buffer.add(5);
    }

    buffer
}
