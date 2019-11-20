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
    error::ErrorKind,
    internal::{
        des_decrypt, des_destroy_key, des_encrypt, des_import_key, yk_des_is_weak_key,
        DesErrorKind, DesKey, PRngErrorKind, _ykpiv_prng_generate,
    },
};
use libc::{c_char, free, malloc, memcmp, memcpy, memmove, memset, strlen, strncasecmp};
use std::{convert::TryInto, ffi::CStr, mem, os::raw::c_void, ptr, slice};
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
        pbSendBuffer: *mut c_char,
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

/// Application ID(?)
pub const AID: [u8; 5] = [0xa0, 0x00, 0x00, 0x03, 0x08];

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
    pub(crate) verbose: i32,
    pub(crate) pin: *mut u8,
    pub(crate) is_neo: bool,
    pub(crate) ver: Version,
    pub(crate) serial: u32,
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

/// Initialize YubiKey client instance
pub fn ykpiv_init(verbose: i32) -> YubiKey {
    YubiKey {
        context: -1,
        card: 0,
        verbose,
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
pub(crate) unsafe fn _ykpiv_done(state: &mut YubiKey, disconnect: bool) -> Result<(), ErrorKind> {
    if disconnect {
        ykpiv_disconnect(state);
    }

    _cache_pin(state, ptr::null(), 0);
    Ok(())
}

/// Cleanup YubiKey session with external card upon completion
// TODO(tarcieri): make this a `Drop` handler
pub unsafe fn ykpiv_done_with_external_card(state: &mut YubiKey) -> Result<(), ErrorKind> {
    _ykpiv_done(state, false)
}

/// Cleanup YubiKey session upon completion
pub unsafe fn ykpiv_done(state: &mut YubiKey) -> Result<(), ErrorKind> {
    _ykpiv_done(state, true)
}

/// Disconnect a YubiKey session
pub unsafe fn ykpiv_disconnect(state: &mut YubiKey) -> Result<(), ErrorKind> {
    if state.card != 0 {
        SCardDisconnect(state.card, 0x1);
        state.card = 0i32;
    }

    if SCardIsValidContext(state.context) == 0x0 {
        SCardReleaseContext(state.context);
        state.context = -1i32;
    }

    Ok(())
}

/// Select application
pub(crate) unsafe fn _ykpiv_select_application(state: &mut YubiKey) -> Result<(), ErrorKind> {
    let mut data = [0u8; 255];
    let mut recv_len = data.len() as u32;
    let mut sw = 0i32;

    let mut apdu = APDU::default();
    apdu.ins = YKPIV_INS_SELECT_APPLICATION;
    apdu.p1 = 0x04;
    apdu.lc = AID.len() as u8;

    memcpy(
        apdu.data.as_mut_ptr() as *mut c_void,
        AID.as_ptr() as *const c_void,
        AID.len(),
    );

    let mut res = _send_data(state, &mut apdu, data.as_mut_ptr(), &mut recv_len, &mut sw);

    if let Err(e) = res.as_ref() {
        if state.verbose != 0 {
            eprintln!("Failed communicating with card: \'{}\'", e);
        }
    } else if sw != SW_SUCCESS {
        if state.verbose != 0 {
            eprintln!("Failed selecting application: {:04x}", sw);
        }
        return Err(ErrorKind::GenericError);
    }

    // now that the PIV application is selected, retrieve the version
    // and serial number.  Previously the NEO/YK4 required switching
    // to the yk applet to retrieve the serial, YK5 implements this
    // as a PIV applet command.  Unfortunately, this change requires
    // that we retrieve the version number first, so that get_serial
    // can determine how to get the serial number, which for the NEO/Yk4
    // will result in another selection of the PIV applet.

    res = _ykpiv_get_version(state, ptr::null_mut());
    if let Err(e) = res.as_ref() {
        if state.verbose != 0 {
            eprintln!("Failed to retrieve version: \'{}\'", e);
        }
    }

    if let Err(e) = _ykpiv_get_serial(state, false) {
        if state.verbose != 0 {
            eprintln!("Failed to retrieve serial number: \'{}\'", e);
        }

        res = Ok(());
    }

    res
}

/// Ensure an application is selected (presently noop)
pub(crate) unsafe fn _ykpiv_ensure_application_selected(
    _state: &mut YubiKey,
) -> Result<(), ErrorKind> {
    // TODO(tarcieri): ENABLE_APPLICATION_RESELECTION support?
    //
    // Original C code below:
    //
    //    #if ENABLE_APPLICATION_RESELECTION
    //      if (NULL == state) {
    //        return YKPIV_GENERIC_ERROR;
    //      }
    //
    //      res = ykpiv_verify(state, NULL, 0);
    //
    //      if ((YKPIV_OK != res) && (YKPIV_WRONG_PIN != res)) {
    //        res = _ykpiv_select_application(state);
    //      }
    //      else {
    //        res = YKPIV_OK;
    //      }
    //
    //      return res;
    //    #else
    //      (void)state;
    //      return res;
    //    #endif

    Ok(())
}

/// Connect to the YubiKey
pub(crate) unsafe fn _ykpiv_connect(
    state: &mut YubiKey,
    context: usize,
    card: usize,
) -> Result<(), ErrorKind> {
    // if the context has changed, and the new context is not valid, return an error
    if context != state.context as (usize) && (0x0i32 != SCardIsValidContext(context as (i32))) {
        return Err(ErrorKind::PcscError);
    }

    // if card handle has changed, determine if handle is valid (less efficient, but complete)
    if card != state.card as usize {
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
            return Err(ErrorKind::PcscError);
        }

        state.is_neo = (atr_len as usize == YKPIV_ATR_NEO_R3.len() - 1)
            && (memcmp(
                YKPIV_ATR_NEO_R3.as_ptr() as *const c_void,
                atr.as_mut_ptr() as *const c_void,
                atr_len as usize,
            ) == 0);
    }

    state.context = context as i32;
    state.card = card as i32;

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
    state: &mut YubiKey,
    context: usize,
    card: usize,
) -> Result<(), ErrorKind> {
    _ykpiv_connect(state, context, card)
}

/// Connect to a YubiKey
pub unsafe fn ykpiv_connect(state: &mut YubiKey, wanted: *const c_char) -> Result<(), ErrorKind> {
    let mut _currentBlock;
    let mut active_protocol: u32 = 0;
    let mut reader_buf: [c_char; 2048] = [0; 2048];
    let mut num_readers = reader_buf.len();
    let mut rc: isize;
    let mut reader_ptr: *mut c_char;
    let mut card: i32 = -1i32;

    ykpiv_list_readers(state, reader_buf.as_mut_ptr(), &mut num_readers)?;

    reader_ptr = reader_buf.as_mut_ptr();
    loop {
        if *reader_ptr == b'\0' as c_char {
            _currentBlock = 3;
            break;
        }
        if !wanted.is_null() {
            let mut ptr = reader_ptr;
            let mut found: bool = false;
            loop {
                if strlen(ptr) < strlen(wanted) {
                    _currentBlock = 14;
                    break;
                }
                if strncasecmp(ptr, wanted, strlen(wanted)) == 0i32 {
                    _currentBlock = 13;
                    break;
                }
                if *{
                    let _old = ptr;
                    ptr = ptr.offset(1);
                    _old
                } == 0
                {
                    _currentBlock = 14;
                    break;
                }
            }
            if _currentBlock == 13 {
                found = true;
            }
            if found as (i32) == 0i32 {
                if state.verbose != 0 {
                    eprintln!(
                        "skipping reader \'{}\' since it doesn\'t match \'{}\'.",
                        CStr::from_ptr(reader_ptr).to_string_lossy(),
                        CStr::from_ptr(wanted).to_string_lossy()
                    );
                    _currentBlock = 26;
                } else {
                    _currentBlock = 26;
                }
            } else {
                _currentBlock = 15;
            }
        } else {
            _currentBlock = 15;
        }
        if _currentBlock == 15 {
            if state.verbose != 0 {
                eprintln!(
                    "trying to connect to reader \'{}\'.",
                    CStr::from_ptr(reader_ptr).to_string_lossy()
                );
            }
            rc = SCardConnect(
                state.context,
                reader_ptr,
                0x2u32,
                0x2u32,
                &mut card,
                &mut active_protocol,
            ) as (isize);
            if rc != 0x0 {
                if state.verbose != 0 {
                    eprintln!("SCardConnect failed, rc={}", rc);
                }
            } else {
                // at this point, card should not equal state->card,
                // to allow _ykpiv_connect() to determine device type
                let res = _ykpiv_connect(state, state.context as (usize), card as (usize));
                if res.is_err() {
                    _currentBlock = 19;
                    break;
                }
            }
        }

        reader_ptr = reader_ptr.add(strlen(reader_ptr) + 1);
    }

    if _currentBlock == 3 {
        if *reader_ptr == b'\0' as c_char {
            if state.verbose != 0 {
                eprintln!("error: no usable reader found.");
            }

            SCardReleaseContext(state.context);
            state.context = -1;
            return Err(ErrorKind::PcscError);
        } else {
            return Err(ErrorKind::GenericError);
        }
    }

    // Select applet.  This is done here instead of in _ykpiv_connect() because
    // you may not want to select the applet when connecting to a card handle that
    // was supplied by an external library.
    _ykpiv_begin_transaction(state)?;

    let res = _ykpiv_select_application(state);
    _ykpiv_end_transaction(state);
    res
}

/// List readers
pub unsafe fn ykpiv_list_readers(
    state: &mut YubiKey,
    readers: *mut c_char,
    len: *mut usize,
) -> Result<(), ErrorKind> {
    let mut num_readers: u32 = 0u32;
    let mut rc: i32;

    if SCardIsValidContext(state.context) != 0 {
        rc = SCardEstablishContext(0x2, ptr::null(), ptr::null(), &mut state.context);

        if rc != 0 {
            if state.verbose != 0 {
                eprintln!("error: SCardEstablishContext failed, rc={}", rc);
            }
            return Err(ErrorKind::PcscError);
        }
    }

    rc = SCardListReaders(
        state.context,
        ptr::null(),
        ptr::null_mut(),
        &mut num_readers,
    );

    if rc != 0 {
        if state.verbose != 0 {
            eprintln!("error: SCardListReaders failed, rc={}", rc);
        }
        SCardReleaseContext(state.context);
        state.context = -1i32;
        return Err(ErrorKind::PcscError);
    }

    if num_readers as (usize) > *len {
        num_readers = *len as (u32);
    } else if num_readers as (usize) < *len {
        *len = num_readers as (usize);
    }

    rc = SCardListReaders(state.context, ptr::null(), readers, &mut num_readers);

    if rc != 0 {
        if state.verbose != 0 {
            eprintln!("error: SCardListReaders failed, rc={}", rc);
        }

        SCardReleaseContext(state.context);
        state.context = -1i32;
        return Err(ErrorKind::PcscError);
    }

    *len = num_readers as usize;
    Ok(())
}

/// Reconnect to a YubiKey
pub(crate) unsafe fn reconnect(state: &mut YubiKey) -> Result<(), ErrorKind> {
    let mut active_protocol: u32 = 0;
    let mut tries: i32 = 0;

    if state.verbose != 0 {
        eprintln!("trying to reconnect to current reader.");
    }

    let rc = SCardReconnect(state.card, 0x2u32, 0x2u32, 0x1u32, &mut active_protocol);

    if rc != 0x0 {
        if state.verbose != 0 {
            eprintln!("SCardReconnect failed, rc={}", rc);
        }
        return Err(ErrorKind::PcscError);
    }

    _ykpiv_select_application(state)?;

    if !state.pin.is_null() {
        ykpiv_verify(state, state.pin as *const c_char, &mut tries)
    } else {
        Ok(())
    }
}

/// Begin a transaction
pub(crate) unsafe fn _ykpiv_begin_transaction(state: &mut YubiKey) -> Result<(), ErrorKind> {
    let mut rc = SCardBeginTransaction(state.card);

    if rc as usize & 0xffff_ffff == 0x8010_0068 {
        reconnect(state)?;

        rc = SCardBeginTransaction(state.card);
    }

    if rc != 0 {
        if state.verbose != 0 {
            eprintln!("error: Failed to begin pcsc transaction, rc={}", rc);
        }

        return Err(ErrorKind::PcscError);
    }

    Ok(())
}

/// End a transaction
pub(crate) unsafe fn _ykpiv_end_transaction(state: &mut YubiKey) -> Result<(), ErrorKind> {
    let rc = SCardEndTransaction(state.card, 0x0);

    if rc != 0x0 && state.verbose != 0 {
        eprintln!("error: Failed to end pcsc transaction, rc={}", rc);
        return Err(ErrorKind::PcscError);
    }

    Ok(())
}

/// Transfer data
pub(crate) unsafe fn _ykpiv_transfer_data(
    state: &mut YubiKey,
    templ: *const u8,
    in_data: *const u8,
    in_len: isize,
    mut out_data: *mut u8,
    out_len: *mut usize,
    sw: *mut i32,
) -> Result<(), ErrorKind> {
    let mut _currentBlock;
    let mut in_ptr: *const u8 = in_data;
    let max_out = *out_len;
    let mut res: Result<(), ErrorKind>;
    let mut recv_len: u32;

    *out_len = 0;

    loop {
        let mut this_size: usize = 0xff;
        let mut data = [0u8; 261];
        recv_len = data.len() as u32;

        let mut apdu = APDU::default();
        apdu.cla = *templ;
        apdu.ins = *templ.offset(1);
        apdu.p1 = *templ.offset(2);
        apdu.p2 = *templ.offset(3);

        if in_ptr.offset(0xff) < in_data.offset(in_len) {
            apdu.cla = 0x10;
        } else {
            this_size = in_data.offset(in_len) as usize - in_ptr as usize;
        }

        if state.verbose > 2 {
            eprintln!("Going to send {} bytes in this go.", this_size);
        }

        apdu.lc = this_size.try_into().unwrap();
        memcpy(
            apdu.data.as_mut_ptr() as *mut c_void,
            in_ptr as *const c_void,
            this_size,
        );

        res = _send_data(state, &mut apdu, data.as_mut_ptr(), &mut recv_len, sw);

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

            if state.verbose > 2 {
                eprintln!(
                    "The card indicates there is {} bytes more data for us.",
                    *sw & 0xff
                );
            }

            let mut apdu = APDU::default();
            apdu.ins = YKPIV_INS_GET_RESPONSE_APDU;
            res = _send_data(state, &mut apdu, data.as_mut_ptr(), &mut recv_len, sw);

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
            if state.verbose != 0 {
                eprintln!(
                    "Output buffer to small, wanted to write {}, max was {}.",
                    (*out_len).wrapping_add(recv_len as usize).wrapping_sub(2),
                    max_out
                );
            }
            res = Err(ErrorKind::SizeError);
        }
    } else if _currentBlock == 21 {
        if state.verbose != 0 {
            eprintln!(
                "Output buffer to small, wanted to write {}, max was {}.",
                (*out_len).wrapping_add(recv_len as usize).wrapping_sub(2),
                max_out
            );
        }
        res = Err(ErrorKind::SizeError);
    }
    res
}

/// Transfer data
pub unsafe fn ykpiv_transfer_data(
    state: &mut YubiKey,
    templ: *const u8,
    in_data: *const u8,
    in_len: isize,
    out_data: *mut u8,
    out_len: *mut usize,
    sw: *mut i32,
) -> Result<(), ErrorKind> {
    if let Err(e) = _ykpiv_begin_transaction(state) {
        *out_len = 0;
        return Err(e);
    }

    let res = _ykpiv_transfer_data(state, templ, in_data, in_len, out_data, out_len, sw);
    _ykpiv_end_transaction(state);
    res
}

/// Dump hex
pub(crate) unsafe fn dump_hex(buf: *const u8, len: u32) {
    let mut i: u32 = 0;

    while i < len {
        eprintln!("{:02x} ", *buf.offset(i as isize));
        i += 1;
    }
}

/// Send data
pub(crate) unsafe fn _send_data(
    state: &mut YubiKey,
    apdu: &mut APDU,
    data: *mut u8,
    recv_len: *mut u32,
    sw: *mut i32,
) -> Result<(), ErrorKind> {
    let send_len = apdu.lc as u32 + 5;
    let mut tmp_len = *recv_len;

    if state.verbose > 1 {
        eprint!("> ");
        dump_hex(apdu.as_ptr() as *const u8, send_len);
        eprintln!();
    }

    let rc = SCardTransmit(
        state.card,
        SCARD_PCI_T1,
        apdu.as_mut_ptr() as *mut i8,
        send_len,
        ptr::null(),
        data,
        &mut tmp_len,
    );

    if rc != SCARD_S_SUCCESS {
        if state.verbose != 0 {
            eprintln!("error: SCardTransmit failed, rc={:08x}", rc);
        }

        return Err(ErrorKind::PcscError);
    }

    *recv_len = tmp_len;

    if state.verbose > 1 {
        eprint!("< ");
        dump_hex(data, *recv_len);
        eprintln!();
    }

    if *recv_len >= 2 {
        *sw = *data.offset((*recv_len).wrapping_sub(2) as (isize)) as (i32) << 8
            | *data.offset((*recv_len).wrapping_sub(1) as (isize)) as (i32);
    } else {
        *sw = 0;
    }

    Ok(())
}

/// Default authentication key
pub const DEFAULT_AUTH_KEY: &[u8] = b"\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08\0";

/// Authenticate to the card
pub unsafe fn ykpiv_authenticate(state: &mut YubiKey, mut key: *const u8) -> Result<(), ErrorKind> {
    let mut data = [0u8; 261];
    let mut challenge = [0u8; 8];
    let mut recv_len = data.len() as u32;
    let mut sw: i32 = 0;
    let mut drc: DesErrorKind;
    let mut mgm_key: *mut DesKey = ptr::null_mut();
    let mut out_len: usize;
    let mut res = Ok(());

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_ok() {
        if key.is_null() {
            key = DEFAULT_AUTH_KEY.as_ptr();
        }

        // set up our key
        drc = des_import_key(1i32, key, (8i32 * 3i32) as (usize), &mut mgm_key);

        if drc != DesErrorKind::Ok {
            assert!(
                mgm_key.is_null(),
                "didn't expect mgm key to be set by failing op!"
            );
            _ykpiv_end_transaction(state);
            return Err(ErrorKind::AlgorithmError);
        }

        // get a challenge from the card
        let mut apdu = APDU::default();
        apdu.ins = YKPIV_INS_AUTHENTICATE;
        apdu.p1 = YKPIV_ALGO_3DES; // triple des
        apdu.p2 = YKPIV_KEY_CARDMGM; // management key
        apdu.lc = 0x04;
        apdu.data[0] = 0x7c;
        apdu.data[1] = 0x02;
        apdu.data[2] = 0x80;

        res = _send_data(state, &mut apdu, data.as_mut_ptr(), &mut recv_len, &mut sw);

        if res.is_err() {
            _ykpiv_end_transaction(state);
            return res;
        }

        if sw != SW_SUCCESS {
            _ykpiv_end_transaction(state);
            return Err(ErrorKind::AuthenticationError);
        }

        memcpy(
            challenge.as_mut_ptr() as *mut c_void,
            data.as_ptr().offset(4) as *const c_void,
            8,
        );

        // send a response to the cards challenge and a challenge of our own.
        let mut response = [0u8; 8];
        out_len = response.len();

        drc = des_decrypt(
            mgm_key,
            challenge.as_ptr(),
            challenge.len(),
            response.as_mut_ptr(),
            &mut out_len,
        );

        if drc != DesErrorKind::Ok {
            _ykpiv_end_transaction(state);
            return Err(ErrorKind::AuthenticationError);
        }

        recv_len = data.len() as u32;
        apdu = APDU::default();
        apdu.ins = YKPIV_INS_AUTHENTICATE;
        apdu.p1 = YKPIV_ALGO_3DES; // triple des
        apdu.p2 = YKPIV_KEY_CARDMGM; // management key
        apdu.data[0] = 0x7c;
        apdu.data[1] = 20; // 2 + 8 + 2 +8
        apdu.data[2] = 0x80;
        apdu.data[3] = 8;
        memcpy(
            apdu.data[4..12].as_mut_ptr() as *mut c_void,
            response.as_ptr() as *const c_void,
            8,
        );
        apdu.data[12] = 0x81;
        apdu.data[13] = 8;

        if _ykpiv_prng_generate(data[14..20].as_mut_ptr(), 8) == PRngErrorKind::GeneralError {
            if state.verbose != 0 {
                eprintln!("Failed getting randomness for authentication.");
            }

            _ykpiv_end_transaction(state);
            return Err(ErrorKind::RandomnessError);
        }

        memcpy(
            challenge.as_mut_ptr() as *mut c_void,
            data[14..20].as_ptr() as *const c_void,
            8,
        );
        apdu.lc = 20;

        res = _send_data(state, &mut apdu, data.as_mut_ptr(), &mut recv_len, &mut sw);

        if res.is_err() {
            _ykpiv_end_transaction(state);
            return res;
        }

        if sw != SW_SUCCESS {
            _ykpiv_end_transaction(state);
            return Err(ErrorKind::AuthenticationError);
        }

        // compare the response from the card with our challenge
        let mut response = [0u8; 8];
        out_len = response.len();
        drc = des_encrypt(
            mgm_key,
            challenge.as_ptr(),
            mem::size_of::<[u8; 8]>(),
            response.as_mut_ptr(),
            &mut out_len,
        );

        if drc == DesErrorKind::Ok
            // TODO(tarcieri): constant time comparison!
            && memcmp(
                response.as_mut_ptr() as *const c_void,
                data.as_mut_ptr().offset(4) as *const c_void,
                8,
            ) == 0
        {
            res = Ok(());
        } else {
            res = Err(ErrorKind::AuthenticationError);
        }
    }

    if !mgm_key.is_null() {
        des_destroy_key(mgm_key);
    }

    _ykpiv_end_transaction(state);
    res
}

/// Set the management key (MGM)
pub unsafe fn ykpiv_set_mgmkey(state: &mut YubiKey, new_key: *const u8) -> Result<(), ErrorKind> {
    ykpiv_set_mgmkey2(state, new_key, 0)
}

/// Set the management key (MGM)
pub(crate) unsafe fn ykpiv_set_mgmkey2(
    state: &mut YubiKey,
    new_key: *const u8,
    touch: u8,
) -> Result<(), ErrorKind> {
    let mut data = [0u8; 261];
    let mut recv_len = data.len() as u32;
    let mut sw: i32 = 0;
    let mut res = Ok(());
    let mut apdu = APDU::default();

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_ok() {
        if yk_des_is_weak_key(new_key, (8i32 * 3i32) as (usize)) {
            if state.verbose != 0 {
                // TODO(tarcieri): format string
                eprint!("Won\'t set new key \'");
                dump_hex(new_key, DES_LEN_3DES as u32);
                eprintln!("\' since it\'s weak (with odd parity).");
            }
            res = Err(ErrorKind::KeyError);
            apdu.ins = YKPIV_INS_SET_MGMKEY;
            apdu.p1 = 0xff;

            apdu.p2 = match touch {
                0 => 0xff,
                1 => 0xfe,
                _ => {
                    _ykpiv_end_transaction(state);
                    return Err(ErrorKind::GenericError);
                }
            };

            apdu.lc = DES_LEN_3DES as u8 + 3;
            apdu.data[0] = YKPIV_ALGO_3DES;
            apdu.data[1] = YKPIV_KEY_CARDMGM;
            apdu.data[2] = DES_LEN_3DES as u8;
            memcpy(
                apdu.data.as_mut_ptr().offset(3) as *mut c_void,
                new_key as *const c_void,
                DES_LEN_3DES,
            );
        } else {
            res = _send_data(state, &mut apdu, data.as_mut_ptr(), &mut recv_len, &mut sw);

            // TODO(str4d): Shouldn't this be res.is_ok()?
            if res.is_err() && sw != SW_SUCCESS {
                res = Err(ErrorKind::GenericError);
            }
        }
    }

    apdu.zeroize();
    _ykpiv_end_transaction(state);
    res
}

/// Authenticate to the YubiKey
pub(crate) unsafe fn _general_authenticate(
    state: &mut YubiKey,
    sign_in: *const u8,
    in_len: usize,
    out: *mut u8,
    out_len: *mut usize,
    algorithm: u8,
    key: u8,
    decipher: bool,
) -> Result<(), ErrorKind> {
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
                return Err(ErrorKind::SizeError);
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

            if (!decipher && (in_len > key_len)) || (decipher && (in_len != (key_len * 2) + 1)) {
                return Err(ErrorKind::SizeError);
            }
        }
        _ => return Err(ErrorKind::AlgorithmError),
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

    if let Err(e) = ykpiv_transfer_data(
        state,
        templ.as_ptr(),
        indata.as_mut_ptr(),
        dataptr as isize - indata.as_mut_ptr() as isize,
        data.as_mut_ptr(),
        &mut recv_len,
        &mut sw,
    ) {
        if state.verbose != 0 {
            eprintln!("Sign command failed to communicate.");
        }
        return Err(e);
    }

    if sw != SW_SUCCESS {
        if state.verbose != 0 {
            eprintln!("Failed sign command with code {:x}.\n\0", sw);
        }

        if sw == SW_ERR_SECURITY_STATUS {
            return Err(ErrorKind::AuthenticationError);
        } else {
            return Err(ErrorKind::GenericError);
        }
    }

    // skip the first 7c tag
    if data[0] != 0x7c {
        if state.verbose != 0 {
            eprintln!("Failed parsing signature reply.");
        }
        return Err(ErrorKind::ParseError);
    }

    dataptr = data.as_mut_ptr().add(1);
    dataptr = dataptr.add(_ykpiv_get_length(dataptr, &mut len));

    // skip the 82 tag
    if *dataptr != 0x82 {
        if state.verbose != 0 {
            eprintln!("Failed parsing signature reply.");
        }

        return Err(ErrorKind::ParseError);
    }

    dataptr = dataptr.add(1);
    dataptr = dataptr.add(_ykpiv_get_length(dataptr, &mut len));

    if len > *out_len {
        if state.verbose != 0 {
            eprintln!("Wrong size on output buffer.");
        }
        return Err(ErrorKind::SizeError);
    }

    *out_len = len;
    memcpy(out as (*mut c_void), dataptr as (*const c_void), len);
    Ok(())
}

/// Sign data using a PIV key
pub unsafe fn ykpiv_sign_data(
    state: &mut YubiKey,
    raw_in: *const u8,
    in_len: usize,
    sign_out: *mut u8,
    out_len: *mut usize,
    algorithm: u8,
    key: u8,
) -> Result<(), ErrorKind> {
    _ykpiv_begin_transaction(state)?;

    // don't attempt to reselect in crypt operations to avoid problems with PIN_ALWAYS

    let res = _general_authenticate(
        state, raw_in, in_len, sign_out, out_len, algorithm, key, false,
    );

    _ykpiv_end_transaction(state);
    res
}

/// Decrypt data using a PIV key
pub unsafe fn ykpiv_decrypt_data(
    state: &mut YubiKey,
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    out_len: *mut usize,
    algorithm: u8,
    key: u8,
) -> Result<(), ErrorKind> {
    _ykpiv_begin_transaction(state)?;

    // don't attempt to reselect in crypt operations to avoid problems with PIN_ALWAYS

    let res = _general_authenticate(state, input, input_len, out, out_len, algorithm, key, true);
    _ykpiv_end_transaction(state);
    res
}

/// Get the version of the PIV application installed on the YubiKey
pub(crate) unsafe fn _ykpiv_get_version(
    state: &mut YubiKey,
    p_version: *mut Version,
) -> Result<(), ErrorKind> {
    let mut data = [0u8; 261];
    let mut recv_len = data.len() as u32;
    let mut sw: i32 = 0;

    // get version from state if already from device
    if state.ver.major != 0 || state.ver.minor != 0 || state.ver.patch != 0 {
        if !p_version.is_null() {
            // TODO(tarcieri): use real references instead of pointers and memcpy!!!
            #[allow(trivial_casts)]
            memcpy(
                p_version as *mut c_void,
                &state.ver as *const Version as *const c_void,
                mem::size_of::<Version>(),
            );
        }

        return Ok(());
    }

    // get version from device
    let mut apdu = APDU::default();
    apdu.ins = YKPIV_INS_GET_VERSION;

    _send_data(state, &mut apdu, data.as_mut_ptr(), &mut recv_len, &mut sw)?;

    if sw != SW_SUCCESS {
        return Err(ErrorKind::GenericError);
    }

    if recv_len < 3 {
        return Err(ErrorKind::SizeError);
    }

    state.ver.major = data[0];
    state.ver.minor = data[1];
    state.ver.patch = data[2];

    if !p_version.is_null() {
        // TODO(tarcieri): use real references instead of pointers and memcpy!!!
        #[allow(trivial_casts)]
        memcpy(
            p_version as *mut c_void,
            &state.ver as (*const Version) as (*const c_void),
            mem::size_of::<Version>(),
        );
    }

    Ok(())
}

/// Get the YubiKey's PIV application version as a string
pub unsafe fn ykpiv_get_version(state: &mut YubiKey) -> Result<String, ErrorKind> {
    let mut ver: Version = Version {
        major: 0u8,
        minor: 0u8,
        patch: 0u8,
    };

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_ok() {
        let res = _ykpiv_get_version(state, &mut ver);

        if res.is_ok() {
            _ykpiv_end_transaction(state);
            return Ok(format!("{}.{}.{}", ver.major, ver.minor, ver.patch));
        }
    }

    _ykpiv_end_transaction(state);
    Err(ErrorKind::GenericError)
}

/// Get YubiKey device serial number
///
/// NOTE: caller must make sure that this is wrapped in a transaction for synchronized operation
pub(crate) unsafe fn _ykpiv_get_serial(
    state: &mut YubiKey,
    f_force: bool,
) -> Result<u32, ErrorKind> {
    let yk_applet: *const u8 = ptr::null();
    let mut data = [0u8; 255];
    let mut recv_len = data.len() as u32;
    let mut sw: i32 = 0;
    let p_temp: *mut u8;

    if !f_force && state.serial != 0 {
        return Ok(state.serial);
    }

    if state.ver.major < 5 {
        // get serial from neo/yk4 devices using the otp applet
        let mut temp = [0u8; 255];
        recv_len = temp.len() as u32;

        let mut apdu = APDU::default();
        apdu.ins = YKPIV_INS_SELECT_APPLICATION;
        apdu.p1 = 0x04;
        apdu.lc = mem::size_of_val(&yk_applet) as u8;

        memcpy(
            apdu.data.as_mut_ptr() as *mut c_void,
            yk_applet as *const c_void,
            mem::size_of_val(&yk_applet),
        );

        if let Err(e) = _send_data(state, &mut apdu, temp.as_mut_ptr(), &mut recv_len, &mut sw) {
            if state.verbose != 0 {
                eprintln!("Failed communicating with card: \'{}\'", e);
            }

            return Err(e);
        } else if sw != SW_SUCCESS {
            if state.verbose != 0 {
                eprintln!("Failed selecting yk application: {:04x}", sw);
            }

            return Err(ErrorKind::GenericError);
        }

        recv_len = temp.len() as u32;
        apdu = APDU::default();
        apdu.ins = 0x01;
        apdu.p1 = 0x10;
        apdu.lc = 0x00;

        if let Err(e) = _send_data(state, &mut apdu, data.as_mut_ptr(), &mut recv_len, &mut sw) {
            if state.verbose != 0 {
                eprintln!("Failed communicating with card: \'{}\'", e);
            }

            return Err(e);
        } else if sw != SW_SUCCESS {
            if state.verbose != 0 {
                eprintln!("Failed retrieving serial number: {:04x}", sw);
            }

            return Err(ErrorKind::GenericError);
        }

        recv_len = temp.len() as u32;
        apdu = APDU::default();
        apdu.ins = YKPIV_INS_SELECT_APPLICATION;
        apdu.p1 = 0x04;
        apdu.lc = mem::size_of_val(&AID) as u8;

        memcpy(
            apdu.data.as_mut_ptr() as *mut c_void,
            AID.as_ptr() as *const c_void,
            mem::size_of_val(&AID),
        );

        if let Err(e) = _send_data(state, &mut apdu, temp.as_mut_ptr(), &mut recv_len, &mut sw) {
            if state.verbose != 0 {
                eprintln!("Failed communicating with card: \'{}\'", e);
            }
            return Err(e);
        } else if sw != SW_SUCCESS {
            if state.verbose != 0 {
                eprintln!("Failed selecting application: {:04x}", sw);
            }
            return Err(ErrorKind::GenericError);
        }
    } else {
        // get serial from yk5 and later devices using the f8 command
        let mut apdu = APDU::default();
        apdu.ins = YKPIV_INS_GET_SERIAL;

        if let Err(e) = _send_data(state, &mut apdu, data.as_mut_ptr(), &mut recv_len, &mut sw) {
            if state.verbose != 0 {
                eprintln!("Failed communicating with card: \'{}\'", e);
            }
            return Err(e);
        } else if sw != SW_SUCCESS {
            if state.verbose != 0 {
                eprintln!("Failed retrieving serial number: {:04x}", sw);
            }
            return Err(ErrorKind::GenericError);
        }
    }

    // check that we received enough data for the serial number
    if recv_len < 4 {
        return Err(ErrorKind::SizeError);
    }

    // TODO(tarcieri): replace pointers and casts with proper references!
    #[allow(trivial_casts)]
    {
        p_temp = &mut state.serial as (*mut u32) as (*mut u8);
    }

    *p_temp = data[3];
    *p_temp.add(1) = data[2];
    *p_temp.add(2) = data[1];
    *p_temp.add(3) = data[0];

    Ok(state.serial)
}

/// Get YubiKey device serial number
pub unsafe fn ykpiv_get_serial(state: &mut YubiKey) -> Result<u32, ErrorKind> {
    let mut res = Err(ErrorKind::GenericError);

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_ok() {
        res = _ykpiv_get_serial(state, false);
    }

    _ykpiv_end_transaction(state);
    res
}

/// Cache PIN in memory
// TODO(tarcieri): better security around the cached PIN
pub(crate) unsafe fn _cache_pin(
    state: &mut YubiKey,
    pin: *const c_char,
    len: usize,
) -> Result<(), ErrorKind> {
    if !pin.is_null() && (state.pin as *const c_char == pin) {
        return Ok(());
    }

    if !state.pin.is_null() {
        // Zeroize the old cached PIN
        let old_len = strlen(state.pin as *const c_char);
        let pin_slice = slice::from_raw_parts_mut(state.pin, old_len);
        pin_slice.zeroize();

        free(state.pin as (*mut c_void));
        state.pin = ptr::null_mut();
    }

    if !pin.is_null() && len > 0 {
        state.pin = malloc(len + 1) as (*mut u8);

        if state.pin.is_null() {
            return Err(ErrorKind::MemoryError);
        }

        memcpy(state.pin as (*mut c_void), pin as (*const c_void), len);
        *state.pin.add(len) = 0u8;
    }

    Ok(())
}

/// Verify device PIN
pub unsafe fn ykpiv_verify(
    state: &mut YubiKey,
    pin: *const c_char,
    tries: *mut i32,
) -> Result<(), ErrorKind> {
    ykpiv_verify_select(
        state,
        pin,
        if !pin.is_null() { strlen(pin) } else { 0 },
        tries,
        false,
    )
}

/// Verify device PIN
pub(crate) unsafe fn _verify(
    state: &mut YubiKey,
    pin: *const c_char,
    pin_len: usize,
    tries: *mut i32,
) -> Result<(), ErrorKind> {
    let mut data = [0u8; 261];
    let mut recv_len = data.len() as u32;
    let mut sw: i32 = 0;

    if pin_len > CB_PIN_MAX {
        return Err(ErrorKind::SizeError);
    }

    let mut apdu = APDU::default();
    apdu.ins = YKPIV_INS_VERIFY;
    apdu.p1 = 0x00;
    apdu.p2 = 0x80;
    apdu.lc = if pin.is_null() { 0 } else { 0x08 };

    if !pin.is_null() {
        memcpy(
            apdu.data.as_mut_ptr() as *mut c_void,
            pin as *const c_void,
            pin_len,
        );

        if pin_len < CB_PIN_MAX {
            memset(
                apdu.data.as_mut_ptr().add(pin_len) as *mut c_void,
                0xff,
                CB_PIN_MAX - pin_len,
            );
        }
    }

    let res = _send_data(state, &mut apdu, data.as_mut_ptr(), &mut recv_len, &mut sw);

    apdu.zeroize();

    if res.is_err() {
        return res;
    }

    if sw == SW_SUCCESS {
        if !pin.is_null() && (pin_len != 0) {
            // Intentionally ignore errors.  If the PIN fails to save, it will only
            // be a problem if a reconnect is attempted.  Failure deferred until then.
            _cache_pin(state, pin, pin_len);
        }

        if !tries.is_null() {
            *tries = sw & 0xf;
        }
        Ok(())
    } else if sw >> 8 == 0x63 {
        if !tries.is_null() {
            *tries = sw & 0xf;
        }
        Err(ErrorKind::WrongPin)
    } else if sw == SW_ERR_AUTH_BLOCKED {
        if !tries.is_null() {
            *tries = 0;
        }
        Err(ErrorKind::WrongPin)
    } else {
        Err(ErrorKind::GenericError)
    }
}

/// Verify and select application
pub unsafe fn ykpiv_verify_select(
    state: &mut YubiKey,
    pin: *const c_char,
    pin_len: usize,
    tries: *mut i32,
    force_select: bool,
) -> Result<(), ErrorKind> {
    let mut res = Ok(());

    _ykpiv_begin_transaction(state)?;

    if force_select {
        res = _ykpiv_ensure_application_selected(state);
    }

    if res.is_ok() {
        res = _verify(state, pin, pin_len, tries);
    }

    _ykpiv_end_transaction(state);
    res
}

/// Get the number of PIN retries
pub unsafe fn ykpiv_get_pin_retries(state: &mut YubiKey, tries: *mut i32) -> Result<(), ErrorKind> {
    if tries.is_null() {
        return Err(ErrorKind::ArgumentError);
    }

    // Force a re-select to unverify, because once verified the spec dictates that
    // subsequent verify calls will return a "verification not needed" instead of
    // the number of tries left...
    _ykpiv_select_application(state)?;

    let ykrc = ykpiv_verify(state, ptr::null(), tries);

    // WRONG_PIN is expected on successful query.
    match ykrc {
        Ok(()) | Err(ErrorKind::WrongPin) => Ok(()),
        e => e,
    }
}

/// Set the number of PIN retries
pub unsafe fn ykpiv_set_pin_retries(
    state: &mut YubiKey,
    pin_tries: i32,
    puk_tries: i32,
) -> Result<(), ErrorKind> {
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
        return Err(ErrorKind::RangeError);
    }

    templ[2] = pin_tries as (u8);
    templ[3] = puk_tries as (u8);

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_ok() {
        res = ykpiv_transfer_data(
            state,
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
                SW_ERR_AUTH_BLOCKED => Err(ErrorKind::AuthenticationError),
                SW_ERR_SECURITY_STATUS => Err(ErrorKind::AuthenticationError),
                _ => Err(ErrorKind::GenericError),
            };
        }
    }

    _ykpiv_end_transaction(state);
    res
}

/// Change the PIN
pub(crate) unsafe fn _ykpiv_change_pin(
    state: &mut YubiKey,
    action: i32,
    current_pin: *const c_char,
    current_pin_len: usize,
    new_pin: *const c_char,
    new_pin_len: usize,
    tries: *mut i32,
) -> Result<(), ErrorKind> {
    let mut sw: i32 = 0;
    let mut templ = [0, YKPIV_INS_CHANGE_REFERENCE, 0, 0x80];
    let mut indata = [0u8; 16];
    let mut data = [0u8; 255];
    let mut recv_len: usize = data.len();

    if current_pin_len > 8 || new_pin_len > 8 {
        return Err(ErrorKind::SizeError);
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

    let res = ykpiv_transfer_data(
        state,
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
            if !tries.is_null() {
                *tries = sw & 0xf;
            }

            return Err(ErrorKind::WrongPin);
        } else if sw == SW_ERR_AUTH_BLOCKED {
            return Err(ErrorKind::PinLocked);
        } else {
            if state.verbose != 0 {
                eprintln!("Failed changing pin, token response code: {:x}.", sw);
            }

            return Err(ErrorKind::GenericError);
        }
    }

    Ok(())
}

/// Change the Personal Identification Number (PIN).
///
/// The default PIN code is 123456
pub unsafe fn ykpiv_change_pin(
    state: &mut YubiKey,
    current_pin: *const c_char,
    current_pin_len: usize,
    new_pin: *const c_char,
    new_pin_len: usize,
    tries: *mut i32,
) -> Result<(), ErrorKind> {
    let mut res = Err(ErrorKind::GenericError);

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_ok() {
        res = _ykpiv_change_pin(
            state,
            0,
            current_pin,
            current_pin_len,
            new_pin,
            new_pin_len,
            tries,
        );

        if res.is_ok() && !new_pin.is_null() {
            // Intentionally ignore errors.  If the PIN fails to save, it will only
            // be a problem if a reconnect is attempted.  Failure deferred until then.
            _cache_pin(state, new_pin, new_pin_len);
        }
    }

    _ykpiv_end_transaction(state);
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
    state: &mut YubiKey,
    current_puk: *const c_char,
    current_puk_len: usize,
    new_puk: *const c_char,
    new_puk_len: usize,
    tries: *mut i32,
) -> Result<(), ErrorKind> {
    let mut res = Err(ErrorKind::GenericError);

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_ok() {
        res = _ykpiv_change_pin(
            state,
            2,
            current_puk,
            current_puk_len,
            new_puk,
            new_puk_len,
            tries,
        );
    }

    _ykpiv_end_transaction(state);
    res
}

/// Unblock a Personal Identification Number (PIN) using a previously
/// configured PIN Unblocking Key (PUK).
pub unsafe fn ykpiv_unblock_pin(
    state: &mut YubiKey,
    puk: *const c_char,
    puk_len: usize,
    new_pin: *const c_char,
    new_pin_len: usize,
    tries: *mut i32,
) -> Result<(), ErrorKind> {
    let mut res = Err(ErrorKind::GenericError);

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_ok() {
        res = _ykpiv_change_pin(state, 1, puk, puk_len, new_pin, new_pin_len, tries);
    }

    _ykpiv_end_transaction(state);
    res
}

/// Fetch an object from the YubiKey
pub unsafe fn ykpiv_fetch_object(
    state: &mut YubiKey,
    object_id: i32,
    data: *mut u8,
    len: *mut usize,
) -> Result<(), ErrorKind> {
    let mut res = Ok(());

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_ok() {
        res = _ykpiv_fetch_object(state, object_id, data, len);
    }

    _ykpiv_end_transaction(state);
    res
}

/// Fetch an object
pub(crate) unsafe fn _ykpiv_fetch_object(
    state: &mut YubiKey,
    object_id: i32,
    data: *mut u8,
    len: *mut usize,
) -> Result<(), ErrorKind> {
    let mut sw: i32 = 0;
    let mut indata = [0u8; 5];
    let mut inptr: *mut u8 = indata.as_mut_ptr();
    let templ = [0, YKPIV_INS_GET_DATA, 0x3f, 0xff];

    inptr = set_object(object_id, inptr);

    if inptr.is_null() {
        return Err(ErrorKind::InvalidObject);
    }

    ykpiv_transfer_data(
        state,
        templ.as_ptr(),
        indata.as_mut_ptr(),
        inptr as isize - indata.as_mut_ptr() as isize,
        data,
        len,
        &mut sw,
    )?;

    if sw != SW_SUCCESS {
        return Err(ErrorKind::GenericError);
    }

    let mut outlen: usize = 0;

    if *len < 2 || !_ykpiv_has_valid_length(data.offset(1), (*len).wrapping_sub(1)) {
        return Err(ErrorKind::SizeError);
    }

    let offs = _ykpiv_get_length(data.offset(1), &mut outlen);

    if offs == 0 {
        return Err(ErrorKind::SizeError);
    }

    if outlen.wrapping_add(offs).wrapping_add(1) != *len {
        if state.verbose != 0 {
            eprintln!(
                "Invalid length indicated in object, total objlen is {}, indicated length is {}.",
                *len, outlen
            );
        }

        return Err(ErrorKind::SizeError);
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
    state: &mut YubiKey,
    object_id: i32,
    indata: *mut u8,
    len: usize,
) -> Result<(), ErrorKind> {
    let mut res = Ok(());

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_ok() {
        res = _ykpiv_save_object(state, object_id, indata, len);
    }

    _ykpiv_end_transaction(state);
    res
}

/// Save an object
pub unsafe fn _ykpiv_save_object(
    state: &mut YubiKey,
    object_id: i32,
    indata: *mut u8,
    len: usize,
) -> Result<(), ErrorKind> {
    let mut data = [0u8; YKPIV_OBJ_MAX_SIZE];
    let mut dataptr: *mut u8 = data.as_mut_ptr();
    let templ = [0, YKPIV_INS_PUT_DATA, 0x3f, 0xff];
    let mut sw: i32 = 0;
    let mut outlen: usize = 0usize;

    if len > CB_OBJ_MAX {
        return Err(ErrorKind::SizeError);
    }

    dataptr = set_object(object_id, dataptr);

    if dataptr.is_null() {
        return Err(ErrorKind::InvalidObject);
    }
    *{
        let _old = dataptr;
        dataptr = dataptr.offset(1);
        _old
    } = 0x53;

    dataptr = dataptr.add(_ykpiv_set_length(dataptr, len));
    memcpy(dataptr as (*mut c_void), indata as (*const c_void), len);
    dataptr = dataptr.add(len);

    _ykpiv_transfer_data(
        state,
        templ.as_ptr(),
        data.as_mut_ptr(),
        dataptr as isize - data.as_mut_ptr() as isize,
        ptr::null_mut(),
        &mut outlen,
        &mut sw,
    )?;

    match sw {
        SW_SUCCESS => Ok(()),
        SW_ERR_SECURITY_STATUS => Err(ErrorKind::AuthenticationError),
        _ => Err(ErrorKind::GenericError),
    }
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

/// Import a private encryption or signing key into the YubiKey
pub unsafe fn ykpiv_import_private_key(
    state: &mut YubiKey,
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
) -> Result<(), ErrorKind> {
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
        return Err(ErrorKind::KeyError);
    }

    if pin_policy != YKPIV_PINPOLICY_DEFAULT
        && (pin_policy != YKPIV_PINPOLICY_NEVER)
        && (pin_policy != YKPIV_PINPOLICY_ONCE)
        && (pin_policy != YKPIV_PINPOLICY_ALWAYS)
    {
        return Err(ErrorKind::GenericError);
    }

    if touch_policy != YKPIV_TOUCHPOLICY_DEFAULT
        && (touch_policy != YKPIV_TOUCHPOLICY_NEVER)
        && (touch_policy != YKPIV_TOUCHPOLICY_ALWAYS)
        && (touch_policy != YKPIV_TOUCHPOLICY_CACHED)
    {
        return Err(ErrorKind::GenericError);
    }

    match algorithm {
        YKPIV_ALGO_RSA1024 | YKPIV_ALGO_RSA2048 => {
            if p_len + q_len + dp_len + dq_len + qinv_len >= 1024 {
                return Err(ErrorKind::SizeError);
            } else {
                if algorithm == YKPIV_ALGO_RSA1024 {
                    elem_len = 64;
                }

                if algorithm == YKPIV_ALGO_RSA2048 {
                    elem_len = 128;
                }

                if p.is_null() || q.is_null() || dp.is_null() || dq.is_null() || qinv.is_null() {
                    return Err(ErrorKind::GenericError);
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
                return Err(ErrorKind::SizeError);
            }

            if algorithm == YKPIV_ALGO_ECCP256 {
                elem_len = 32;
            } else if algorithm == YKPIV_ALGO_ECCP384 {
                elem_len = 48;
            }

            if ec_data.is_null() {
                return Err(ErrorKind::GenericError);
            }

            params[0] = ec_data;
            lens[0] = ec_data_len as usize;
            param_tag = 0x6;
            n_params = 1;
        }
        _ => return Err(ErrorKind::AlgorithmError),
    }

    for i in 0..n_params {
        *in_ptr = (param_tag + i as i32) as u8;
        in_ptr = in_ptr.offset(1);

        in_ptr = in_ptr.add(_ykpiv_set_length(in_ptr, elem_len as usize));
        let padding = (elem_len as (usize)).wrapping_sub(lens[i as usize]);
        let remaining = (key_data.as_mut_ptr() as usize) + 1024 - in_ptr as usize;

        if padding > remaining {
            return Err(ErrorKind::AlgorithmError);
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

    _ykpiv_begin_transaction(state)?;

    let mut res = Ok(());
    if _ykpiv_ensure_application_selected(state).is_ok() {
        res = ykpiv_transfer_data(
            state,
            templ.as_ptr(),
            key_data.as_mut_ptr(),
            in_ptr as isize - key_data.as_mut_ptr() as isize,
            data.as_mut_ptr(),
            &mut recv_len,
            &mut sw,
        );

        if res.is_ok() && sw != SW_SUCCESS {
            res = Err(ErrorKind::GenericError);
            if sw == SW_ERR_SECURITY_STATUS {
                res = Err(ErrorKind::AuthenticationError);
            }
        }
    }

    key_data.zeroize();
    _ykpiv_end_transaction(state);
    res
}

/// Generate an attestation certificate for a stored key
pub unsafe fn ykpiv_attest(
    state: &mut YubiKey,
    key: u8,
    data: *mut u8,
    data_len: *mut usize,
) -> Result<(), ErrorKind> {
    let mut res = Err(ErrorKind::GenericError);
    let templ = [0, YKPIV_INS_ATTEST, key, 0];
    let mut sw: i32 = 0;
    let mut ul_data_len: usize;

    if data.is_null() || data_len.is_null() {
        return Err(ErrorKind::ArgumentError);
    }

    ul_data_len = *data_len;

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_ok() {
        res = ykpiv_transfer_data(
            state,
            templ.as_ptr(),
            ptr::null(),
            0,
            data,
            &mut ul_data_len,
            &mut sw,
        );

        if res.is_ok() {
            if sw != SW_SUCCESS {
                res = Err(ErrorKind::GenericError);
                if sw == SW_ERR_NOT_SUPPORTED {
                    res = Err(ErrorKind::NotSupported);
                }
            } else if *data as i32 != 0x30 {
                res = Err(ErrorKind::GenericError);
            } else {
                *data_len = ul_data_len;
            }
        }
    }

    _ykpiv_end_transaction(state);
    res
}

/// Get an auth challenge
pub unsafe fn ykpiv_auth_getchallenge(
    state: &mut YubiKey,
    challenge: *mut u8,
    challenge_len: usize,
) -> Result<(), ErrorKind> {
    let mut data = [0u8; 261];
    let mut recv_len = data.len() as u32;
    let mut sw: i32 = 0;
    let mut res = Ok(());

    if challenge.is_null() {
        return Err(ErrorKind::GenericError);
    }

    if challenge_len != 8 {
        return Err(ErrorKind::SizeError);
    }

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_ok() {
        let mut apdu = APDU::default();
        apdu.ins = YKPIV_INS_AUTHENTICATE;
        apdu.p1 = YKPIV_ALGO_3DES; // triple des
        apdu.p2 = YKPIV_KEY_CARDMGM; // management key
        apdu.lc = 0x04;
        apdu.data[0] = 0x7c;
        apdu.data[1] = 0x02;
        apdu.data[2] = 0x81; //0x80;

        res = _send_data(state, &mut apdu, data.as_mut_ptr(), &mut recv_len, &mut sw);

        if res.is_err() {
            if sw != SW_SUCCESS {
                res = Err(ErrorKind::AuthenticationError);
            } else {
                memcpy(
                    challenge as (*mut c_void),
                    data.as_mut_ptr().offset(4isize) as (*const c_void),
                    8usize,
                );
            }
        }
    }

    _ykpiv_end_transaction(state);
    res
}

/// Verify an auth response
pub unsafe fn ykpiv_auth_verifyresponse(
    state: &mut YubiKey,
    response: *mut u8,
    response_len: usize,
) -> Result<(), ErrorKind> {
    let mut data = [0u8; 261];
    let mut recv_len = data.len() as u32;
    let mut sw: i32 = 0;

    if response.is_null() {
        return Err(ErrorKind::GenericError);
    }

    if response_len != 8 {
        return Err(ErrorKind::SizeError);
    }

    _ykpiv_begin_transaction(state)?;

    // send the response to the card and a challenge of our own.
    let mut apdu = APDU::default();
    apdu.ins = YKPIV_INS_AUTHENTICATE;
    apdu.p1 = YKPIV_ALGO_3DES; // triple des
    apdu.p2 = YKPIV_KEY_CARDMGM; // management key
    apdu.data[0] = 0x7c;
    apdu.data[1] = 0x0a; // 2 + 8
    apdu.data[2] = 0x82;
    apdu.data[3] = 8;

    memcpy(
        apdu.data.as_mut_ptr().add(4) as *mut c_void,
        response as *const c_void,
        response_len,
    );

    apdu.lc = 12;

    let mut res = _send_data(state, &mut apdu, data.as_mut_ptr(), &mut recv_len, &mut sw);

    if res.is_ok() && sw != SW_SUCCESS {
        res = Err(ErrorKind::AuthenticationError);
    }

    apdu.zeroize();
    _ykpiv_end_transaction(state);
    res
}

/// MGMT Application ID(?)
static mut MGMT_AID: [u8; 8] = [0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];

/// Deauthenticate
pub unsafe fn ykpiv_auth_deauthenticate(state: &mut YubiKey) -> Result<(), ErrorKind> {
    let mut data = [0u8; 255];
    let mut recv_len = data.len() as u32;
    let mut sw: i32 = 0;

    _ykpiv_begin_transaction(state)?;

    let mut apdu = APDU::default();
    apdu.ins = YKPIV_INS_SELECT_APPLICATION;
    apdu.p1 = 0x04;
    apdu.lc = mem::size_of::<*const u8>() as u8;

    memcpy(
        apdu.data.as_mut_ptr() as *mut c_void,
        MGMT_AID.as_ptr() as *const c_void,
        MGMT_AID.len(),
    );

    let mut res = _send_data(state, &mut apdu, data.as_mut_ptr(), &mut recv_len, &mut sw);

    if let Err(e) = res.as_ref() {
        if state.verbose != 0 {
            eprintln!("Failed communicating with card: \'{}\'", e);
        }
    } else if sw != SW_SUCCESS {
        if state.verbose != 0 {
            eprintln!("Failed selecting mgmt application: {:04x}", sw);
        }
        res = Err(ErrorKind::GenericError);
    }

    _ykpiv_end_transaction(state);
    res
}
