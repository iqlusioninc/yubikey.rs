//! Utility functions

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

#![allow(non_camel_case_types, non_snake_case)]
#![allow(clippy::missing_safety_doc, clippy::too_many_arguments)]

use crate::{consts::*, error::ErrorKind, internal::*, yubikey::*};
use getrandom::getrandom;
use libc::{calloc, free, memcpy, memmove, realloc, time};
use log::{error, warn};
use std::ops::DerefMut;
use std::{ffi::CString, mem, os::raw::c_void, ptr};
use zeroize::{Zeroize, Zeroizing};

/// Cardholder Unique Identifier (CHUID) Template
///
/// Format defined in SP-800-73-4, Appendix A, Table 9
///
/// FASC-N containing S9999F9999F999999F0F1F0000000000300001E encoded in
/// 4-bit BCD with 1 bit parity. run through the tools/fasc.pl script to get
/// bytes. This CHUID has an expiry of 2030-01-01.
///
/// Defined fields:
///
/// - 0x30: FASC-N (hard-coded)
/// - 0x34: Card UUID / GUID (settable)
/// - 0x35: Exp. Date (hard-coded)
/// - 0x3e: Signature (hard-coded, empty)
/// - 0xfe: Error Detection Code (hard-coded)
pub const CHUID_TMPL: &[u8] = &[
    0x30, 0x19, 0xd4, 0xe7, 0x39, 0xda, 0x73, 0x9c, 0xed, 0x39, 0xce, 0x73, 0x9d, 0x83, 0x68, 0x58,
    0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0xc8, 0x42, 0x10, 0xc3, 0xeb, 0x34, 0x10, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x35, 0x08, 0x32,
    0x30, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x3e, 0x00, 0xfe, 0x00,
];

/// Cardholder Capability Container (CCC) Template
///
/// f0: Card Identifier
///
///  - 0xa000000116 == GSC-IS RID
///  - 0xff == Manufacturer ID (dummy)
///  - 0x02 == Card type (javaCard)
///  - next 14 bytes: card ID
pub static mut CCC_TMPL: &[u8] = &[
    0xf0, 0x15, 0xa0, 0x00, 0x00, 0x01, 0x16, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1, 0x01, 0x21, 0xf2, 0x01, 0x21, 0xf3, 0x00, 0xf4,
    0x01, 0x00, 0xf5, 0x01, 0x10, 0xf6, 0x00, 0xf7, 0x00, 0xfa, 0x00, 0xfb, 0x00, 0xfc, 0x00, 0xfd,
    0x00, 0xfe, 0x00,
];

/// Card ID
#[derive(Copy, Clone, Debug)]
pub struct CardId([u8; 16]);

/// Get Card ID
pub unsafe fn ykpiv_util_get_cardid(
    state: &mut YubiKey,
    cardid: *mut CardId,
) -> Result<(), ErrorKind> {
    let mut buf = [0u8; CB_OBJ_MAX];
    let mut len = buf.len();
    let mut res = Ok(());

    if cardid.is_null() {
        return Err(ErrorKind::GenericError);
    }

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_ok() {
        res = _ykpiv_fetch_object(state, YKPIV_OBJ_CHUID as i32, buf.as_mut_ptr(), &mut len);

        if res.is_ok() {
            if len != CHUID_TMPL.len() {
                res = Err(ErrorKind::GenericError);
            } else {
                memcpy(
                    (*cardid).0.as_mut_ptr() as (*mut c_void),
                    buf.as_mut_ptr().add(CHUID_GUID_OFFS) as (*const c_void),
                    YKPIV_CARDID_SIZE,
                );
            }
        }
    }

    let _ = _ykpiv_end_transaction(state);
    res
}

/// Set Card ID
pub unsafe fn ykpiv_util_set_cardid(
    state: &mut YubiKey,
    cardid: *const CardId,
) -> Result<(), ErrorKind> {
    let mut id = [0u8; YKPIV_CARDID_SIZE];
    let mut buf = [0u8; CHUID_TMPL.len()];
    let mut res = Ok(());

    if cardid.is_null() {
        getrandom(&mut id).map_err(|_| ErrorKind::RandomnessError)?;
    } else {
        memcpy(
            id.as_mut_ptr() as (*mut c_void),
            (*cardid).0.as_ptr() as (*const c_void),
            id.len(),
        );
    }

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_ok() {
        memcpy(
            buf.as_mut_ptr() as *mut c_void,
            CHUID_TMPL.as_ptr() as *const c_void,
            buf.len(),
        );

        memcpy(
            buf.as_mut_ptr().add(CHUID_GUID_OFFS) as *mut c_void,
            id.as_mut_ptr() as *const c_void,
            id.len(),
        );

        res = _ykpiv_save_object(
            state,
            YKPIV_OBJ_CHUID as i32,
            buf.as_mut_ptr(),
            CHUID_TMPL.len(),
        );
    }

    let _ = _ykpiv_end_transaction(state);
    res
}

/// Cardholder Capability Container (CCC) Identifier
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CCCID([u8; 14]);

/// Get Cardholder Capability Container (CCC) ID
pub unsafe fn ykpiv_util_get_cccid(state: &mut YubiKey, ccc: *mut CCCID) -> Result<(), ErrorKind> {
    let mut res = Ok(());
    let mut buf = [0u8; CB_OBJ_MAX];
    let mut len = buf.len();

    if ccc.is_null() {
        return Err(ErrorKind::GenericError);
    }

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_ok() {
        res = _ykpiv_fetch_object(
            state,
            YKPIV_OBJ_CAPABILITY as i32,
            buf.as_mut_ptr(),
            &mut len,
        );

        if res.is_ok() {
            if len != CCC_TMPL.len() {
                let _ = _ykpiv_end_transaction(state);
                return Err(ErrorKind::GenericError);
            }

            memcpy(
                (*ccc).0.as_mut_ptr() as (*mut c_void),
                buf.as_mut_ptr().offset(9) as (*const c_void),
                YKPIV_CCCID_SIZE,
            );
        }
    }

    res
}

/// Get Cardholder Capability Container (CCC) ID
pub unsafe fn ykpiv_util_set_cccid(
    state: &mut YubiKey,
    ccc: *const CCCID,
) -> Result<(), ErrorKind> {
    let mut res = Ok(());
    let mut id = [0u8; 14];
    let mut buf = [0u8; 51];
    let len: usize;

    if ccc.is_null() {
        getrandom(&mut id).map_err(|_| ErrorKind::RandomnessError)?;
    } else {
        memcpy(
            id.as_mut_ptr() as (*mut c_void),
            (*ccc).0.as_ptr() as (*const c_void),
            id.len(),
        );
    }

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_ok() {
        len = 51;

        memcpy(
            buf.as_mut_ptr() as *mut c_void,
            CCC_TMPL.as_ptr() as *const c_void,
            len,
        );

        memcpy(
            buf.as_mut_ptr().offset(9) as (*mut c_void),
            id.as_mut_ptr() as (*const c_void),
            14,
        );

        res = _ykpiv_save_object(state, YKPIV_OBJ_CAPABILITY as i32, buf.as_mut_ptr(), len);
    }

    let _ = _ykpiv_end_transaction(state);
    res
}

/// Get YubiKey device model
pub unsafe fn ykpiv_util_devicemodel(state: &mut YubiKey) -> u32 {
    if state.context == 0 || state.context == -1 {
        DEVTYPE_UNKNOWN
    } else if state.is_neo {
        DEVTYPE_NEOr3
    } else {
        DEVTYPE_YK4
    }
}

/// Personal Identity Verification (PIV) keys
#[derive(Copy, Clone, Debug)]
pub struct YkPivKey {
    /// Card slot
    slot: u8,

    /// Length of cert
    cert_len: u16,

    /// Cert
    cert: [u8; 1],
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

/// List Personal Identity Verification (PIV) keys
// TODO(tarcieri): fix clippy alignment warnings
#[allow(clippy::cast_ptr_alignment)]
pub unsafe fn ykpiv_util_list_keys(
    state: &mut YubiKey,
    key_count: *mut u8,
    data: *mut *mut YkPivKey,
    data_len: *mut usize,
) -> Result<(), ErrorKind> {
    let mut _currentBlock;
    let mut res = Ok(());
    let mut p_key: *mut YkPivKey;
    let mut p_data: *mut u8 = ptr::null_mut();
    let mut p_temp: *mut u8;
    let mut cb_data: usize;
    let mut offset: usize = 0;
    let mut buf = [0u8; YKPIV_OBJ_MAX_SIZE];
    let mut cb_buf: usize;
    let mut i: usize;
    let mut cb_realloc: usize;
    let CB_PAGE: usize = 4096;

    if data.is_null() || data_len.is_null() || key_count.is_null() {
        return Err(ErrorKind::GenericError);
    }

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_ok() {
        *key_count = 0;
        *data = ptr::null_mut();
        *data_len = 0;

        p_data = calloc(CB_PAGE, 1) as (*mut u8);

        if p_data.is_null() {
            let _ = _ykpiv_end_transaction(state);
            return Err(ErrorKind::MemoryError);
        }

        cb_data = CB_PAGE;
        i = 0;

        loop {
            if i >= mem::size_of::<*const u8>() {
                _currentBlock = 6;
                break;
            }

            cb_buf = buf.len();
            res = _read_certificate(state, SLOTS[i], buf.as_mut_ptr(), &mut cb_buf);

            if res.is_ok() && (cb_buf > 0) {
                cb_realloc = if mem::size_of::<YkPivKey>()
                    .wrapping_add(cb_buf)
                    .wrapping_sub(1)
                    > cb_data.wrapping_sub(offset)
                {
                    (if mem::size_of::<YkPivKey>()
                        .wrapping_add(cb_buf)
                        .wrapping_sub(1)
                        .wrapping_sub(cb_data.wrapping_sub(offset))
                        > CB_PAGE
                    {
                        mem::size_of::<YkPivKey>()
                            .wrapping_add(cb_buf)
                            .wrapping_sub(1)
                            .wrapping_sub(cb_data.wrapping_sub(offset))
                    } else {
                        CB_PAGE
                    })
                } else {
                    0
                };

                if cb_realloc != 0 {
                    if {
                        p_temp = realloc(p_data as (*mut c_void), cb_data.wrapping_add(cb_realloc))
                            as (*mut u8);
                        p_temp
                    }
                    .is_null()
                    {
                        _currentBlock = 15;
                        break;
                    }
                    p_data = p_temp;
                }

                cb_data = cb_data.wrapping_add(cb_realloc);
                p_key = p_data.add(offset) as *mut YkPivKey;
                (*p_key).slot = SLOTS[i];
                (*p_key).cert_len = cb_buf as (u16);

                memcpy(
                    (*p_key).cert.as_mut_ptr() as *mut c_void,
                    buf.as_mut_ptr() as *const c_void,
                    cb_buf,
                );

                offset = offset.wrapping_add(
                    mem::size_of::<YkPivKey>()
                        .wrapping_add(cb_buf)
                        .wrapping_sub(1),
                );

                *key_count = (*key_count as i32 + 1) as u8;
            }

            i += 1;
        }

        if _currentBlock == 6 {
            *data = p_data as *mut YkPivKey;
            p_data = ptr::null_mut();
            if !data_len.is_null() {
                *data_len = offset;
            }
            res = Ok(());
        } else {
            res = Err(ErrorKind::MemoryError);
        }
    }

    if !p_data.is_null() {
        free(p_data as (*mut c_void));
    }

    let _ = _ykpiv_end_transaction(state);
    res
}

/// Read certificate
pub unsafe fn ykpiv_util_read_cert(
    state: &mut YubiKey,
    slot: u8,
    data: *mut *mut u8,
    data_len: *mut usize,
) -> Result<(), ErrorKind> {
    let mut res = Ok(());
    let mut buf = [0u8; YKPIV_OBJ_MAX_SIZE];
    let mut cb_buf: usize = buf.len();

    if data.is_null() || data_len.is_null() {
        return Err(ErrorKind::GenericError);
    }

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_ok() {
        *data = ptr::null_mut();
        *data_len = 0;
        res = _read_certificate(state, slot, buf.as_mut_ptr(), &mut cb_buf);
        if res.is_ok() {
            if cb_buf == 0 {
                *data = ptr::null_mut();
                *data_len = 0;
            } else if {
                *data = calloc(cb_buf, 1) as *mut u8;
                *data
            }
            .is_null()
            {
                res = Err(ErrorKind::MemoryError);
            } else {
                memcpy(
                    *data as (*mut c_void),
                    buf.as_mut_ptr() as (*const c_void),
                    cb_buf,
                );
                *data_len = cb_buf;
            }
        }
    }

    let _ = _ykpiv_end_transaction(state);
    res
}

/// Write certificate
pub unsafe fn ykpiv_util_write_cert(
    state: &mut YubiKey,
    slot: u8,
    data: *mut u8,
    data_len: usize,
    certinfo: u8,
) -> Result<(), ErrorKind> {
    let mut res = Ok(());

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_ok() {
        res = _write_certificate(state, slot, data, data_len, certinfo);
    }

    let _ = _ykpiv_end_transaction(state);
    res
}

/// Delete certificate
pub unsafe fn ykpiv_util_delete_cert(state: &mut YubiKey, slot: u8) -> Result<(), ErrorKind> {
    ykpiv_util_write_cert(state, slot, ptr::null_mut(), 0, 0)
}

/// Block PUK
pub unsafe fn ykpiv_util_block_puk(state: &mut YubiKey) -> Result<(), ErrorKind> {
    let mut res = Ok(());
    let mut puk = [0x30, 0x42, 0x41, 0x44, 0x46, 0x30, 0x30, 0x44];
    let mut tries_remaining: i32 = -1;
    let mut data = [0u8; YKPIV_OBJ_MAX_SIZE];
    let mut cb_data: usize = data.len();
    let mut p_item: *mut u8 = ptr::null_mut();
    let mut cb_item: usize = 0;
    let mut flags: u8 = 0;

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_err() {
        let _ = _ykpiv_end_transaction(state);
        return Ok(());
    }

    while tries_remaining != 0 {
        res = ykpiv_change_puk(state, puk.as_ptr(), puk.len(), puk.as_ptr(), puk.len());

        match res {
            Ok(()) => puk[0] += 1,
            Err(ErrorKind::WrongPin { tries }) => {
                tries_remaining = tries;
                continue;
            }
            Err(e) => {
                if e != ErrorKind::PinLocked {
                    continue;
                }
                tries_remaining = 0;
                res = Ok(());
            }
        }
    }

    if _read_metadata(state, TAG_ADMIN, data.as_mut_ptr(), &mut cb_data).is_ok()
        && _get_metadata_item(
            data.as_mut_ptr(),
            cb_data,
            TAG_ADMIN_FLAGS_1,
            &mut p_item,
            &mut cb_item,
        )
        .is_ok()
    {
        if cb_item == mem::size_of_val(&flags) {
            // TODO(tarcieri): get rid of memcpy and pointers, replace with slices!
            #[allow(trivial_casts)]
            memcpy(
                &mut flags as *mut u8 as *mut c_void,
                p_item as (*const c_void),
                cb_item,
            );
        } else {
            error!("admin flags exist, but are incorrect size = {}", cb_item);
        }
    }

    flags |= ADMIN_FLAGS_1_PUK_BLOCKED;

    if _set_metadata_item(
        data.as_mut_ptr(),
        &mut cb_data,
        CB_OBJ_MAX,
        TAG_ADMIN_FLAGS_1,
        &mut flags,
        1,
    )
    .is_ok()
    {
        if _write_metadata(state, TAG_ADMIN, data.as_mut_ptr(), cb_data).is_err() {
            error!("could not write admin metadata");
        }
    } else {
        error!("could not set admin flags");
    }

    let _ = _ykpiv_end_transaction(state);
    res
}

/// PIV container
// TODO(tarcieri): dead code?
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub struct YkPivContainer {
    /// Name
    name: [i32; 40],

    /// Card slot
    slot: u8,

    /// Key spec
    key_spec: u8,

    /// Key size in bits
    key_size_bits: u16,

    /// Flags
    flags: u8,

    /// PIN ID
    pin_id: u8,

    /// Associated ECHD container
    associated_echd_container: u8,

    /// Cert fingerprint
    cert_fingerprint: [u8; 20],
}

/// Read mscmap
pub unsafe fn ykpiv_util_read_mscmap(
    state: &mut YubiKey,
    containers: *mut *mut YkPivContainer,
    n_containers: *mut usize,
) -> Result<(), ErrorKind> {
    let mut res = Ok(());
    let mut buf = [0u8; YKPIV_OBJ_MAX_SIZE];
    let mut cb_buf: usize = buf.len();
    let mut len: usize = 0;
    let mut ptr: *mut u8;

    if containers.is_null() || n_containers.is_null() {
        // TODO(str4d): Should this really continue on here?
        res = Err(ErrorKind::GenericError);
    }

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_ok() {
        *containers = ptr::null_mut();
        *n_containers = 0;

        res = _ykpiv_fetch_object(
            state,
            YKPIV_OBJ_MSCMAP as i32,
            buf.as_mut_ptr(),
            &mut cb_buf,
        );

        if res.is_err() {
            let _ = _ykpiv_end_transaction(state);
            return res;
        }

        ptr = buf.as_mut_ptr();

        if cb_buf < CB_OBJ_TAG_MIN {
            let _ = _ykpiv_end_transaction(state);
            return Ok(());
        }

        if *ptr == TAG_MSCMAP {
            ptr = ptr.add(1);
            ptr = ptr.add(_ykpiv_get_length(ptr, &mut len));

            if len > cb_buf - (ptr as isize - buf.as_mut_ptr() as isize) as usize {
                let _ = _ykpiv_end_transaction(state);
                return Ok(());
            }

            *containers = calloc(len, 1) as (*mut YkPivContainer);

            if (*containers).is_null() {
                res = Err(ErrorKind::MemoryError);
            } else {
                memcpy(*containers as (*mut c_void), ptr as (*const c_void), len);
                *n_containers = len.wrapping_div(mem::size_of::<YkPivContainer>());
            }
        }
    }

    res
}

/// Get max object size
unsafe fn _obj_size_max(state: &mut YubiKey) -> usize {
    if state.is_neo {
        2048 - 9
    } else {
        CB_OBJ_MAX
    }
}

/// Write mscmap
pub unsafe fn ykpiv_util_write_mscmap(
    state: &mut YubiKey,
    containers: *mut YkPivContainer,
    n_containers: usize,
) -> Result<(), ErrorKind> {
    let mut res = Ok(());
    let mut buf = [0u8; CB_OBJ_MAX];
    let mut offset: usize = 0;
    let data_len: usize = n_containers.wrapping_mul(mem::size_of::<YkPivContainer>());

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_ok() {
        if containers.is_null() || n_containers == 0 {
            if !containers.is_null() || n_containers != 0 {
                res = Err(ErrorKind::GenericError);
            } else {
                res = _ykpiv_save_object(state, YKPIV_OBJ_MSCMAP as i32, ptr::null_mut(), 0);
            }

            let _ = _ykpiv_end_transaction(state);
            return res;
        }

        let req_len = 1 + _ykpiv_set_length(buf.as_mut_ptr(), data_len) + data_len;

        if req_len > _obj_size_max(state) {
            let _ = _ykpiv_end_transaction(state);
            return Err(ErrorKind::SizeError);
        }

        buf[offset] = TAG_MSCMAP;
        offset += 1;
        offset += _ykpiv_set_length(buf.as_mut_ptr().add(offset), data_len);
        memcpy(
            buf.as_mut_ptr().add(offset) as (*mut c_void),
            containers as (*mut u8) as (*const c_void),
            data_len,
        );
        offset = offset.wrapping_add(data_len);
        res = _ykpiv_save_object(state, YKPIV_OBJ_MSCMAP as i32, buf.as_mut_ptr(), offset);
    }

    let _ = _ykpiv_end_transaction(state);
    res
}

/// Read msroots
pub unsafe fn ykpiv_util_read_msroots(
    state: &mut YubiKey,
    data: *mut *mut u8,
    data_len: *mut usize,
) -> Result<(), ErrorKind> {
    let mut _currentBlock = 0;
    let mut res;
    let mut buf = [0u8; YKPIV_OBJ_MAX_SIZE];
    let mut cb_buf: usize;
    let mut len: usize = 0;
    let mut ptr: *mut u8;
    let mut tag: u8;
    let mut p_data: *mut u8;
    let mut p_temp: *mut u8;
    let mut cb_data: usize;
    let mut cb_realloc: usize;
    let mut offset: usize = 0;

    if data.is_null() || data_len.is_null() {
        return Err(ErrorKind::GenericError);
    }

    _ykpiv_begin_transaction(state)?;

    res = _ykpiv_ensure_application_selected(state);
    if res.is_err() {
        let _ = _ykpiv_end_transaction(state);
        return res;
    }

    *data = ptr::null_mut();
    *data_len = 0;

    // allocate first page
    cb_data = _obj_size_max(state);
    p_data = calloc(cb_data, 1) as (*mut u8);

    if p_data.is_null() {
        let _ = _ykpiv_end_transaction(state);
        return Err(ErrorKind::MemoryError);
    }

    for object_id in YKPIV_OBJ_MSROOTS1..YKPIV_OBJ_MSROOTS5 {
        cb_buf = buf.len();

        res = _ykpiv_fetch_object(state, object_id as i32, buf.as_mut_ptr(), &mut cb_buf);

        if res.is_err() {
            let _ = _ykpiv_end_transaction(state);
            return res;
        }

        ptr = buf.as_mut_ptr();
        if cb_buf < CB_OBJ_TAG_MIN {
            let _ = _ykpiv_end_transaction(state);
            return Ok(());
        }

        tag = *ptr;
        ptr = ptr.add(1);

        if tag != TAG_MSROOTS_MID && (tag != TAG_MSROOTS_END || object_id == YKPIV_OBJ_MSROOTS5) {
            // the current object doesn't contain a valid part of a msroots file
            let _ = _ykpiv_end_transaction(state);

            // treat condition as object isn't found
            return Ok(());
        }

        ptr = ptr.add(_ykpiv_get_length(ptr, &mut len));

        // check that decoded length represents object contents
        if len > cb_buf - (ptr as isize - buf.as_mut_ptr() as isize) as usize {
            let _ = _ykpiv_end_transaction(state);
            return Ok(());
        }

        cb_realloc = if len > cb_data.wrapping_sub(offset) {
            len.wrapping_sub(cb_data.wrapping_sub(offset))
        } else {
            0
        };

        if cb_realloc != 0 {
            if {
                p_temp =
                    realloc(p_data as (*mut c_void), cb_data.wrapping_add(cb_realloc)) as (*mut u8);
                p_temp
            }
            .is_null()
            {
                // realloc failed, pData will be freed in cleanup
                _currentBlock = 16;
                break;
            }
            p_data = p_temp;
        }

        cb_data = cb_data.wrapping_add(cb_realloc);

        memcpy(
            p_data.add(offset) as (*mut c_void),
            ptr as (*const c_void),
            len,
        );

        offset = offset.wrapping_add(len);

        if tag == TAG_MSROOTS_END {
            _currentBlock = 15;
            break;
        }
    }

    if _currentBlock == 15 {
        *data = p_data;
        p_data = ptr::null_mut();
        *data_len = offset;
        res = Ok(());
    } else if _currentBlock == 16 {
        res = Err(ErrorKind::MemoryError);
    } else if _currentBlock != 21 {
        res = Ok(());
    }

    if !p_data.is_null() {
        free(p_data as (*mut c_void));
    }

    let _ = _ykpiv_end_transaction(state);
    res
}

/// Write msroots
pub unsafe fn ykpiv_util_write_msroots(
    state: &mut YubiKey,
    data: *mut u8,
    data_len: usize,
) -> Result<(), ErrorKind> {
    let mut res = Ok(());
    let mut buf = [0u8; CB_OBJ_MAX];
    let mut offset: usize;
    let mut data_offset: usize = 0;
    let mut data_chunk: usize;
    let n_objs: usize;
    let cb_obj_max = _obj_size_max(state);

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_ok() {
        if data.is_null() || data_len == 0 {
            if !data.is_null() || data_len != 0 {
                res = Err(ErrorKind::GenericError);
            } else {
                res = _ykpiv_save_object(state, YKPIV_OBJ_MSROOTS1 as i32, ptr::null_mut(), 0);
            }

            let _ = _ykpiv_end_transaction(state);
            return res;
        }

        n_objs = (data_len / (cb_obj_max - 4)) + 1;

        if n_objs > 5 {
            let _ = _ykpiv_end_transaction(state);
            return Err(ErrorKind::SizeError);
        }

        for i in 0..n_objs {
            offset = 0;

            data_chunk = if cb_obj_max - 4 < data_len - data_offset {
                cb_obj_max - 4
            } else {
                data_len - data_offset
            };

            buf[offset] = if i == n_objs - 1 {
                TAG_MSROOTS_END
            } else {
                TAG_MSROOTS_MID
            };

            offset += 1;
            offset += _ykpiv_set_length(buf.as_mut_ptr().add(offset), data_chunk);

            memcpy(
                buf.as_mut_ptr().add(offset) as *mut c_void,
                data.add(data_offset) as *const c_void,
                data_chunk,
            );

            offset = offset.wrapping_add(data_chunk);

            res = _ykpiv_save_object(
                state,
                (YKPIV_OBJ_MSROOTS1 + i as u32) as i32,
                buf.as_mut_ptr(),
                offset,
            );

            if res.is_err() {
                break;
            }

            data_offset = data_offset.wrapping_add(data_chunk);
        }
    }

    let _ = _ykpiv_end_transaction(state);
    res
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

/// Generate key
#[allow(clippy::cognitive_complexity)]
pub unsafe fn ykpiv_util_generate_key(
    state: &mut YubiKey,
    slot: u8,
    algorithm: u8,
    pin_policy: u8,
    touch_policy: u8,
    modulus: *mut *mut u8,
    modulus_len: *mut usize,
    exp: *mut *mut u8,
    exp_len: *mut usize,
    point: *mut *mut u8,
    point_len: *mut usize,
) -> Result<(), ErrorKind> {
    let mut res = Ok(());
    let mut in_data = [0u8; 11];
    let mut in_ptr = in_data.as_mut_ptr();
    let mut data = [0u8; 1024];
    let mut templ = [0, YKPIV_INS_GENERATE_ASYMMETRIC, 0, 0];
    let mut recv_len = data.len();
    let mut sw: i32 = 0;
    let mut ptr_modulus: *mut u8 = ptr::null_mut();
    let cb_modulus: usize;
    let mut ptr_exp: *mut u8 = ptr::null_mut();
    let cb_exp: usize;
    let mut ptr_point: *mut u8 = ptr::null_mut();
    let cb_point: usize;
    let setting_roca: SettingBool;

    if ykpiv_util_devicemodel(state) == DEVTYPE_YK4
        && (algorithm == YKPIV_ALGO_RSA1024 || algorithm == YKPIV_ALGO_RSA2048)
        && state.ver.major == 4
        && (state.ver.minor < 3 || state.ver.minor == 3 && (state.ver.patch < 5))
    {
        let setting_name = CString::new(SZ_SETTING_ROCA).unwrap();
        setting_roca = setting_get_bool(setting_name.as_ptr(), true);

        let psz_msg = match setting_roca.source {
            SettingSource::User => {
                if setting_roca.value {
                    SZ_ROCA_ALLOW_USER
                } else {
                    SZ_ROCA_BLOCK_USER
                }
            }
            SettingSource::Admin => {
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
            state.serial, psz_msg
        );

        if !setting_roca.value {
            return Err(ErrorKind::NotSupported);
        }
    }

    match algorithm {
        YKPIV_ALGO_RSA1024 | YKPIV_ALGO_RSA2048 => {
            if point.is_null() || point_len.is_null() {
                error!("invalid output parameter for ECC algorithm");
                return Err(ErrorKind::GenericError);
            }

            *point = ptr::null_mut();
            *point_len = 0;
        }
        YKPIV_ALGO_ECCP256 | YKPIV_ALGO_ECCP384 => {
            if modulus.is_null() || modulus_len.is_null() || exp.is_null() || exp_len.is_null() {
                error!("invalid output parameter for RSA algorithm");
                return Err(ErrorKind::GenericError);
            }

            *modulus = ptr::null_mut();
            *modulus_len = 0;
            *exp = ptr::null_mut();
            *exp_len = 0;
        }
        _ => {
            error!("invalid algorithm specified");
            return Err(ErrorKind::GenericError);
        }
    }

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_ok() {
        templ[3] = slot;

        *in_ptr = 0xac;
        *in_ptr.add(1) = 3;
        *in_ptr.add(2) = YKPIV_ALGO_TAG;
        *in_ptr.add(3) = 1;
        *in_ptr.add(4) = algorithm;
        in_ptr = in_ptr.add(5);

        if in_data[4] == 0 {
            res = Err(ErrorKind::AlgorithmError);
            error!("unexpected algorithm");
        } else {
            if pin_policy != YKPIV_PINPOLICY_DEFAULT {
                in_data[1] += 3;
                *in_ptr = YKPIV_PINPOLICY_TAG;
                *in_ptr.add(1) = 1;
                *in_ptr.add(2) = pin_policy;
                in_ptr = in_ptr.add(3);
            }

            if touch_policy != YKPIV_TOUCHPOLICY_DEFAULT {
                in_data[1] += 3;
                *in_ptr = YKPIV_TOUCHPOLICY_TAG;
                *in_ptr.add(1) = 1;
                *in_ptr.add(2) = touch_policy;
                in_ptr = in_ptr.add(3);
            }

            res = _ykpiv_transfer_data(
                state,
                templ.as_ptr(),
                in_data.as_mut_ptr(),
                in_ptr as isize - in_data.as_mut_ptr() as isize,
                data.as_mut_ptr(),
                &mut recv_len,
                &mut sw,
            );

            if res.is_err() {
                error!("failed to communicate");
            } else if sw != SW_SUCCESS {
                let err_msg = "failed to generate new key";

                match sw {
                    SW_ERR_INCORRECT_SLOT => {
                        res = Err(ErrorKind::KeyError);
                        error!("{} (incorrect slot)", err_msg);
                    }
                    SW_ERR_INCORRECT_PARAM => {
                        res = Err(ErrorKind::AlgorithmError);

                        if pin_policy != 0 {
                            error!("{} (pin policy not supported?)", err_msg);
                        } else if touch_policy != 0 {
                            error!("{} (touch policy not supported?)", err_msg);
                        } else {
                            error!("{} (algorithm not supported?)", err_msg);
                        }
                    }
                    SW_ERR_SECURITY_STATUS => {
                        res = Err(ErrorKind::AuthenticationError);
                        error!("{} (not authenticated)", err_msg);
                    }
                    _ => {
                        res = Err(ErrorKind::GenericError);
                        error!("{} (error {:x})", err_msg, sw);
                    }
                }
            } else if algorithm == YKPIV_ALGO_RSA1024 || algorithm == YKPIV_ALGO_RSA2048 {
                let mut data_ptr: *mut u8 = data.as_mut_ptr().offset(5);
                let mut len: usize = 0;

                if *data_ptr != TAG_RSA_MODULUS {
                    error!("Failed to parse public key structure (modulus)");
                    res = Err(ErrorKind::ParseError);
                } else {
                    data_ptr = data_ptr.add(1);
                    data_ptr = data_ptr.add(_ykpiv_get_length(data_ptr, &mut len));
                    cb_modulus = len;
                    ptr_modulus = calloc(cb_modulus, 1) as *mut u8;

                    if ptr_modulus.is_null() {
                        error!("failed to allocate memory for modulus");
                        res = Err(ErrorKind::MemoryError);
                    } else {
                        memcpy(
                            ptr_modulus as *mut c_void,
                            data_ptr as *const c_void,
                            cb_modulus,
                        );

                        data_ptr = data_ptr.add(len);
                        if *data_ptr != TAG_RSA_EXP {
                            error!("failed to parse public key structure (public exponent)");
                            res = Err(ErrorKind::ParseError);
                        } else {
                            data_ptr = data_ptr.add(1);
                            data_ptr = data_ptr.add(_ykpiv_get_length(data_ptr, &mut len));
                            cb_exp = len;
                            ptr_exp = calloc(cb_exp, 1) as *mut u8;
                            if ptr_exp.is_null() {
                                error!("failed to allocate memory for public exponent");
                                res = Err(ErrorKind::MemoryError);
                            } else {
                                memcpy(
                                    ptr_exp as (*mut c_void),
                                    data_ptr as (*const c_void),
                                    cb_exp,
                                );

                                // set output parameters
                                *modulus = ptr_modulus;
                                ptr_modulus = ptr::null_mut();
                                *modulus_len = cb_modulus;
                                *exp = ptr_exp;
                                ptr_exp = ptr::null_mut();
                                *exp_len = cb_exp;
                            }
                        }
                    }
                }
            } else if algorithm == YKPIV_ALGO_ECCP256 || algorithm == YKPIV_ALGO_ECCP384 {
                let mut data_ptr: *mut u8 = data.as_mut_ptr().offset(3);

                let len = if algorithm == YKPIV_ALGO_ECCP256 {
                    CB_ECC_POINTP256
                } else {
                    CB_ECC_POINTP384
                };

                let tag = *data_ptr;
                data_ptr = data_ptr.add(1);

                if tag != TAG_ECC_POINT {
                    error!("failed to parse public key structure");
                    res = Err(ErrorKind::ParseError);
                } else {
                    // the curve point should always be determined by the curve
                    let len_byte = *data_ptr;
                    data_ptr = data_ptr.add(1);

                    if len_byte as usize != len {
                        error!("unexpected length");
                        res = Err(ErrorKind::AlgorithmError);
                    } else {
                        cb_point = len;
                        ptr_point = calloc(cb_point, 1) as (*mut u8);

                        if ptr_point.is_null() {
                            error!("failed to allocate memory for public point");
                            res = Err(ErrorKind::MemoryError);
                        } else {
                            memcpy(
                                ptr_point as (*mut c_void),
                                data_ptr as (*const c_void),
                                cb_point,
                            );
                            *point = ptr_point;
                            ptr_point = ptr::null_mut();
                            *point_len = cb_point;
                        }
                    }
                }
            } else {
                error!("wrong algorithm");
                res = Err(ErrorKind::AlgorithmError);
            }
        }
    }

    if !ptr_modulus.is_null() {
        free(modulus as (*mut c_void));
    }

    if !ptr_exp.is_null() {
        free(ptr_exp as (*mut c_void));
    }

    if !ptr_point.is_null() {
        free(ptr_exp as (*mut c_void));
    }

    let _ = _ykpiv_end_transaction(state);
    res
}

/// Config mgm type
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
#[allow(non_camel_case_types)]
pub enum YkPivConfigMgmType {
    /// Manual
    YKPIV_CONFIG_MGM_MANUAL = 0i32,

    /// Derived
    YKPIV_CONFIG_MGM_DERIVED = 1i32,

    /// Protected
    YKPIV_CONFIG_MGM_PROTECTED = 2i32,
}

/// Config
#[derive(Copy, Clone)]
pub struct YkPivConfig {
    /// Protected data available
    protected_data_available: bool,

    /// PUK blocked
    puk_blocked: bool,

    /// No block on upgrade
    puk_noblock_on_upgrade: bool,

    /// PIN last changed
    pin_last_changed: u32,

    /// MGM type
    mgm_type: YkPivConfigMgmType,
}

/// Get config
pub unsafe fn ykpiv_util_get_config(
    state: &mut YubiKey,
    config: *mut YkPivConfig,
) -> Result<(), ErrorKind> {
    let mut data = [0u8; YKPIV_OBJ_MAX_SIZE];
    let mut cb_data: usize = mem::size_of::<[u8; YKPIV_OBJ_MAX_SIZE]>();
    let mut p_item: *mut u8 = ptr::null_mut();
    let mut cb_item: usize = 0;
    let mut res = Ok(());

    if config.is_null() {
        return Err(ErrorKind::GenericError);
    }

    (*config).protected_data_available = false;
    (*config).puk_blocked = false;
    (*config).puk_noblock_on_upgrade = false;
    (*config).pin_last_changed = 0;
    (*config).mgm_type = YkPivConfigMgmType::YKPIV_CONFIG_MGM_MANUAL;

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_ok() {
        if _read_metadata(state, TAG_ADMIN, data.as_mut_ptr(), &mut cb_data).is_ok() {
            if _get_metadata_item(
                data.as_mut_ptr(),
                cb_data,
                TAG_ADMIN_FLAGS_1,
                &mut p_item,
                &mut cb_item,
            )
            .is_ok()
            {
                if *p_item & ADMIN_FLAGS_1_PUK_BLOCKED != 0 {
                    (*config).puk_blocked = true;
                }

                if *p_item & ADMIN_FLAGS_1_PROTECTED_MGM != 0 {
                    (*config).mgm_type = YkPivConfigMgmType::YKPIV_CONFIG_MGM_PROTECTED;
                }
            }
            if _get_metadata_item(
                data.as_mut_ptr(),
                cb_data,
                TAG_ADMIN_SALT,
                &mut p_item,
                &mut cb_item,
            )
            .is_ok()
            {
                if (*config).mgm_type != YkPivConfigMgmType::YKPIV_CONFIG_MGM_MANUAL {
                    error!("conflicting types of mgm key administration configured");
                } else {
                    (*config).mgm_type = YkPivConfigMgmType::YKPIV_CONFIG_MGM_DERIVED;
                }
            }

            if _get_metadata_item(
                data.as_mut_ptr(),
                cb_data,
                TAG_ADMIN_TIMESTAMP,
                &mut p_item,
                &mut cb_item,
            )
            .is_ok()
            {
                if cb_item != CB_ADMIN_TIMESTAMP {
                    error!("pin timestamp in admin metadata is an invalid size");
                } else {
                    // TODO(tarcieri): get rid of memcpy and pointers, replace with slices!
                    #[allow(trivial_casts)]
                    memcpy(
                        &mut (*config).pin_last_changed as (*mut u32) as (*mut c_void),
                        p_item as (*const c_void),
                        cb_item,
                    );
                }
            }
        }

        cb_data = YKPIV_OBJ_MAX_SIZE;
        if _read_metadata(state, TAG_PROTECTED, data.as_mut_ptr(), &mut cb_data).is_ok() {
            (*config).protected_data_available = true;

            res = _get_metadata_item(
                data.as_mut_ptr(),
                cb_data,
                TAG_PROTECTED_FLAGS_1,
                &mut p_item,
                &mut cb_item,
            );

            if res.is_ok() && *p_item & PROTECTED_FLAGS_1_PUK_NOBLOCK != 0 {
                (*config).puk_noblock_on_upgrade = true;
            }

            res = _get_metadata_item(
                data.as_mut_ptr(),
                cb_data,
                TAG_PROTECTED_MGM,
                &mut p_item,
                &mut cb_item,
            );

            if res.is_ok() {
                if (*config).mgm_type != YkPivConfigMgmType::YKPIV_CONFIG_MGM_PROTECTED {
                    error!("conflicting types of mgm key administration configured - protected mgm exists");
                }

                (*config).mgm_type = YkPivConfigMgmType::YKPIV_CONFIG_MGM_PROTECTED;
            }
        }
    }

    let _ = _ykpiv_end_transaction(state);
    res
}

/// Set PIN last changed
pub unsafe fn ykpiv_util_set_pin_last_changed(state: &mut YubiKey) -> Result<(), ErrorKind> {
    let mut data = [0u8; YKPIV_OBJ_MAX_SIZE];
    let mut cb_data = data.len();
    let mut res = Ok(());

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_ok() {
        if _read_metadata(state, TAG_ADMIN, data.as_mut_ptr(), &mut cb_data).is_err() {
            cb_data = 0;
        }

        let mut tnow = time(ptr::null_mut());

        res = {
            // TODO(tarcieri): get rid of memcpy and pointers, replace with slices!
            #[allow(trivial_casts)]
            _set_metadata_item(
                data.as_mut_ptr(),
                &mut cb_data,
                CB_OBJ_MAX,
                TAG_ADMIN_TIMESTAMP,
                &mut tnow as *mut i64 as *mut u8,
                CB_ADMIN_TIMESTAMP,
            )
        };

        if let Err(e) = &res {
            error!("could not set pin timestamp, err = {}", e);
        } else {
            res = _write_metadata(state, TAG_ADMIN, data.as_mut_ptr(), cb_data);
            if let Err(e) = &res {
                error!("could not write admin data, err = {}", e);
            }
        }
    }
    let _ = _ykpiv_end_transaction(state);
    res
}

/// Management key (MGM)
#[derive(Clone)]
pub struct YkPivMgm([u8; 24]);

impl Zeroize for YkPivMgm {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for YkPivMgm {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Get derived management key (MGM)
pub unsafe fn ykpiv_util_get_derived_mgm(
    state: &mut YubiKey,
    pin: *const u8,
    pin_len: usize,
    mgm: *mut YkPivMgm,
) -> Result<(), ErrorKind> {
    let mut data = [0u8; YKPIV_OBJ_MAX_SIZE];
    let mut cb_data: usize = data.len();
    let mut p_item: *mut u8 = ptr::null_mut();
    let mut cb_item: usize = 0;

    if pin.is_null() || pin_len == 0 || mgm.is_null() {
        return Err(ErrorKind::GenericError);
    }

    _ykpiv_begin_transaction(state)?;

    let mut res = _ykpiv_ensure_application_selected(state);

    if res.is_err() {
        let _ = _ykpiv_end_transaction(state);
        return res;
    }

    // recover management key
    res = _read_metadata(state, TAG_ADMIN, data.as_mut_ptr(), &mut cb_data);

    if res.is_ok() {
        res = _get_metadata_item(
            data.as_mut_ptr(),
            cb_data,
            TAG_ADMIN_SALT,
            &mut p_item,
            &mut cb_item,
        );

        if res.is_ok() {
            if cb_item != CB_ADMIN_SALT {
                error!(
                    "derived mgm salt exists, but is incorrect size = {}",
                    cb_item,
                );
            }

            let _ = _ykpiv_end_transaction(state);
            return Err(ErrorKind::GenericError);
        }

        let p5rc = pkcs5_pbkdf2_sha1(
            pin,
            pin_len,
            p_item,
            cb_item,
            ITER_MGM_PBKDF2,
            (*mgm).0.as_mut_ptr(),
            (*mgm).0.len(),
        );

        if p5rc != Pkcs5ErrorKind::Ok {
            error!("pbkdf2 failure, err = {:?}", p5rc);
            res = Err(ErrorKind::GenericError);
        }
    }

    let _ = _ykpiv_end_transaction(state);
    res
}

/// Get protected management key (MGM)
pub unsafe fn ykpiv_util_get_protected_mgm(
    state: &mut YubiKey,
    mgm: *mut YkPivMgm,
) -> Result<(), ErrorKind> {
    // TODO(tarcieri): replace vec with wrapper type that impls `Zeroize`
    let mut data = Zeroizing::new([0u8; YKPIV_OBJ_MAX_SIZE].to_vec());
    let mut cb_data: usize = data.len();
    let mut p_item: *mut u8 = ptr::null_mut();
    let mut cb_item: usize = 0;
    let mut res = Ok(());

    if mgm.is_null() {
        return Err(ErrorKind::GenericError);
    }

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_ok() {
        res = _read_metadata(state, TAG_PROTECTED, data.as_mut_ptr(), &mut cb_data);

        if res.is_err() {
            error!("could not read protected data, err = {:?}", res);
        } else {
            res = _get_metadata_item(
                data.as_mut_ptr(),
                cb_data,
                TAG_PROTECTED_MGM,
                &mut p_item,
                &mut cb_item,
            );

            if let Err(e) = &res {
                error!("could not read protected mgm from metadata, err = {}", e,);
            } else if cb_item != (*mgm).0.len() {
                error!(
                    "protected data contains mgm, but is the wrong size = {}",
                    cb_item,
                );
                res = Err(ErrorKind::AuthenticationError);
            } else {
                memcpy(
                    (*mgm).0.as_mut_ptr() as (*mut c_void),
                    p_item as (*const c_void),
                    cb_item,
                );
            }
        }
    }

    let _ = _ykpiv_end_transaction(state);
    res
}

/// Set protected management key (MGM)
///
/// To set a generated mgm, pass NULL for mgm, or set mgm.data to all zeroes
#[allow(clippy::cognitive_complexity)]
pub unsafe fn ykpiv_util_set_protected_mgm(
    state: &mut YubiKey,
    mgm: *mut YkPivMgm,
) -> Result<(), ErrorKind> {
    let mut f_generate: bool;
    let mut mgm_key = Zeroizing::new([0u8; 24]);
    // TODO(tarcieri): replace vec with wrapper type that impls `Zeroize`
    let mut data = Zeroizing::new([0u8; YKPIV_OBJ_MAX_SIZE].to_vec());
    let mut cb_data = data.len();
    let mut p_item: *mut u8 = ptr::null_mut();
    let mut cb_item: usize = 0;
    let mut flags_1: u8 = 0;

    if mgm.is_null() {
        f_generate = true;
    } else {
        f_generate = true;
        memcpy(
            (*mgm_key).as_mut_ptr() as (*mut c_void),
            (*mgm).0.as_mut_ptr() as (*const c_void),
            (*mgm).0.len(),
        );

        for i in 0..mgm_key.len() {
            if mgm_key[i] != 0 {
                f_generate = false;
                break;
            }
        }
    }

    _ykpiv_begin_transaction(state)?;

    if _ykpiv_ensure_application_selected(state).is_err() {
        let _ = _ykpiv_end_transaction(state);
        return Ok(());
    }

    // try to set the mgm key as long as we don't encounter a fatal error
    loop {
        if f_generate {
            // generate a new mgm key
            if let Err(e) = getrandom(mgm_key.deref_mut()) {
                error!("could not generate new mgm, err = {}", e);
                let _ = _ykpiv_end_transaction(state);
                return Err(ErrorKind::RandomnessError);
            }
        }

        let ykrc = ykpiv_set_mgmkey(state, mgm_key.as_mut_ptr());

        if ykrc.is_err() {
            // if set_mgmkey fails with KeyError, it means the generated key is weak
            // otherwise, log a warning, since the device mgm key is corrupt or we're in
            // a state where we can't set the mgm key
            if Err(ErrorKind::KeyError) != ykrc {
                error!(
                    "could not set new derived mgm key, err = {}",
                    ykrc.as_ref().unwrap_err()
                );
                let _ = _ykpiv_end_transaction(state);
                return ykrc;
            }
        } else {
            f_generate = false;
        }

        if !f_generate {
            break;
        }
    }

    if !mgm.is_null() {
        memcpy(
            (*mgm).0.as_mut_ptr() as (*mut c_void),
            mgm_key.as_mut_ptr() as (*const c_void),
            (*mgm).0.len(),
        );
    }

    // after this point, we've set the mgm key, so the function should
    // succeed, regardless of being able to set the metadata

    // set the new mgm key in protected data
    let mut ykrc = _read_metadata(state, TAG_PROTECTED, data.as_mut_ptr(), &mut cb_data);

    if ykrc.is_err() {
        // set current metadata blob size to zero, we'll add to the blank blob
        cb_data = 0;
    }

    ykrc = _set_metadata_item(
        data.as_mut_ptr(),
        &mut cb_data,
        CB_OBJ_MAX,
        TAG_PROTECTED_MGM,
        mgm_key.as_mut_ptr(),
        mgm_key.len(),
    );

    if ykrc.is_err() {
        error!("could not set protected mgm item, err = {:?}", ykrc);
    } else {
        ykrc = _write_metadata(state, TAG_PROTECTED, data.as_mut_ptr(), cb_data);

        if ykrc.is_err() {
            error!("could not write protected data, err = {:?}", ykrc);
            let _ = _ykpiv_end_transaction(state);
            return ykrc;
        }
    }

    // set the protected mgm flag in admin data
    cb_data = YKPIV_OBJ_MAX_SIZE;
    ykrc = _read_metadata(state, TAG_ADMIN, data.as_mut_ptr(), &mut cb_data);

    if ykrc.is_err() {
        cb_data = 0;
    } else {
        ykrc = _get_metadata_item(
            data.as_mut_ptr(),
            cb_data,
            TAG_ADMIN_FLAGS_1,
            &mut p_item,
            &mut cb_item,
        );

        if ykrc.is_err() {
            // flags are not set
            error!("admin data exists, but flags are not present",);
        }

        if cb_item == 1 {
            // TODO(tarcieri): get rid of memcpy and pointers, replace with slices!
            #[allow(trivial_casts)]
            memcpy(
                &mut flags_1 as (*mut u8) as (*mut c_void),
                p_item as (*const c_void),
                cb_item,
            );
        } else {
            error!("admin data flags are an incorrect size = {}", cb_item,);
        }

        // remove any existing salt
        ykrc = _set_metadata_item(
            data.as_mut_ptr(),
            &mut cb_data,
            CB_OBJ_MAX,
            TAG_ADMIN_SALT,
            ptr::null_mut(),
            0,
        );

        if let Err(e) = &ykrc {
            error!("could not unset derived mgm salt, err = {}", e)
        }
    }

    flags_1 |= ADMIN_FLAGS_1_PROTECTED_MGM;

    ykrc = _set_metadata_item(
        data.as_mut_ptr(),
        &mut cb_data,
        CB_OBJ_MAX,
        TAG_ADMIN_FLAGS_1,
        &mut flags_1,
        mem::size_of_val(&flags_1),
    );

    if let Err(e) = &ykrc {
        error!("could not set admin flags item, err = {}", e);
    } else {
        ykrc = _write_metadata(state, TAG_ADMIN, data.as_mut_ptr(), cb_data);
        if let Err(e) = ykrc.as_ref() {
            error!("could not write admin data, err = {}", e);
        }
    }

    let _ = _ykpiv_end_transaction(state);
    Ok(())
}

/// Reset
pub unsafe fn ykpiv_util_reset(state: &mut YubiKey) -> Result<(), ErrorKind> {
    let templ = [0, YKPIV_INS_RESET, 0, 0];
    let mut data = [0u8; 255];
    let mut recv_len = data.len();
    let mut sw: i32 = 0;

    let res = ykpiv_transfer_data(
        state,
        templ.as_ptr(),
        ptr::null(),
        0,
        data.as_mut_ptr(),
        &mut recv_len,
        &mut sw,
    );

    match (res.is_ok(), sw) {
        (true, SW_SUCCESS) => Ok(()),
        _ => Err(ErrorKind::GenericError),
    }
}

/// Get object for slot
pub fn ykpiv_util_slot_object(slot: u8) -> u32 {
    match slot {
        YKPIV_KEY_AUTHENTICATION => YKPIV_OBJ_AUTHENTICATION,
        YKPIV_KEY_SIGNATURE => YKPIV_OBJ_SIGNATURE,
        YKPIV_KEY_KEYMGM => YKPIV_OBJ_KEY_MANAGEMENT,
        YKPIV_KEY_CARDAUTH => YKPIV_OBJ_CARD_AUTH,
        YKPIV_KEY_ATTESTATION => YKPIV_OBJ_ATTESTATION,
        _ => {
            if slot >= YKPIV_KEY_RETIRED1 && (slot <= YKPIV_KEY_RETIRED20) {
                YKPIV_OBJ_RETIRED1 + (slot - YKPIV_KEY_RETIRED1) as u32
            } else {
                0
            }
        }
    }
}

/// Read certificate
unsafe fn _read_certificate(
    state: &mut YubiKey,
    slot: u8,
    buf: *mut u8,
    buf_len: *mut usize,
) -> Result<(), ErrorKind> {
    let mut ptr: *mut u8;
    let object_id = ykpiv_util_slot_object(slot) as i32;
    let mut len: usize = 0;

    if object_id == -1 {
        return Err(ErrorKind::InvalidObject);
    }

    if _ykpiv_fetch_object(state, object_id, buf, buf_len).is_ok() {
        ptr = buf;

        if *buf_len < CB_OBJ_TAG_MIN {
            *buf_len = 0;
            return Ok(());
        } else if *{
            let _old = ptr;
            ptr = ptr.offset(1);
            _old
        } == TAG_CERT
        {
            ptr = ptr.add(_ykpiv_get_length(ptr, &mut len));

            if len > *buf_len - (ptr as isize - buf as isize) as usize {
                *buf_len = 0;
                return Ok(());
            } else {
                memmove(buf as (*mut c_void), ptr as (*const c_void), len);
                *buf_len = len;
            }
        }
    } else {
        *buf_len = 0;
    }

    Ok(())
}

/// Write certificate
unsafe fn _write_certificate(
    state: &mut YubiKey,
    slot: u8,
    data: *mut u8,
    data_len: usize,
    certinfo: u8,
) -> Result<(), ErrorKind> {
    let mut buf = [0u8; CB_OBJ_MAX];
    let object_id = ykpiv_util_slot_object(slot) as i32;
    let mut offset: usize = 0;
    let mut req_len: usize;

    if object_id == -1 {
        return Err(ErrorKind::InvalidObject);
    }

    if data.is_null() || data_len == 0 {
        if !data.is_null() || data_len != 0 {
            return Err(ErrorKind::GenericError);
        }

        return _ykpiv_save_object(state, object_id, ptr::null_mut(), 0);
    }

    req_len = 1 /* cert tag */ + 3 /* compression tag + data*/ + 2 /* lrc */;
    req_len += _ykpiv_set_length(buf.as_mut_ptr(), data_len);
    req_len += data_len;

    if req_len < data_len || req_len > _obj_size_max(state) {
        return Err(ErrorKind::SizeError);
    }

    buf[offset] = TAG_CERT;
    offset += 1;
    offset += _ykpiv_set_length(buf.as_mut_ptr().add(offset), data_len);

    memcpy(
        buf.as_mut_ptr().add(offset) as (*mut c_void),
        data as (*const c_void),
        data_len,
    );

    offset += data_len;

    // write compression info and LRC trailer
    buf[offset] = TAG_CERT_COMPRESS;
    buf[offset + 1] = 0x01;
    buf[offset + 2] = if certinfo == YKPIV_CERTINFO_GZIP {
        0x01
    } else {
        0x00
    };
    buf[offset + 3] = TAG_CERT_LRC;
    buf[offset + 4] = 00;

    offset += 5;

    _ykpiv_save_object(state, object_id, buf.as_mut_ptr(), offset)
}

/// Get metadata item
unsafe fn _get_metadata_item(
    data: *mut u8,
    cb_data: usize,
    tag: u8,
    pp_item: *mut *mut u8,
    pcb_item: *mut usize,
) -> Result<(), ErrorKind> {
    let mut p_temp: *mut u8 = data;
    let mut cb_temp: usize = 0;
    let mut tag_temp: u8;

    if data.is_null() || pp_item.is_null() || pcb_item.is_null() {
        return Err(ErrorKind::GenericError);
    }

    *pp_item = ptr::null_mut();
    *pcb_item = 0;

    while p_temp < data.add(cb_data) {
        tag_temp = *p_temp;
        p_temp = p_temp.add(1);

        if !_ykpiv_has_valid_length(p_temp, data.add(cb_data) as usize - p_temp as usize) {
            return Err(ErrorKind::SizeError);
        }

        p_temp = p_temp.add(_ykpiv_get_length(p_temp, &mut cb_temp));

        if tag_temp == tag {
            break;
        }

        p_temp = p_temp.add(cb_temp);
    }

    if p_temp < data.add(cb_data) {
        *pp_item = p_temp;
        *pcb_item = cb_temp;

        Ok(())
    } else {
        Err(ErrorKind::GenericError)
    }
}

/// Get length size
fn _get_length_size(length: usize) -> i32 {
    if length < 0x80 {
        1
    } else if length < 0xff {
        2
    } else {
        3
    }
}

/// Set metadata item
unsafe fn _set_metadata_item(
    data: *mut u8,
    pcb_data: *mut usize,
    cb_data_max: usize,
    tag: u8,
    p_item: *mut u8,
    cb_item: usize,
) -> Result<(), ErrorKind> {
    let mut p_temp: *mut u8 = data;
    let mut cb_temp: usize = 0;
    let mut tag_temp: u8 = 0;
    let mut cb_len: usize = 0;
    let p_next: *mut u8;
    let cb_moved: isize;

    if data.is_null() || pcb_data.is_null() {
        return Err(ErrorKind::GenericError);
    }

    while p_temp < data.add(*pcb_data) {
        tag_temp = *p_temp;
        p_temp = p_temp.add(1);

        cb_len = _ykpiv_get_length(p_temp, &mut cb_temp);
        p_temp = p_temp.add(cb_len);

        if tag_temp == tag {
            break;
        }

        p_temp = p_temp.add(cb_temp);
    }

    if tag_temp != tag {
        if cb_item == 0 {
            return Ok(());
        }

        p_temp = data.add(*pcb_data);
        cb_len = _get_length_size(cb_item) as (usize);

        if (*pcb_data).wrapping_add(cb_len).wrapping_add(cb_item) > cb_data_max {
            return Err(ErrorKind::GenericError);
        }

        *p_temp = tag;
        p_temp = p_temp.add(1);
        p_temp = p_temp.add(_ykpiv_set_length(p_temp, cb_item));

        memcpy(p_temp as (*mut c_void), p_item as (*const c_void), cb_item);
        *pcb_data += 1 + cb_len + cb_item;

        return Ok(());
    }

    if cb_temp == cb_item {
        memcpy(p_temp as (*mut c_void), p_item as (*const c_void), cb_item);
        return Ok(());
    }

    p_next = p_temp.add(cb_temp);
    cb_moved = cb_item as (isize) - cb_temp as (isize)
        + (if cb_item != 0 {
            _get_length_size(cb_item)
        } else {
            -1
        } as (isize)
            - cb_len as (isize));

    if (*pcb_data + cb_moved as usize) > cb_data_max {
        return Err(ErrorKind::GenericError);
    }

    memmove(
        p_next.offset(cb_moved) as (*mut c_void),
        p_next as (*const c_void),
        (*pcb_data).wrapping_sub(
            ((p_next as (isize)).wrapping_sub(data as (isize)) / mem::size_of::<u8>() as (isize))
                as (usize),
        ),
    );

    *pcb_data = (*pcb_data).wrapping_add(cb_moved as (usize));

    if cb_item != 0 {
        p_temp = p_temp.offset(-(cb_len as (isize)));
        p_temp = p_temp.add(_ykpiv_set_length(p_temp, cb_item));
        memcpy(p_temp as (*mut c_void), p_item as (*const c_void), cb_item);
    }

    Ok(())
}

/// Read metadata
unsafe fn _read_metadata(
    state: &mut YubiKey,
    tag: u8,
    data: *mut u8,
    pcb_data: *mut usize,
) -> Result<(), ErrorKind> {
    let mut p_temp: *mut u8;
    let mut cb_temp: usize;

    if data.is_null() || pcb_data.is_null() || YKPIV_OBJ_MAX_SIZE > *pcb_data {
        return Err(ErrorKind::GenericError);
    }

    let obj_id = match tag {
        TAG_ADMIN => YKPIV_OBJ_ADMIN_DATA,
        TAG_PROTECTED => YKPIV_OBJ_PRINTED,
        _ => return Err(ErrorKind::InvalidObject),
    } as i32;

    cb_temp = *pcb_data;
    *pcb_data = 0;

    _ykpiv_fetch_object(state, obj_id, data, &mut cb_temp)?;

    if cb_temp < CB_OBJ_TAG_MIN {
        return Err(ErrorKind::GenericError);
    }
    p_temp = data;

    if tag as (i32)
        != *{
            let _old = p_temp;
            p_temp = p_temp.offset(1);
            _old
        } as (i32)
    {
        return Err(ErrorKind::GenericError);
    }

    p_temp = p_temp.add(_ykpiv_get_length(p_temp, pcb_data));

    if *pcb_data > cb_temp - (p_temp as isize - data as isize) as usize {
        *pcb_data = 0;
        return Err(ErrorKind::GenericError);
    }

    memmove(data as (*mut c_void), p_temp as (*const c_void), *pcb_data);
    Ok(())
}

/// Write metadata
unsafe fn _write_metadata(
    state: &mut YubiKey,
    tag: u8,
    data: *mut u8,
    cb_data: usize,
) -> Result<(), ErrorKind> {
    let mut buf = [0u8; CB_OBJ_MAX]; // XXX REMEMBER TO ZERO
    let mut p_temp: *mut u8 = buf.as_mut_ptr();

    if cb_data > _obj_size_max(state) - CB_OBJ_TAG_MAX {
        return Err(ErrorKind::GenericError);
    }

    let obj_id = match tag {
        TAG_ADMIN => YKPIV_OBJ_ADMIN_DATA,
        TAG_PROTECTED => YKPIV_OBJ_PRINTED,
        _ => return Err(ErrorKind::InvalidObject),
    } as i32;

    if data.is_null() || cb_data == 0 {
        return _ykpiv_save_object(state, obj_id, ptr::null_mut(), 0);
    }

    *{
        let _old = p_temp;
        p_temp = p_temp.offset(1);
        _old
    } = tag;

    p_temp = p_temp.add(_ykpiv_set_length(p_temp, cb_data));
    memcpy(p_temp as (*mut c_void), data as (*const c_void), cb_data);
    p_temp = p_temp.add(cb_data);

    _ykpiv_save_object(
        state,
        obj_id,
        buf.as_mut_ptr(),
        ((p_temp as (isize)).wrapping_sub(buf.as_mut_ptr() as (isize))
            / mem::size_of::<u8>() as (isize)) as (usize),
    )
}
