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
use libc::{c_char, calloc, free, memcpy, memmove, realloc, time};
use std::{ffi::CString, mem, os::raw::c_void, ptr};
use zeroize::Zeroize;

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
pub unsafe fn ykpiv_util_get_cardid(state: *mut YubiKey, cardid: *mut CardId) -> ErrorKind {
    let mut buf = [0u8; CB_OBJ_MAX];
    let mut len = buf.len();
    let mut res: ErrorKind = ErrorKind::Ok;

    if cardid.is_null() {
        return ErrorKind::GenericError;
    }

    if _ykpiv_begin_transaction(state) != ErrorKind::Ok {
        return ErrorKind::PcscError;
    }

    if _ykpiv_ensure_application_selected(state) == ErrorKind::Ok {
        res = _ykpiv_fetch_object(state, YKPIV_OBJ_CHUID as i32, buf.as_mut_ptr(), &mut len);

        if res == ErrorKind::Ok {
            if len != CHUID_TMPL.len() {
                res = ErrorKind::GenericError;
            } else {
                memcpy(
                    (*cardid).0.as_mut_ptr() as (*mut c_void),
                    buf.as_mut_ptr().add(CHUID_GUID_OFFS) as (*const c_void),
                    YKPIV_CARDID_SIZE,
                );
            }
        }
    }

    _ykpiv_end_transaction(state);
    res
}

/// Set Card ID
pub unsafe fn ykpiv_util_set_cardid(state: *mut YubiKey, cardid: *const CardId) -> ErrorKind {
    let mut id = [0u8; YKPIV_CARDID_SIZE];
    let mut buf = [0u8; CHUID_TMPL.len()];
    let mut res = ErrorKind::Ok;

    if state.is_null() {
        return ErrorKind::GenericError;
    }

    if cardid.is_null() {
        if _ykpiv_prng_generate(id.as_mut_ptr(), id.len()) != PRngErrorKind::Ok {
            return ErrorKind::RandomnessError;
        }
    } else {
        memcpy(
            id.as_mut_ptr() as (*mut c_void),
            (*cardid).0.as_ptr() as (*const c_void),
            id.len(),
        );
    }

    if _ykpiv_begin_transaction(state) != ErrorKind::Ok {
        return ErrorKind::PcscError;
    }

    if _ykpiv_ensure_application_selected(state) == ErrorKind::Ok {
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

    _ykpiv_end_transaction(state);
    res
}

/// Cardholder Capability Container (CCC) Identifier
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CCCID([u8; 14]);

/// Get Cardholder Capability Container (CCC) ID
pub unsafe fn ykpiv_util_get_cccid(state: *mut YubiKey, ccc: *mut CCCID) -> ErrorKind {
    let mut res: ErrorKind = ErrorKind::Ok;
    let mut buf = [0u8; CB_OBJ_MAX];
    let mut len = buf.len();

    if ccc.is_null() {
        return ErrorKind::GenericError;
    }

    if _ykpiv_begin_transaction(state) != ErrorKind::Ok {
        return ErrorKind::PcscError;
    }

    if _ykpiv_ensure_application_selected(state) == ErrorKind::Ok {
        res = _ykpiv_fetch_object(
            state,
            YKPIV_OBJ_CAPABILITY as i32,
            buf.as_mut_ptr(),
            &mut len,
        );

        if res == ErrorKind::Ok {
            if len != CCC_TMPL.len() {
                _ykpiv_end_transaction(state);
                return ErrorKind::GenericError;
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
pub unsafe fn ykpiv_util_set_cccid(state: *mut YubiKey, ccc: *const CCCID) -> ErrorKind {
    let mut res: ErrorKind = ErrorKind::Ok;
    let mut id = [0u8; 14];
    let mut buf = [0u8; 51];
    let len: usize;

    if state.is_null() {
        return ErrorKind::GenericError;
    }

    if ccc.is_null() {
        if _ykpiv_prng_generate(id.as_mut_ptr(), id.len()) != PRngErrorKind::Ok {
            return ErrorKind::RandomnessError;
        }
    } else {
        memcpy(
            id.as_mut_ptr() as (*mut c_void),
            (*ccc).0.as_ptr() as (*const c_void),
            id.len(),
        );
    }

    if _ykpiv_begin_transaction(state) != ErrorKind::Ok {
        return ErrorKind::PcscError;
    }

    if _ykpiv_ensure_application_selected(state) == ErrorKind::Ok {
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

    _ykpiv_end_transaction(state);
    res
}

/// Get YubiKey device model
pub unsafe fn ykpiv_util_devicemodel(state: *mut YubiKey) -> u32 {
    if state.is_null() || (*state).context == 0 || (*state).context == -1 {
        DEVTYPE_UNKNOWN
    } else if (*state).is_neo {
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
    state: *mut YubiKey,
    key_count: *mut u8,
    data: *mut *mut YkPivKey,
    data_len: *mut usize,
) -> ErrorKind {
    let mut _currentBlock;
    let mut res: ErrorKind = ErrorKind::Ok;
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
        return ErrorKind::GenericError;
    }

    if _ykpiv_begin_transaction(state) != ErrorKind::Ok {
        return ErrorKind::PcscError;
    }

    if _ykpiv_ensure_application_selected(state) == ErrorKind::Ok {
        *key_count = 0;
        *data = ptr::null_mut();
        *data_len = 0;

        p_data = calloc(CB_PAGE, 1) as (*mut u8);

        if p_data.is_null() {
            _ykpiv_end_transaction(state);
            return ErrorKind::MemoryError;
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

            if res == ErrorKind::Ok && (cb_buf > 0) {
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
            res = ErrorKind::Ok;
        } else {
            res = ErrorKind::MemoryError;
        }
    }

    if !p_data.is_null() {
        free(p_data as (*mut c_void));
    }

    _ykpiv_end_transaction(state);
    res
}

/// Read certificate
pub unsafe fn ykpiv_util_read_cert(
    state: *mut YubiKey,
    slot: u8,
    data: *mut *mut u8,
    data_len: *mut usize,
) -> ErrorKind {
    let mut res: ErrorKind = ErrorKind::Ok;
    let mut buf = [0u8; YKPIV_OBJ_MAX_SIZE];
    let mut cb_buf: usize = buf.len();

    if data.is_null() || data_len.is_null() {
        return ErrorKind::GenericError;
    }

    if _ykpiv_begin_transaction(state) != ErrorKind::Ok {
        return ErrorKind::PcscError;
    }

    if _ykpiv_ensure_application_selected(state) == ErrorKind::Ok {
        *data = ptr::null_mut();
        *data_len = 0;
        res = _read_certificate(state, slot, buf.as_mut_ptr(), &mut cb_buf);
        if res == ErrorKind::Ok {
            if cb_buf == 0 {
                *data = ptr::null_mut();
                *data_len = 0;
            } else if {
                *data = calloc(cb_buf, 1) as *mut u8;
                *data
            }
            .is_null()
            {
                res = ErrorKind::MemoryError;
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

    _ykpiv_end_transaction(state);
    res
}

/// Write certificate
pub unsafe fn ykpiv_util_write_cert(
    state: *mut YubiKey,
    slot: u8,
    data: *mut u8,
    data_len: usize,
    certinfo: u8,
) -> ErrorKind {
    let mut res: ErrorKind = ErrorKind::Ok;

    if _ykpiv_begin_transaction(state) != ErrorKind::Ok {
        return ErrorKind::PcscError;
    }

    if _ykpiv_ensure_application_selected(state) == ErrorKind::Ok {
        res = _write_certificate(state, slot, data, data_len, certinfo);
    }

    _ykpiv_end_transaction(state);
    res
}

/// Delete certificate
pub unsafe fn ykpiv_util_delete_cert(state: *mut YubiKey, slot: u8) -> ErrorKind {
    ykpiv_util_write_cert(state, slot, ptr::null_mut(), 0, 0)
}

/// Block PUK
pub unsafe fn ykpiv_util_block_puk(state: *mut YubiKey) -> ErrorKind {
    let mut _currentBlock;
    let mut res: ErrorKind = ErrorKind::Ok;
    let mut puk = [0x30, 0x42, 0x41, 0x44, 0x46, 0x30, 0x30, 0x44];
    let mut tries: i32 = -1;
    let mut data = [0u8; YKPIV_OBJ_MAX_SIZE];
    let mut cb_data: usize = data.len();
    let mut p_item: *mut u8 = ptr::null_mut();
    let mut cb_item: usize = 0;
    let mut flags: u8 = 0;

    if state.is_null() {
        return ErrorKind::GenericError;
    }

    if _ykpiv_begin_transaction(state) != ErrorKind::Ok {
        return ErrorKind::PcscError;
    }

    if _ykpiv_ensure_application_selected(state) == ErrorKind::Ok {
        _currentBlock = 20;
    } else {
        _currentBlock = 3;
    }

    loop {
        if _currentBlock == 3 {
            if tries != 0 {
                res = ykpiv_change_puk(
                    state,
                    puk.as_ptr(),
                    mem::size_of::<*const c_char>(),
                    puk.as_ptr(),
                    mem::size_of::<*const c_char>(),
                    &mut tries,
                );

                if res == ErrorKind::Ok {
                    let _rhs = 1;
                    let mut _lhs = &mut puk[0];
                    *_lhs += _rhs;
                    _currentBlock = 3;
                } else {
                    if res != ErrorKind::PinLocked {
                        _currentBlock = 3;
                        continue;
                    }
                    tries = 0;
                    res = ErrorKind::Ok;
                    _currentBlock = 3;
                }
            } else {
                let res = _read_metadata(state, TAG_ADMIN, data.as_mut_ptr(), &mut cb_data);

                if res == ErrorKind::Ok {
                    let res = _get_metadata_item(
                        data.as_mut_ptr(),
                        cb_data,
                        TAG_ADMIN_FLAGS_1,
                        &mut p_item,
                        &mut cb_item,
                    );

                    if res == ErrorKind::Ok {
                        if cb_item == 1 {
                            // TODO(tarcieri): get rid of memcpy and pointers, replace with slices!
                            #[allow(trivial_casts)]
                            memcpy(
                                &mut flags as *mut u8 as *mut c_void,
                                p_item as (*const c_void),
                                cb_item,
                            );
                        } else if (*state).verbose != 0 {
                            eprintln!("admin flags exist, but are incorrect size = {}", cb_item,);
                        }
                    }
                }

                flags |= 0x1;

                if _set_metadata_item(
                    data.as_mut_ptr(),
                    &mut cb_data,
                    CB_OBJ_MAX,
                    TAG_ADMIN_FLAGS_1,
                    &mut flags,
                    1,
                ) != ErrorKind::Ok
                {
                    if (*state).verbose == 0 {
                        _currentBlock = 20;
                        continue;
                    }
                    eprintln!("could not set admin flags");
                    _currentBlock = 20;
                } else {
                    if _write_metadata(state, 0x80u8, data.as_mut_ptr(), cb_data) == ErrorKind::Ok {
                        _currentBlock = 20;
                        continue;
                    }
                    if (*state).verbose == 0 {
                        _currentBlock = 20;
                        continue;
                    }
                    eprintln!("could not write admin metadata");
                    _currentBlock = 20;
                }
            }
        } else {
            _ykpiv_end_transaction(state);
            return res;
        }
    }
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
    state: *mut YubiKey,
    containers: *mut *mut YkPivContainer,
    n_containers: *mut usize,
) -> ErrorKind {
    let mut res: ErrorKind = ErrorKind::Ok;
    let mut buf = [0u8; YKPIV_OBJ_MAX_SIZE];
    let mut cb_buf: usize = buf.len();
    let mut len: usize = 0;
    let mut ptr: *mut u8;

    if containers.is_null() || n_containers.is_null() {
        res = ErrorKind::GenericError;
    }

    if _ykpiv_begin_transaction(state) != ErrorKind::Ok {
        return ErrorKind::PcscError;
    }

    if _ykpiv_ensure_application_selected(state) == ErrorKind::Ok {
        *containers = ptr::null_mut();
        *n_containers = 0;

        res = _ykpiv_fetch_object(
            state,
            YKPIV_OBJ_MSCMAP as i32,
            buf.as_mut_ptr(),
            &mut cb_buf,
        );

        if res != ErrorKind::Ok {
            _ykpiv_end_transaction(state);
            return res;
        }

        ptr = buf.as_mut_ptr();

        if cb_buf < CB_OBJ_TAG_MIN {
            _ykpiv_end_transaction(state);
            return ErrorKind::Ok;
        }

        if *ptr == TAG_MSCMAP {
            ptr = ptr.add(1);
            ptr = ptr.add(_ykpiv_get_length(ptr, &mut len));

            if len > cb_buf - (ptr as isize - buf.as_mut_ptr() as isize) as usize {
                _ykpiv_end_transaction(state);
                return ErrorKind::Ok;
            }

            *containers = calloc(len, 1) as (*mut YkPivContainer);

            if (*containers).is_null() {
                res = ErrorKind::MemoryError;
            } else {
                memcpy(*containers as (*mut c_void), ptr as (*const c_void), len);
                *n_containers = len.wrapping_div(mem::size_of::<YkPivContainer>());
            }
        }
    }

    res
}

/// Get max object size
unsafe fn _obj_size_max(state: *mut YubiKey) -> usize {
    if !state.is_null() && (*state).is_neo {
        2048 - 9
    } else {
        CB_OBJ_MAX
    }
}

/// Write mscmap
pub unsafe fn ykpiv_util_write_mscmap(
    state: *mut YubiKey,
    containers: *mut YkPivContainer,
    n_containers: usize,
) -> ErrorKind {
    let mut res = ErrorKind::Ok;
    let mut buf = [0u8; CB_OBJ_MAX];
    let mut offset: usize = 0;
    let data_len: usize = n_containers.wrapping_mul(mem::size_of::<YkPivContainer>());

    if _ykpiv_begin_transaction(state) != ErrorKind::Ok {
        return ErrorKind::PcscError;
    }

    if _ykpiv_ensure_application_selected(state) == ErrorKind::Ok {
        if containers.is_null() || n_containers == 0 {
            if !containers.is_null() || n_containers != 0 {
                res = ErrorKind::GenericError;
            } else {
                res = _ykpiv_save_object(state, YKPIV_OBJ_MSCMAP as i32, ptr::null_mut(), 0);
            }

            _ykpiv_end_transaction(state);
            return res;
        }

        let req_len = 1 + _ykpiv_set_length(buf.as_mut_ptr(), data_len) + data_len;

        if req_len > _obj_size_max(state) {
            _ykpiv_end_transaction(state);
            return ErrorKind::SizeError;
        }

        buf[offset] = 0x81;
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

    _ykpiv_end_transaction(state);
    res
}

/// Read msroots
pub unsafe fn ykpiv_util_read_msroots(
    state: *mut YubiKey,
    data: *mut *mut u8,
    data_len: *mut usize,
) -> ErrorKind {
    let mut _currentBlock;
    let mut res = ErrorKind::Ok;
    let mut buf = [0u8; YKPIV_OBJ_MAX_SIZE];
    let mut cb_buf: usize;
    let mut len: usize = 0;
    let mut ptr: *mut u8;
    let mut object_id: i32;
    let mut tag: u8;
    let mut p_data: *mut u8 = ptr::null_mut();
    let mut p_temp: *mut u8;
    let mut cb_data: usize;
    let mut cb_realloc: usize;
    let mut offset: usize = 0;

    if data.is_null() || data_len.is_null() {
        return ErrorKind::GenericError;
    }

    if _ykpiv_begin_transaction(state) != ErrorKind::Ok {
        return ErrorKind::PcscError;
    }

    if _ykpiv_ensure_application_selected(state) == ErrorKind::Ok {
        *data = ptr::null_mut();
        *data_len = 0;
        cb_data = _obj_size_max(state);
        p_data = calloc(cb_data, 1) as (*mut u8);

        if p_data.is_null() {
            res = ErrorKind::MemoryError;
        } else {
            object_id = YKPIV_OBJ_MSROOTS1 as i32;
            loop {
                if object_id > YKPIV_OBJ_MSROOTS5 as i32 {
                    _currentBlock = 15;
                    break;
                }
                cb_buf = buf.len();

                res = _ykpiv_fetch_object(state, object_id, buf.as_mut_ptr(), &mut cb_buf);

                if res != ErrorKind::Ok {
                    _currentBlock = 21;
                    break;
                }

                ptr = buf.as_mut_ptr();
                if cb_buf < 2 {
                    _currentBlock = 19;
                    break;
                }

                tag = *{
                    let _old = ptr;
                    ptr = ptr.offset(1);
                    _old
                };

                if tag != 0x82 && (tag != 0x83 || object_id == YKPIV_OBJ_MSROOTS5 as i32) {
                    _currentBlock = 18;
                    break;
                }

                ptr = ptr.add(_ykpiv_get_length(ptr, &mut len));

                if len > cb_buf - (ptr as isize - buf.as_mut_ptr() as isize) as usize {
                    _currentBlock = 17;
                    break;
                }

                cb_realloc = if len > cb_data.wrapping_sub(offset) {
                    len.wrapping_sub(cb_data.wrapping_sub(offset))
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
                if tag == 0x82 {
                    _currentBlock = 15;
                    break;
                }
                object_id += 1;
            }
            if _currentBlock == 21 {
            } else if _currentBlock == 15 {
                *data = p_data;
                p_data = ptr::null_mut();
                *data_len = offset;
                res = ErrorKind::Ok;
            } else if _currentBlock == 16 {
                res = ErrorKind::MemoryError;
            } else {
                res = ErrorKind::Ok;
            }
        }
    }

    if !p_data.is_null() {
        free(p_data as (*mut c_void));
    }

    _ykpiv_end_transaction(state);
    res
}

/// Write msroots
pub unsafe fn ykpiv_util_write_msroots(
    state: *mut YubiKey,
    data: *mut u8,
    data_len: usize,
) -> ErrorKind {
    let mut res: ErrorKind = ErrorKind::Ok;
    let mut buf = [0u8; CB_OBJ_MAX];
    let mut offset: usize;
    let mut data_offset: usize = 0;
    let mut data_chunk: usize;
    let n_objs: usize;
    let cb_obj_max = _obj_size_max(state);

    if _ykpiv_begin_transaction(state) != ErrorKind::Ok {
        return ErrorKind::PcscError;
    }

    if _ykpiv_ensure_application_selected(state) == ErrorKind::Ok {
        if data.is_null() || data_len == 0 {
            if !data.is_null() || data_len != 0 {
                res = ErrorKind::GenericError;
            } else {
                res = _ykpiv_save_object(state, YKPIV_OBJ_MSROOTS1 as i32, ptr::null_mut(), 0);
            }

            _ykpiv_end_transaction(state);
            return res;
        }

        n_objs = (data_len / (cb_obj_max - 4)) + 1;

        if n_objs > 5 {
            _ykpiv_end_transaction(state);
            return ErrorKind::SizeError;
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

            if res != ErrorKind::Ok {
                break;
            }

            data_offset = data_offset.wrapping_add(data_chunk);
        }
    }

    _ykpiv_end_transaction(state);
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
    state: *mut YubiKey,
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
) -> ErrorKind {
    let mut res: ErrorKind = ErrorKind::Ok;
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

    if state.is_null() {
        return ErrorKind::ArgumentError;
    }

    if ykpiv_util_devicemodel(state) == DEVTYPE_YK4
        && (algorithm == YKPIV_ALGO_RSA1024 || algorithm == YKPIV_ALGO_RSA2048)
        && (*state).ver.major == 4
        && ((*state).ver.minor < 3 || (*state).ver.minor == 3 && ((*state).ver.patch < 5))
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

        eprintln!(
            "YubiKey serial number {} is affected by vulnerability CVE-2017-15361 \
             (ROCA) and should be replaced. On-chip key generation {}  See \
             YSA-2017-01 <https://www.yubico.com/support/security-advisories/ysa-2017-01/> \
             for additional information on device replacement and mitigation assistance",
            (*state).serial,
            psz_msg
        );

        if !setting_roca.value {
            return ErrorKind::NotSupported;
        }
    }

    match algorithm {
        YKPIV_ALGO_RSA1024 | YKPIV_ALGO_RSA2048 => {
            if point.is_null() || point_len.is_null() {
                if (*state).verbose != 0 {
                    eprintln!("Invalid output parameter for ECC algorithm");
                }
                return ErrorKind::GenericError;
            } else {
                *point = ptr::null_mut();
                *point_len = 0;
            }
        }
        YKPIV_ALGO_ECCP256 | YKPIV_ALGO_ECCP384 => {
            if modulus.is_null() || modulus_len.is_null() || exp.is_null() || exp_len.is_null() {
                if (*state).verbose != 0 {
                    eprintln!("Invalid output parameter for RSA algorithm",);
                }
                return ErrorKind::GenericError;
            } else {
                *modulus = ptr::null_mut();
                *modulus_len = 0;
                *exp = ptr::null_mut();
                *exp_len = 0;
            }
        }
        _ => {
            if (*state).verbose != 0 {
                eprintln!("Invalid algorithm specified");
            }

            return ErrorKind::GenericError;
        }
    }

    if _ykpiv_begin_transaction(state) != ErrorKind::Ok {
        return ErrorKind::PcscError;
    }

    if _ykpiv_ensure_application_selected(state) == ErrorKind::Ok {
        templ[3] = slot;
        *{
            let _old = in_ptr;
            in_ptr = in_ptr.offset(1);
            _old
        } = 0xac;

        *{
            let _old = in_ptr;
            in_ptr = in_ptr.offset(1);
            _old
        } = 3;

        *{
            let _old = in_ptr;
            in_ptr = in_ptr.offset(1);
            _old
        } = YKPIV_ALGO_TAG;

        *{
            let _old = in_ptr;
            in_ptr = in_ptr.offset(1);
            _old
        } = 1;

        *{
            let _old = in_ptr;
            in_ptr = in_ptr.offset(1);
            _old
        } = algorithm;

        if in_data[4] == 0 {
            res = ErrorKind::AlgorithmError;
            if (*state).verbose != 0 {
                eprintln!("Unexpected algorithm.\n");
            }
        } else {
            if pin_policy != YKPIV_PINPOLICY_DEFAULT {
                let _rhs = 3;
                let _lhs = &mut in_data[1];
                *_lhs = (*_lhs as (i32) + _rhs) as (u8);
                *{
                    let _old = in_ptr;
                    in_ptr = in_ptr.offset(1);
                    _old
                } = YKPIV_PINPOLICY_TAG;
                *{
                    let _old = in_ptr;
                    in_ptr = in_ptr.offset(1);
                    _old
                } = 1u8;
                *{
                    let _old = in_ptr;
                    in_ptr = in_ptr.offset(1);
                    _old
                } = pin_policy;
            }

            if touch_policy != YKPIV_TOUCHPOLICY_DEFAULT {
                let _rhs = 3i32;
                let _lhs = &mut in_data[1];
                *_lhs = (*_lhs as (i32) + _rhs) as (u8);
                *{
                    let _old = in_ptr;
                    in_ptr = in_ptr.offset(1);
                    _old
                } = YKPIV_TOUCHPOLICY_TAG;
                *{
                    let _old = in_ptr;
                    in_ptr = in_ptr.offset(1);
                    _old
                } = 1u8;
                *{
                    let _old = in_ptr;
                    in_ptr = in_ptr.offset(1);
                    _old
                } = touch_policy;
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

            if res != ErrorKind::Ok {
                if (*state).verbose != 0 {
                    eprintln!("Failed to communicate.");
                }
            } else if sw != SW_SUCCESS {
                if (*state).verbose != 0 {
                    eprint!("Failed to generate new key (");
                }

                match sw {
                    SW_ERR_INCORRECT_SLOT => {
                        res = ErrorKind::KeyError;
                        if (*state).verbose != 0 {
                            eprintln!("incorrect slot)");
                        }
                    }
                    SW_ERR_INCORRECT_PARAM => {
                        res = ErrorKind::AlgorithmError;
                        if (*state).verbose != 0 {
                            if pin_policy as (i32) != 0i32 {
                                eprintln!("pin policy not supported?)",);
                            } else if touch_policy as (i32) != 0i32 {
                                eprintln!("touch policy not supported?)",);
                            } else {
                                eprintln!("algorithm not supported?)",);
                            }
                        }
                    }
                    SW_ERR_SECURITY_STATUS => {
                        res = ErrorKind::AuthenticationError;
                        if (*state).verbose != 0 {
                            eprintln!("not authenticated)");
                        }
                    }
                    _ => {
                        res = ErrorKind::GenericError;
                        if (*state).verbose != 0 {
                            eprintln!("error {:x})", sw);
                        }
                    }
                }
            } else if algorithm == YKPIV_ALGO_RSA1024 || algorithm == YKPIV_ALGO_RSA2048 {
                let mut data_ptr: *mut u8 = data.as_mut_ptr().offset(5);
                let mut len: usize = 0;
                if *data_ptr != TAG_RSA_MODULUS {
                    if (*state).verbose != 0 {
                        eprintln!("Failed to parse public key structure (modulus).");
                    }
                    res = ErrorKind::ParseError;
                } else {
                    data_ptr = data_ptr.add(1);
                    data_ptr = data_ptr.add(_ykpiv_get_length(data_ptr, &mut len));
                    cb_modulus = len;
                    ptr_modulus = calloc(cb_modulus, 1) as *mut u8;
                    if ptr_modulus.is_null() {
                        if (*state).verbose != 0 {
                            eprintln!("Failed to allocate memory for modulus.");
                        }
                        res = ErrorKind::MemoryError;
                    } else {
                        memcpy(
                            ptr_modulus as *mut c_void,
                            data_ptr as *const c_void,
                            cb_modulus,
                        );
                        data_ptr = data_ptr.add(len);
                        if *data_ptr != TAG_RSA_EXP {
                            if (*state).verbose != 0 {
                                eprintln!(
                                    "Failed to parse public key structure (public exponent)."
                                );
                            }
                            res = ErrorKind::ParseError;
                        } else {
                            data_ptr = data_ptr.add(1);
                            data_ptr = data_ptr.add(_ykpiv_get_length(data_ptr, &mut len));
                            cb_exp = len;
                            ptr_exp = calloc(cb_exp, 1) as *mut u8;
                            if ptr_exp.is_null() {
                                if (*state).verbose != 0 {
                                    eprintln!("Failed to allocate memory for public exponent.");
                                }
                                res = ErrorKind::MemoryError;
                            } else {
                                memcpy(
                                    ptr_exp as (*mut c_void),
                                    data_ptr as (*const c_void),
                                    cb_exp,
                                );
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

                if *{
                    let _old = data_ptr;
                    data_ptr = data_ptr.offset(1);
                    _old
                } != TAG_ECC_POINT
                {
                    if (*state).verbose != 0 {
                        eprintln!("Failed to parse public key structure.\n",);
                    }
                    res = ErrorKind::ParseError;
                } else if *{
                    let _old = data_ptr;
                    data_ptr = data_ptr.offset(1);
                    _old
                } as (usize)
                    != len
                {
                    if (*state).verbose != 0 {
                        eprintln!("Unexpected length.\n");
                    }
                    res = ErrorKind::AlgorithmError;
                } else {
                    cb_point = len;
                    ptr_point = calloc(cb_point, 1) as (*mut u8);
                    if ptr_point.is_null() {
                        if (*state).verbose != 0 {
                            eprintln!("Failed to allocate memory for public point.");
                        }
                        res = ErrorKind::MemoryError;
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
            } else {
                if (*state).verbose != 0 {
                    eprintln!("Wrong algorithm.");
                }
                res = ErrorKind::AlgorithmError;
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

    _ykpiv_end_transaction(state);
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
    protected_data_available: u8,

    /// PUK blocked
    puk_blocked: u8,

    /// No block on upgrade
    puk_noblock_on_upgrade: u8,

    /// PIN last changed
    pin_last_changed: u32,

    /// MGM type
    mgm_type: YkPivConfigMgmType,
}

/// Get config
pub unsafe fn ykpiv_util_get_config(state: *mut YubiKey, config: *mut YkPivConfig) -> ErrorKind {
    let mut data = [0u8; YKPIV_OBJ_MAX_SIZE];
    let mut cb_data: usize = mem::size_of::<[u8; YKPIV_OBJ_MAX_SIZE]>();
    let mut p_item: *mut u8 = ptr::null_mut();
    let mut cb_item: usize = 0;
    let res = ErrorKind::Ok;

    if state.is_null() || config.is_null() {
        return ErrorKind::GenericError;
    }

    (*config).protected_data_available = 0u8;
    (*config).puk_blocked = 0u8;
    (*config).puk_noblock_on_upgrade = 0u8;
    (*config).pin_last_changed = 0u32;
    (*config).mgm_type = YkPivConfigMgmType::YKPIV_CONFIG_MGM_MANUAL;

    if _ykpiv_begin_transaction(state) != ErrorKind::Ok {
        return ErrorKind::PcscError;
    }

    if _ykpiv_ensure_application_selected(state) == ErrorKind::Ok {
        if _read_metadata(state, 0x80u8, data.as_mut_ptr(), &mut cb_data) == ErrorKind::Ok {
            if _get_metadata_item(
                data.as_mut_ptr(),
                cb_data,
                0x81u8,
                &mut p_item,
                &mut cb_item,
            ) == ErrorKind::Ok
            {
                if *p_item & 0x1 != 0 {
                    (*config).puk_blocked = 1u8;
                }

                if *p_item & 0x2 != 0 {
                    (*config).mgm_type = YkPivConfigMgmType::YKPIV_CONFIG_MGM_PROTECTED;
                }
            }
            if _get_metadata_item(
                data.as_mut_ptr(),
                cb_data,
                0x82u8,
                &mut p_item,
                &mut cb_item,
            ) == ErrorKind::Ok
            {
                if (*config).mgm_type as (i32)
                    != YkPivConfigMgmType::YKPIV_CONFIG_MGM_MANUAL as (i32)
                {
                    if (*state).verbose != 0 {
                        eprintln!("conflicting types of mgm key administration configured");
                    }
                } else {
                    (*config).mgm_type = YkPivConfigMgmType::YKPIV_CONFIG_MGM_DERIVED;
                }
            }

            if _get_metadata_item(
                data.as_mut_ptr(),
                cb_data,
                0x83u8,
                &mut p_item,
                &mut cb_item,
            ) == ErrorKind::Ok
            {
                if cb_item != 4 {
                    if (*state).verbose != 0 {
                        eprintln!("pin timestamp in admin metadata is an invalid size");
                    }
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
        cb_data = mem::size_of::<[u8; YKPIV_OBJ_MAX_SIZE]>();
        if _read_metadata(state, 0x88u8, data.as_mut_ptr(), &mut cb_data) == ErrorKind::Ok {
            (*config).protected_data_available = 1u8;

            let res = _get_metadata_item(
                data.as_mut_ptr(),
                cb_data,
                0x81u8,
                &mut p_item,
                &mut cb_item,
            );

            if res == ErrorKind::Ok && *p_item as (i32) & 0x1i32 != 0 {
                (*config).puk_noblock_on_upgrade = 1u8;
            }

            let res = _get_metadata_item(
                data.as_mut_ptr(),
                cb_data,
                0x89u8,
                &mut p_item,
                &mut cb_item,
            );

            if res == ErrorKind::Ok {
                if (*config).mgm_type != YkPivConfigMgmType::YKPIV_CONFIG_MGM_PROTECTED
                    && (*state).verbose != 0
                {
                    eprintln!(
                             "conflicting types of mgm key administration configured - protected mgm exists"
                         );
                }
                (*config).mgm_type = YkPivConfigMgmType::YKPIV_CONFIG_MGM_PROTECTED;
            }
        }
    }

    _ykpiv_end_transaction(state);
    res
}

/// Set PIN last changed
pub unsafe fn ykpiv_util_set_pin_last_changed(state: *mut YubiKey) -> ErrorKind {
    let mut data = [0u8; YKPIV_OBJ_MAX_SIZE];
    let mut cb_data = data.len();
    let mut res = ErrorKind::Ok;
    let ykrc: ErrorKind;

    if state.is_null() {
        return ErrorKind::GenericError;
    }

    if _ykpiv_begin_transaction(state) != ErrorKind::Ok {
        return ErrorKind::PcscError;
    }

    if _ykpiv_ensure_application_selected(state) == ErrorKind::Ok {
        ykrc = _read_metadata(state, 0x80, data.as_mut_ptr(), &mut cb_data);

        if ykrc != ErrorKind::Ok {
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
                0x83,
                &mut tnow as *mut i64 as *mut u8,
                4,
            )
        };

        if res != ErrorKind::Ok {
            if (*state).verbose != 0 {
                eprintln!("could not set pin timestamp, err = {}\n", res as (i32),);
            }
        } else {
            res = _write_metadata(state, 0x80u8, data.as_mut_ptr(), cb_data);
            if res != ErrorKind::Ok && (*state).verbose != 0 {
                eprintln!("could not write admin data, err = {}", res);
            }
        }
    }
    _ykpiv_end_transaction(state);
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
    state: *mut YubiKey,
    pin: *const u8,
    pin_len: usize,
    mgm: *mut YkPivMgm,
) -> ErrorKind {
    let mut data = [0u8; YKPIV_OBJ_MAX_SIZE];
    let mut cb_data: usize = data.len();
    let mut p_item: *mut u8 = ptr::null_mut();
    let mut cb_item: usize = 0;
    let mut res: ErrorKind = ErrorKind::Ok;

    if state.is_null() {
        return ErrorKind::GenericError;
    }

    if pin.is_null() || pin_len == 0 || mgm.is_null() {
        return ErrorKind::GenericError;
    }

    if _ykpiv_begin_transaction(state) != ErrorKind::Ok {
        return ErrorKind::PcscError;
    }

    if _ykpiv_ensure_application_selected(state) == ErrorKind::Ok {
        res = _read_metadata(state, 0x80u8, data.as_mut_ptr(), &mut cb_data);

        if res == ErrorKind::Ok {
            res = _get_metadata_item(
                data.as_mut_ptr(),
                cb_data,
                0x82u8,
                &mut p_item,
                &mut cb_item,
            );

            if res == ErrorKind::Ok {
                if cb_item != 16usize {
                    if (*state).verbose != 0 {
                        eprintln!(
                            "derived mgm salt exists, but is incorrect size = {}",
                            cb_item,
                        );
                    }
                    res = ErrorKind::GenericError;
                } else {
                    let p5rc = pkcs5_pbkdf2_sha1(
                        pin,
                        pin_len,
                        p_item,
                        cb_item,
                        10000,
                        (*mgm).0.as_mut_ptr(),
                        (*mgm).0.len(),
                    );

                    if p5rc != Pkcs5ErrorKind::Ok {
                        if (*state).verbose != 0 {
                            eprintln!("pbkdf2 failure, err = {:?}", p5rc);
                        }

                        res = ErrorKind::GenericError;
                    }
                }
            }
        }
    }

    _ykpiv_end_transaction(state);
    res
}

/// Get protected management key (MGM)
pub unsafe fn ykpiv_util_get_protected_mgm(state: *mut YubiKey, mgm: *mut YkPivMgm) -> ErrorKind {
    let mut data = [0u8; YKPIV_OBJ_MAX_SIZE];
    let mut cb_data: usize = data.len();
    let mut p_item: *mut u8 = ptr::null_mut();
    let mut cb_item: usize = 0;
    let mut res = ErrorKind::Ok;

    if state.is_null() || mgm.is_null() {
        return ErrorKind::GenericError;
    }

    if _ykpiv_begin_transaction(state) != ErrorKind::Ok {
        return ErrorKind::PcscError;
    }

    if _ykpiv_ensure_application_selected(state) == ErrorKind::Ok {
        res = _read_metadata(state, 0x88u8, data.as_mut_ptr(), &mut cb_data);

        if res != ErrorKind::Ok {
            if (*state).verbose != 0 {
                eprintln!("could not read protected data, err = {:?}", res);
            }
        } else {
            res = _get_metadata_item(
                data.as_mut_ptr(),
                cb_data,
                0x89u8,
                &mut p_item,
                &mut cb_item,
            );

            if res != ErrorKind::Ok {
                if (*state).verbose != 0 {
                    eprintln!(
                        "could not read protected mgm from metadata, err = {}",
                        res as (i32),
                    );
                }
            } else if cb_item != (*mgm).0.len() {
                if (*state).verbose != 0 {
                    eprintln!(
                        "protected data contains mgm, but is the wrong size = {}",
                        cb_item,
                    );
                }
                res = ErrorKind::AuthenticationError;
            } else {
                memcpy(
                    (*mgm).0.as_mut_ptr() as (*mut c_void),
                    p_item as (*const c_void),
                    cb_item,
                );
            }
        }
    }

    data.zeroize();
    _ykpiv_end_transaction(state);
    res
}

/// Set protected management key (MGM)
#[allow(clippy::cognitive_complexity)]
pub unsafe fn ykpiv_util_set_protected_mgm(state: *mut YubiKey, mgm: *mut YkPivMgm) -> ErrorKind {
    let mut _currentBlock;
    let mut res: ErrorKind = ErrorKind::Ok;
    let mut ykrc: ErrorKind = ErrorKind::Ok;
    let mut prngrc: PRngErrorKind = PRngErrorKind::Ok;
    let mut f_generate: bool;
    let mut mgm_key = [0u8; 24];
    let mut i: usize;
    let mut data = [0u8; YKPIV_OBJ_MAX_SIZE];
    let mut cb_data = data.len();
    let mut p_item: *mut u8 = ptr::null_mut();
    let mut cb_item: usize = 0;
    let mut flags_1: u8 = 0;

    if state.is_null() {
        return ErrorKind::GenericError;
    }

    if mgm.is_null() {
        f_generate = true;
    } else {
        f_generate = true;
        memcpy(
            mgm_key.as_mut_ptr() as (*mut c_void),
            (*mgm).0.as_mut_ptr() as (*const c_void),
            (*mgm).0.len(),
        );
        i = 0;
        loop {
            if i >= 24 {
                _currentBlock = 8;
                break;
            }
            if mgm_key[i] as (i32) != 0i32 {
                _currentBlock = 6;
                break;
            }
            i = i.wrapping_add(1);
        }
        if _currentBlock == 8 {
        } else {
            f_generate = false;
        }
    }

    if _ykpiv_begin_transaction(state) != ErrorKind::Ok {
        return ErrorKind::PcscError;
    }

    if _ykpiv_ensure_application_selected(state) == ErrorKind::Ok {
        loop {
            if f_generate {
                prngrc = _ykpiv_prng_generate(mgm_key.as_mut_ptr(), mem::size_of::<[u8; 24]>());
                if prngrc != PRngErrorKind::Ok {
                    _currentBlock = 47;
                    break;
                }
            }

            ykrc = ykpiv_set_mgmkey(state, mgm_key.as_mut_ptr());
            if ykrc != ErrorKind::Ok {
                if ErrorKind::KeyError as (i32) != ykrc as (i32) {
                    _currentBlock = 44;
                    break;
                }
            } else {
                f_generate = false;
            }
            if !f_generate {
                _currentBlock = 16;
                break;
            }
        }

        if _currentBlock == 16 {
            if !mgm.is_null() {
                memcpy(
                    (*mgm).0.as_mut_ptr() as (*mut c_void),
                    mgm_key.as_mut_ptr() as (*const c_void),
                    (*mgm).0.len(),
                );
            }

            ykrc = _read_metadata(state, 0x88u8, data.as_mut_ptr(), &mut cb_data);

            if ykrc != ErrorKind::Ok {
                cb_data = 0;
            }

            ykrc = _set_metadata_item(
                data.as_mut_ptr(),
                &mut cb_data,
                CB_OBJ_MAX,
                0x89,
                mgm_key.as_mut_ptr(),
                mgm_key.len(),
            );

            if ykrc != ErrorKind::Ok {
                if (*state).verbose != 0 {
                    eprintln!("could not set protected mgm item, err = {:?}", ykrc);
                    _currentBlock = 26;
                } else {
                    _currentBlock = 26;
                }
            } else {
                ykrc = _write_metadata(state, 0x88u8, data.as_mut_ptr(), cb_data);
                if ykrc != ErrorKind::Ok {
                    if (*state).verbose != 0 {
                        eprintln!("could not write protected data, err = {:?}", ykrc);
                        _currentBlock = 51;
                    } else {
                        _currentBlock = 51;
                    }
                } else {
                    _currentBlock = 26;
                }
            }

            if _currentBlock != 51 {
                cb_data = YKPIV_OBJ_MAX_SIZE;
                ykrc = _read_metadata(state, 0x80u8, data.as_mut_ptr(), &mut cb_data);

                if ykrc != ErrorKind::Ok {
                    cb_data = 0;
                } else {
                    ykrc = _get_metadata_item(
                        data.as_mut_ptr(),
                        cb_data,
                        0x81u8,
                        &mut p_item,
                        &mut cb_item,
                    );

                    if ykrc != ErrorKind::Ok && (*state).verbose != 0 {
                        eprintln!("admin data exists, but flags are not present",);
                    }

                    if cb_item == 1 {
                        // TODO(tarcieri): get rid of memcpy and pointers, replace with slices!
                        #[allow(trivial_casts)]
                        memcpy(
                            &mut flags_1 as (*mut u8) as (*mut c_void),
                            p_item as (*const c_void),
                            cb_item,
                        );
                    } else if (*state).verbose != 0 {
                        eprintln!("admin data flags are an incorrect size = {}", cb_item,);
                    }

                    ykrc = _set_metadata_item(
                        data.as_mut_ptr(),
                        &mut cb_data,
                        CB_OBJ_MAX,
                        0x82,
                        ptr::null_mut(),
                        0,
                    );

                    if ykrc != ErrorKind::Ok && (*state).verbose != 0 {
                        eprintln!("could not unset derived mgm salt, err = {}", ykrc);
                    }
                }
                flags_1 |= 0x2;

                ykrc = _set_metadata_item(
                    data.as_mut_ptr(),
                    &mut cb_data,
                    CB_OBJ_MAX,
                    0x81,
                    &mut flags_1,
                    1,
                );

                if ykrc != ErrorKind::Ok {
                    if (*state).verbose != 0 {
                        eprintln!("could not set admin flags item, err = {}", ykrc);
                    }
                } else {
                    ykrc = _write_metadata(state, 0x80u8, data.as_mut_ptr(), cb_data);
                    if ykrc != ErrorKind::Ok && (*state).verbose != 0 {
                        eprintln!("could not write admin data, err = {}", ykrc);
                    }
                }
            }
        } else if _currentBlock == 44 {
            if (*state).verbose != 0 {
                eprintln!("could not set new derived mgm key, err = {}", ykrc);
            }

            res = ykrc;
        } else {
            if (*state).verbose != 0 {
                eprintln!("could not generate new mgm, err = {:?}", prngrc);
            }

            res = ErrorKind::RandomnessError;
        }
    }

    data.zeroize();
    mgm_key.zeroize();
    _ykpiv_end_transaction(state);

    res
}

/// Reset
pub unsafe fn ykpiv_util_reset(state: *mut YubiKey) -> ErrorKind {
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

    if res == ErrorKind::Ok && sw == SW_SUCCESS {
        ErrorKind::Ok
    } else {
        ErrorKind::GenericError
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
    state: *mut YubiKey,
    slot: u8,
    buf: *mut u8,
    buf_len: *mut usize,
) -> ErrorKind {
    let mut ptr: *mut u8;
    let object_id = ykpiv_util_slot_object(slot) as i32;
    let mut len: usize = 0;

    if object_id == -1 {
        return ErrorKind::InvalidObject;
    }

    if _ykpiv_fetch_object(state, object_id, buf, buf_len) == ErrorKind::Ok {
        ptr = buf;

        if *buf_len < CB_OBJ_TAG_MIN {
            *buf_len = 0;
            return ErrorKind::Ok;
        } else if *{
            let _old = ptr;
            ptr = ptr.offset(1);
            _old
        } == TAG_CERT
        {
            ptr = ptr.add(_ykpiv_get_length(ptr, &mut len));

            if len > *buf_len - (ptr as isize - buf as isize) as usize {
                *buf_len = 0;
                return ErrorKind::Ok;
            } else {
                memmove(buf as (*mut c_void), ptr as (*const c_void), len);
                *buf_len = len;
            }
        }
    } else {
        *buf_len = 0;
    }

    ErrorKind::Ok
}

/// Write certificate
unsafe fn _write_certificate(
    state: *mut YubiKey,
    slot: u8,
    data: *mut u8,
    data_len: usize,
    certinfo: u8,
) -> ErrorKind {
    let mut buf = [0u8; CB_OBJ_MAX];
    let object_id = ykpiv_util_slot_object(slot) as i32;
    let mut offset: usize = 0;
    let mut req_len: usize;

    if object_id == -1 {
        return ErrorKind::InvalidObject;
    }

    if data.is_null() || data_len == 0 {
        if !data.is_null() || data_len != 0 {
            return ErrorKind::GenericError;
        }

        return _ykpiv_save_object(state, object_id, ptr::null_mut(), 0);
    }

    req_len = 1 /* cert tag */ + 3 /* compression tag + data*/ + 2 /* lrc */;
    req_len += _ykpiv_set_length(buf.as_mut_ptr(), data_len);
    req_len += data_len;

    if req_len < data_len || req_len > _obj_size_max(state) {
        return ErrorKind::SizeError;
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
) -> ErrorKind {
    let mut p_temp: *mut u8 = data;
    let mut cb_temp: usize = 0;
    let mut tag_temp: u8;

    if data.is_null() || pp_item.is_null() || pcb_item.is_null() {
        return ErrorKind::GenericError;
    }

    *pp_item = ptr::null_mut();
    *pcb_item = 0;

    while p_temp < data.add(cb_data) {
        tag_temp = *p_temp;
        p_temp = p_temp.add(1);

        if !_ykpiv_has_valid_length(p_temp, data.add(cb_data) as usize - p_temp as usize) {
            return ErrorKind::SizeError;
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

        ErrorKind::Ok
    } else {
        ErrorKind::GenericError
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
) -> ErrorKind {
    let mut p_temp: *mut u8 = data;
    let mut cb_temp: usize = 0;
    let mut tag_temp: u8 = 0;
    let mut cb_len: usize = 0;
    let p_next: *mut u8;
    let cb_moved: isize;

    if data.is_null() || pcb_data.is_null() {
        return ErrorKind::GenericError;
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
            return ErrorKind::Ok;
        }

        p_temp = data.add(*pcb_data);
        cb_len = _get_length_size(cb_item) as (usize);

        if (*pcb_data).wrapping_add(cb_len).wrapping_add(cb_item) > cb_data_max {
            return ErrorKind::GenericError;
        }

        *p_temp = tag;
        p_temp = p_temp.add(1);
        p_temp = p_temp.add(_ykpiv_set_length(p_temp, cb_item));

        memcpy(p_temp as (*mut c_void), p_item as (*const c_void), cb_item);
        *pcb_data += 1 + cb_len + cb_item;

        return ErrorKind::Ok;
    }

    if cb_temp == cb_item {
        memcpy(p_temp as (*mut c_void), p_item as (*const c_void), cb_item);
        return ErrorKind::Ok;
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
        return ErrorKind::GenericError;
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

    ErrorKind::Ok
}

/// Read metadata
unsafe fn _read_metadata(
    state: *mut YubiKey,
    tag: u8,
    data: *mut u8,
    pcb_data: *mut usize,
) -> ErrorKind {
    let mut p_temp: *mut u8;
    let mut cb_temp: usize;
    let res: ErrorKind;

    if data.is_null() || pcb_data.is_null() || YKPIV_OBJ_MAX_SIZE > *pcb_data {
        return ErrorKind::GenericError;
    }

    let obj_id = match tag {
        TAG_ADMIN => YKPIV_OBJ_ADMIN_DATA,
        TAG_PROTECTED => YKPIV_OBJ_PRINTED,
        _ => return ErrorKind::InvalidObject,
    } as i32;

    cb_temp = *pcb_data;
    *pcb_data = 0;

    res = _ykpiv_fetch_object(state, obj_id, data, &mut cb_temp);

    if res != ErrorKind::Ok {
        return res;
    }

    if cb_temp < CB_OBJ_TAG_MIN {
        return ErrorKind::GenericError;
    }
    p_temp = data;

    if tag as (i32)
        != *{
            let _old = p_temp;
            p_temp = p_temp.offset(1);
            _old
        } as (i32)
    {
        return ErrorKind::GenericError;
    }

    p_temp = p_temp.add(_ykpiv_get_length(p_temp, pcb_data));

    if *pcb_data > cb_temp - (p_temp as isize - data as isize) as usize {
        *pcb_data = 0;
        return ErrorKind::GenericError;
    }

    memmove(data as (*mut c_void), p_temp as (*const c_void), *pcb_data);
    ErrorKind::Ok
}

/// Write metadata
unsafe fn _write_metadata(
    state: *mut YubiKey,
    tag: u8,
    data: *mut u8,
    cb_data: usize,
) -> ErrorKind {
    let mut buf = [0u8; CB_OBJ_MAX]; // XXX REMEMBER TO ZERO
    let mut p_temp: *mut u8 = buf.as_mut_ptr();

    if cb_data > _obj_size_max(state) - CB_OBJ_TAG_MAX {
        return ErrorKind::GenericError;
    }

    let obj_id = match tag {
        TAG_ADMIN => YKPIV_OBJ_ADMIN_DATA,
        TAG_PROTECTED => YKPIV_OBJ_PRINTED,
        _ => return ErrorKind::InvalidObject,
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
