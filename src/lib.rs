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

pub mod error;
pub mod internal;
pub mod util;

use self::{error::ErrorKind, internal::DesKey};
use std::{convert::TryInto, ffi::CStr, mem, os::raw::c_void, ptr};
use zeroize::Zeroize;

use crate::error::ykpiv_strerror;
use libc::{
    c_char, calloc, free, malloc, memcmp, memcpy, memmove, memset, realloc, strchr, strlen,
    strncasecmp, strnlen,
};

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
    static mut _DefaultRuneLocale: Struct1;
    fn __maskrune(arg1: i32, arg2: usize) -> i32;
    fn __tolower(arg1: i32) -> i32;
    fn __toupper(arg1: i32) -> i32;
    fn des_destroy_key(key: *mut DesKey) -> Enum6;
    fn des_encrypt(
        key: *mut DesKey,
        in_: *const u8,
        inlen: usize,
        out: *mut u8,
        outlen: *mut usize,
    ) -> Enum6;
    fn des_import_key(
        type_: i32,
        keyraw: *const u8,
        keyrawlen: usize,
        key: *mut *mut DesKey,
    ) -> Enum6;
    fn memset_s(__s: *mut c_void, __smax: usize, __c: i32, __n: usize) -> i32;
    fn snprintf(__str: *mut u8, __size: usize, __format: *const u8, ...) -> i32;
    fn yk_des_is_weak_key(key: *const u8, cb_key: usize) -> bool;
}

pub const DES_TYPE_3DES: u8 = 1;

pub const DES_LEN_DES: usize = 8;
pub const DES_LEN_3DES: usize = DES_LEN_DES * 3;

pub const YKPIV_ALGO_TAG: u8 = 0x80;
pub const YKPIV_ALGO_3DES: u8 = 0x03;
pub const YKPIV_ALGO_RSA1024: u8 = 0x06;
pub const YKPIV_ALGO_RSA2048: u8 = 0x07;
pub const YKPIV_ALGO_ECCP256: u8 = 0x11;
pub const YKPIV_ALGO_ECCP384: u8 = 0x14;

pub const YKPIV_KEY_AUTHENTICATION: u8 = 0x9a;
pub const YKPIV_KEY_CARDMGM: u8 = 0x9b;
pub const YKPIV_KEY_SIGNATURE: u8 = 0x9c;
pub const YKPIV_KEY_KEYMGM: u8 = 0x9d;
pub const YKPIV_KEY_CARDAUTH: u8 = 0x9e;
pub const YKPIV_KEY_RETIRED1: u8 = 0x82;
pub const YKPIV_KEY_RETIRED2: u8 = 0x83;
pub const YKPIV_KEY_RETIRED3: u8 = 0x84;
pub const YKPIV_KEY_RETIRED4: u8 = 0x85;
pub const YKPIV_KEY_RETIRED5: u8 = 0x86;
pub const YKPIV_KEY_RETIRED6: u8 = 0x87;
pub const YKPIV_KEY_RETIRED7: u8 = 0x88;
pub const YKPIV_KEY_RETIRED8: u8 = 0x89;
pub const YKPIV_KEY_RETIRED9: u8 = 0x8a;
pub const YKPIV_KEY_RETIRED10: u8 = 0x8b;
pub const YKPIV_KEY_RETIRED11: u8 = 0x8c;
pub const YKPIV_KEY_RETIRED12: u8 = 0x8d;
pub const YKPIV_KEY_RETIRED13: u8 = 0x8e;
pub const YKPIV_KEY_RETIRED14: u8 = 0x8f;
pub const YKPIV_KEY_RETIRED15: u8 = 0x90;
pub const YKPIV_KEY_RETIRED16: u8 = 0x91;
pub const YKPIV_KEY_RETIRED17: u8 = 0x92;
pub const YKPIV_KEY_RETIRED18: u8 = 0x93;
pub const YKPIV_KEY_RETIRED19: u8 = 0x94;
pub const YKPIV_KEY_RETIRED20: u8 = 0x95;
pub const YKPIV_KEY_ATTESTATION: u8 = 0xf9;

pub const YKPIV_INS_VERIFY: u8 = 0x20;
pub const YKPIV_INS_CHANGE_REFERENCE: u8 = 0x24;
pub const YKPIV_INS_RESET_RETRY: u8 = 0x2c;
pub const YKPIV_INS_GENERATE_ASYMMETRIC: u8 = 0x47;
pub const YKPIV_INS_AUTHENTICATE: u8 = 0x87;
pub const YKPIV_INS_GET_DATA: u8 = 0xcb;
pub const YKPIV_INS_PUT_DATA: u8 = 0xdb;
pub const YKPIV_INS_SELECT_APPLICATION: u8 = 0xa4;
pub const YKPIV_INS_GET_RESPONSE_APDU: u8 = 0xc0;

// Yubico vendor specific instructions
pub const YKPIV_INS_SET_MGMKEY: u8 = 0xff;
pub const YKPIV_INS_IMPORT_KEY: u8 = 0xfe;
pub const YKPIV_INS_GET_VERSION: u8 = 0xfd;
pub const YKPIV_INS_RESET: u8 = 0xfb;
pub const YKPIV_INS_SET_PIN_RETRIES: u8 = 0xfa;
pub const YKPIV_INS_ATTEST: u8 = 0xf9;
pub const YKPIV_INS_GET_SERIAL: u8 = 0xf8;

/// Application Protocol Data Unit
#[derive(Clone)]
pub struct APDU {
    /// Instruction class - indicates the type of command, e.g. interindustry or proprietary
    pub cla: u8,

    /// Instruction code - indicates the specific command, e.g. "write data"
    pub ins: u8,

    /// Instruction parameter 1 for the command, e.g. offset into file at which to write the data
    pub p1: u8,

    /// Instruction parameter 2 for the command
    pub p2: u8,

    /// Length of command - encodes the number of bytes of command data to follow
    pub lc: u8,

    /// Command data
    pub data: [u8; 255],
}

impl Default for APDU {
    fn default() -> Self {
        Self {
            cla: 0,
            ins: 0,
            p1: 0,
            p2: 0,
            lc: 0,
            data: [0u8; 255],
        }
    }
}

impl Zeroize for APDU {
    fn zeroize(&mut self) {
        self.cla.zeroize();
        self.ins.zeroize();
        self.p1.zeroize();
        self.p2.zeroize();
        self.lc.zeroize();
        self.data.zeroize();
    }
}

#[derive(Copy)]
#[repr(C)]
pub struct __sbuf {
    pub _base: *mut u8,
    pub _size: i32,
}

impl Clone for __sbuf {
    fn clone(&self) -> Self {
        *self
    }
}

pub fn isascii(mut _c: i32) -> i32 {
    (_c & !0x7fi32 == 0i32) as (i32)
}

#[derive(Copy)]
#[repr(C)]
pub struct Struct3 {
    pub __min: i32,
    pub __max: i32,
    pub __map: i32,
    pub __types: *mut u32,
}

impl Clone for Struct3 {
    fn clone(&self) -> Self {
        *self
    }
}

#[derive(Copy)]
#[repr(C)]
pub struct Struct2 {
    pub __nranges: i32,
    pub __ranges: *mut Struct3,
}

impl Clone for Struct2 {
    fn clone(&self) -> Self {
        *self
    }
}

#[derive(Copy)]
#[repr(C)]
pub struct Struct4 {
    pub __name: [u8; 14],
    pub __mask: u32,
}

impl Clone for Struct4 {
    fn clone(&self) -> Self {
        *self
    }
}

#[derive(Copy)]
#[repr(C)]
pub struct Struct1 {
    pub __magic: [u8; 8],
    pub __encoding: [u8; 32],
    pub __sgetrune: unsafe fn(*const u8, usize, *mut *const u8) -> i32,
    pub __sputrune: unsafe fn(i32, *mut u8, usize, *mut *mut u8) -> i32,
    pub __invalid_rune: i32,
    pub __runetype: [u32; 256],
    pub __maplower: [i32; 256],
    pub __mapupper: [i32; 256],
    pub __runetype_ext: Struct2,
    pub __maplower_ext: Struct2,
    pub __mapupper_ext: Struct2,
    pub __variable: *mut c_void,
    pub __variable_len: i32,
    pub __ncharclasses: i32,
    pub __charclasses: *mut Struct4,
}

impl Clone for Struct1 {
    fn clone(&self) -> Self {
        *self
    }
}

pub fn __istype(mut _c: i32, mut _f: usize) -> i32 {
    if isascii(_c) != 0 {
        !(_DefaultRuneLocale.__runetype[_c as (usize)] as (usize) & _f == 0) as (i32)
    } else {
        !(__maskrune(_c, _f) == 0) as (i32)
    }
}

pub fn __isctype(mut _c: i32, mut _f: usize) -> i32 {
    if _c < 0i32 || _c >= 256i32 {
        0i32
    } else {
        !(_DefaultRuneLocale.__runetype[_c as (usize)] as (usize) & _f == 0) as (i32)
    }
}

pub fn __wcwidth(mut _c: i32) -> i32 {
    let mut _x: u32;
    if _c == 0i32 {
        0i32
    } else {
        _x = __maskrune(_c, 0xe0000000usize | 0x40000usize) as (u32);
        (if _x as (usize) & 0xe0000000usize != 0usize {
            ((_x as (usize) & 0xe0000000usize) >> 30i32) as (i32)
        } else if _x as (usize) & 0x40000usize != 0usize {
            1i32
        } else {
            -1i32
        })
    }
}

pub fn isalnum(mut _c: i32) -> i32 {
    __istype(_c, (0x100isize | 0x400isize) as (usize))
}

pub fn isalpha(mut _c: i32) -> i32 {
    __istype(_c, 0x100usize)
}

pub fn isblank(mut _c: i32) -> i32 {
    __istype(_c, 0x20000usize)
}

pub fn iscntrl(mut _c: i32) -> i32 {
    __istype(_c, 0x200usize)
}

pub fn isdigit(mut _c: i32) -> i32 {
    __isctype(_c, 0x400usize)
}

pub fn isgraph(mut _c: i32) -> i32 {
    __istype(_c, 0x800usize)
}

pub fn islower(mut _c: i32) -> i32 {
    __istype(_c, 0x1000usize)
}

pub fn isprint(mut _c: i32) -> i32 {
    __istype(_c, 0x40000usize)
}

pub fn ispunct(mut _c: i32) -> i32 {
    __istype(_c, 0x2000usize)
}

pub fn isspace(mut _c: i32) -> i32 {
    __istype(_c, 0x4000usize)
}

pub fn isupper(mut _c: i32) -> i32 {
    __istype(_c, 0x8000usize)
}

pub fn isxdigit(mut _c: i32) -> i32 {
    __isctype(_c, 0x10000usize)
}

pub fn toascii(mut _c: i32) -> i32 {
    _c & 0x7fi32
}

pub fn tolower(mut _c: i32) -> i32 {
    __tolower(_c)
}

pub fn toupper(mut _c: i32) -> i32 {
    __toupper(_c)
}

pub fn digittoint(mut _c: i32) -> i32 {
    __maskrune(_c, 0xfusize)
}

pub fn ishexnumber(mut _c: i32) -> i32 {
    __istype(_c, 0x10000usize)
}

pub fn isideogram(mut _c: i32) -> i32 {
    __istype(_c, 0x80000usize)
}

pub fn isnumber(mut _c: i32) -> i32 {
    __istype(_c, 0x400usize)
}

pub fn isphonogram(mut _c: i32) -> i32 {
    __istype(_c, 0x200000usize)
}

pub fn isrune(mut _c: i32) -> i32 {
    __istype(_c, 0xfffffff0usize)
}

pub fn isspecial(mut _c: i32) -> i32 {
    __istype(_c, 0x100000usize)
}

static mut aid: *const u8 = 0xa0i32 as (*const u8);

#[derive(Copy)]
#[repr(C)]
pub struct ykpiv_allocator {
    pub pfn_alloc: unsafe fn(*mut c_void, usize) -> *mut c_void,
    pub pfn_realloc: unsafe fn(*mut c_void, *mut c_void, usize) -> *mut c_void,
    pub pfn_free: unsafe fn(*mut c_void, *mut c_void),
    pub alloc_data: *mut c_void,
}

impl Clone for ykpiv_allocator {
    fn clone(&self) -> Self {
        *self
    }
}

unsafe fn _default_alloc(mut data: *mut c_void, mut cb: usize) -> *mut c_void {
    data;
    calloc(cb, 1usize)
}

unsafe fn _default_realloc(
    mut data: *mut c_void,
    mut p: *mut c_void,
    mut cb: usize,
) -> *mut c_void {
    data;
    realloc(p, cb)
}

unsafe fn _default_free(mut data: *mut c_void, mut p: *mut c_void) {
    data;
    free(p);
}

pub static mut _default_allocator: ykpiv_allocator = ykpiv_allocator {
    pfn_alloc: _default_alloc,
    pfn_realloc: _default_realloc,
    pfn_free: _default_free,
    alloc_data: 0i32 as (*mut c_void),
};

#[derive(Copy)]
#[repr(C)]
pub struct _ykpiv_version_t {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

impl Clone for _ykpiv_version_t {
    fn clone(&self) -> Self {
        *self
    }
}

#[derive(Copy)]
#[repr(C)]
pub struct ykpiv_state {
    pub context: i32,
    pub card: i32,
    pub verbose: i32,
    pub pin: *mut u8,
    pub allocator: ykpiv_allocator,
    pub isNEO: bool,
    pub ver: _ykpiv_version_t,
    pub serial: u32,
}

impl Clone for ykpiv_state {
    fn clone(&self) -> Self {
        *self
    }
}

pub fn _ykpiv_set_length(mut buffer: *mut u8, mut length: usize) -> u32 {
    if length < 0x80usize {
        *{
            let _old = buffer;
            buffer = buffer.offset(1isize);
            _old
        } = length as (u8);
        1u32
    } else if length < 0x100usize {
        *{
            let _old = buffer;
            buffer = buffer.offset(1isize);
            _old
        } = 0x81u8;
        *{
            let _old = buffer;
            buffer = buffer.offset(1isize);
            _old
        } = length as (u8);
        2u32
    } else {
        *{
            let _old = buffer;
            buffer = buffer.offset(1isize);
            _old
        } = 0x82u8;
        *{
            let _old = buffer;
            buffer = buffer.offset(1isize);
            _old
        } = (length >> 8i32 & 0xffusize) as (u8);
        *{
            let _old = buffer;
            buffer = buffer.offset(1isize);
            _old
        } = (length as (u8) as (i32) & 0xffi32) as (u8);
        3u32
    }
}

pub fn _ykpiv_get_length(mut buffer: *const u8, mut len: *mut usize) -> u32 {
    if *buffer.offset(0isize) as (i32) < 0x81i32 {
        *len = *buffer.offset(0isize) as (usize);
        1u32
    } else if *buffer as (i32) & 0x7fi32 == 1i32 {
        *len = *buffer.offset(1isize) as (usize);
        2u32
    } else if *buffer as (i32) & 0x7fi32 == 2i32 {
        let mut tmp: usize = *buffer.offset(1isize) as (usize);
        *len = (tmp << 8i32).wrapping_add(*buffer.offset(2isize) as (usize));
        3u32
    } else {
        0u32
    }
}

pub fn _ykpiv_has_valid_length(mut buffer: *const u8, mut len: usize) -> bool {
    if *buffer.offset(0isize) as (i32) < 0x81i32 && (len > 0usize) {
        true
    } else if *buffer as (i32) & 0x7fi32 == 1i32 && (len > 1usize) {
        true
    } else if *buffer as (i32) & 0x7fi32 == 2i32 && (len > 2usize) {
        true
    } else {
        false
    }
}

pub fn ykpiv_init_with_allocator(
    mut state: *mut *mut ykpiv_state,
    mut verbose: i32,
    mut allocator: *const ykpiv_allocator,
) -> ErrorKind {
    let mut s: *mut ykpiv_state;
    if 0i32 as (*mut c_void) as (*mut *mut ykpiv_state) == state {
        ErrorKind::YKPIV_GENERIC_ERROR
    } else {
        s = malloc(mem::size_of::<ykpiv_state>()) as (*mut ykpiv_state);

        (if 0i32 as (*mut c_void) as (*mut ykpiv_state) == s {
            ErrorKind::YKPIV_MEMORY_ERROR
        } else {
            memset(s as (*mut c_void), 0i32, mem::size_of::<ykpiv_state>());
            (*s).pin = 0i32 as (*mut c_void) as (*mut u8);
            (*s).allocator = *allocator;
            (*s).verbose = verbose;
            (*s).context = -1i32;
            *state = s;
            ErrorKind::YKPIV_OK
        })
    }
}

pub fn ykpiv_init(mut state: *mut *mut ykpiv_state, mut verbose: i32) -> ErrorKind {
    ykpiv_init_with_allocator(
        state,
        verbose,
        &mut _default_allocator as (*mut ykpiv_allocator) as (*const ykpiv_allocator),
    )
}

unsafe fn _ykpiv_done(mut state: *mut ykpiv_state, mut disconnect: bool) -> ErrorKind {
    if disconnect {
        ykpiv_disconnect(state);
    }

    _cache_pin(state, ptr::null(), 0usize);
    free(state as *mut c_void);
    ErrorKind::YKPIV_OK
}

pub fn ykpiv_done_with_external_card(mut state: *mut ykpiv_state) -> ErrorKind {
    _ykpiv_done(state, false)
}

pub fn ykpiv_done(mut state: *mut ykpiv_state) -> ErrorKind {
    _ykpiv_done(state, true)
}

pub fn ykpiv_disconnect(mut state: *mut ykpiv_state) -> ErrorKind {
    if (*state).card != 0 {
        SCardDisconnect((*state).card, 0x1u32);
        (*state).card = 0i32;
    }
    if SCardIsValidContext((*state).context) == 0x0i32 {
        SCardReleaseContext((*state).context);
        (*state).context = -1i32;
    }
    ErrorKind::YKPIV_OK
}

pub fn _ykpiv_select_application(mut state: *mut ykpiv_state) -> ErrorKind {
    let mut apdu: APDU;
    let mut data: [u8; 255];
    let mut recv_len: u32 = mem::size_of::<[u8; 255]>() as (u32);
    let mut sw: i32;
    let mut res: ErrorKind = ErrorKind::YKPIV_OK;

    // FIXME(tarcieri): translate APDU construction
    /*
      memset(apdu.raw, 0, sizeof(apdu));
      apdu.st.ins = YKPIV_INS_SELECT_APPLICATION;
      apdu.st.p1 = 0x04;
      apdu.st.lc = sizeof(aid);
      memcpy(apdu.st.data, aid, sizeof(aid));
    */

    if {
        res = _send_data(
            state,
            &mut apdu as (*mut APDU),
            data.as_mut_ptr(),
            &mut recv_len as (*mut u32),
            &mut sw as (*mut i32),
        );
        res
    } as (i32)
        != ErrorKind::YKPIV_OK as (i32)
    {
        if (*state).verbose != 0 {
            eprintln!(
                "Failed communicating with card: \'{}\'",
                ykpiv_strerror(res)
            );
        }
        res
    } else if sw != 0x9000i32 {
        if (*state).verbose != 0 {
            eprintln!("Failed selecting application: {:04x}", sw);
        }
        ErrorKind::YKPIV_GENERIC_ERROR
    } else {
        res = _ykpiv_get_version(state, 0i32 as (*mut c_void) as (*mut _ykpiv_version_t));
        if res as (i32) != ErrorKind::YKPIV_OK as (i32) {
            if (*state).verbose != 0 {
                eprintln!("Failed to retrieve version: \'{}\'", ykpiv_strerror(res));
            }
        }
        res = _ykpiv_get_serial(state, 0i32 as (*mut c_void) as (*mut u32), false);
        if res as (i32) != ErrorKind::YKPIV_OK as (i32) {
            if (*state).verbose != 0 {
                eprintln!(
                    "Failed to retrieve serial number: \'{}\'",
                    ykpiv_strerror(res)
                );
            }
            res = ErrorKind::YKPIV_OK;
        }
        res
    }
}

pub fn _ykpiv_ensure_application_selected(mut state: *mut ykpiv_state) -> ErrorKind {
    let mut res: ErrorKind = ErrorKind::YKPIV_OK;
    state;
    res
}

unsafe fn _ykpiv_connect(
    mut state: *mut ykpiv_state,
    mut context: usize,
    mut card: usize,
) -> ErrorKind {
    let mut res: ErrorKind = ErrorKind::YKPIV_OK;
    if 0i32 as (*mut c_void) as (*mut ykpiv_state) == state {
        ErrorKind::YKPIV_GENERIC_ERROR
    } else if context != (*state).context as (usize)
        && (0x0i32 != SCardIsValidContext(context as (i32)))
    {
        ErrorKind::YKPIV_PCSC_ERROR
    } else {
        if card != (*state).card as (usize) {
            let mut reader: [u8; 3072];
            let mut reader_len: u32 = mem::size_of::<[u8; 3072]>() as (u32);
            let mut atr: [u8; 33];
            let mut atr_len: u32 = mem::size_of::<[u8; 33]>() as (u32);
            if 0x0i32
                != SCardStatus(
                    card as (i32),
                    reader.as_mut_ptr(),
                    &mut reader_len as (*mut u32),
                    0i32 as (*mut c_void) as (*mut u32),
                    0i32 as (*mut c_void) as (*mut u32),
                    atr.as_mut_ptr(),
                    &mut atr_len as (*mut u32),
                )
            {
                return ErrorKind::YKPIV_PCSC_ERROR;
            } else {
                (*state).isNEO = mem::size_of::<[u8; 23]>().wrapping_sub(1usize)
                    == atr_len as (usize)
                    && (0i32
                        == memcmp(
                            (*b";\xFC\x13\0\0\x811\xFE\x15YubikeyNEOr3\xE1\0").as_ptr()
                                as (*const c_void),
                            atr.as_mut_ptr() as (*const c_void),
                            atr_len as (usize),
                        ));
            }
        }
        (*state).context = context as (i32);
        (*state).card = card as (i32);
        res
    }
}

pub fn ykpiv_connect_with_external_card(
    mut state: *mut ykpiv_state,
    mut context: usize,
    mut card: usize,
) -> ErrorKind {
    _ykpiv_connect(state, context, card)
}

pub fn ykpiv_connect(mut state: *mut ykpiv_state, mut wanted: *const c_char) -> ErrorKind {
    let mut _currentBlock;
    let mut active_protocol: u32;
    let mut reader_buf: [c_char; 2048];
    let mut num_readers: usize = mem::size_of::<[u8; 2048]>();
    let mut rc: isize;
    let mut reader_ptr: *mut c_char;
    let mut card: i32 = -1i32;
    let mut ret: ErrorKind = ykpiv_list_readers(
        state,
        reader_buf.as_mut_ptr(),
        &mut num_readers as (*mut usize),
    );
    if ret as (i32) != ErrorKind::YKPIV_OK as (i32) {
        ret
    } else {
        reader_ptr = reader_buf.as_mut_ptr();
        'loop2: loop {
            if !(*reader_ptr as (i32) != b'\0' as (i32)) {
                _currentBlock = 3;
                break;
            }
            if !wanted.is_null() {
                let mut ptr = reader_ptr as *const c_char;
                let mut found: bool = false;
                'loop10: loop {
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
                        ptr = ptr.offset(1isize);
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
                    if (*state).verbose != 0 {
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
                if (*state).verbose != 0 {
                    eprintln!(
                        "trying to connect to reader \'{}\'.",
                        CStr::from_ptr(reader_ptr).to_string_lossy()
                    );
                }
                rc = SCardConnect(
                    (*state).context,
                    reader_ptr as *const c_char,
                    0x2u32,
                    0x2u32,
                    &mut card as (*mut i32),
                    &mut active_protocol as (*mut u32),
                ) as (isize);
                if rc != 0x0isize {
                    if (*state).verbose != 0 {
                        eprintln!("SCardConnect failed, rc={}", rc);
                    }
                } else if ErrorKind::YKPIV_OK as (i32)
                    == _ykpiv_connect(state, (*state).context as (usize), card as (usize)) as (i32)
                {
                    _currentBlock = 19;
                    break;
                }
            }
            reader_ptr = reader_ptr.offset(strlen(reader_ptr).wrapping_add(1usize) as (isize));
        }
        (if _currentBlock == 3 {
            (if *reader_ptr as (i32) == b'\0' as (i32) {
                if (*state).verbose != 0 {
                    eprintln!("error: no usable reader found.");
                }
                SCardReleaseContext((*state).context);
                (*state).context = -1i32;
                ErrorKind::YKPIV_PCSC_ERROR
            } else {
                ErrorKind::YKPIV_GENERIC_ERROR
            })
        } else if ErrorKind::YKPIV_OK as (i32) != {
            ret = _ykpiv_begin_transaction(state);
            ret
        } as (i32)
        {
            ErrorKind::YKPIV_PCSC_ERROR
        } else {
            ret = _ykpiv_select_application(state);
            _ykpiv_end_transaction(state);
            ret
        })
    }
}

pub fn ykpiv_list_readers(
    mut state: *mut ykpiv_state,
    mut readers: *mut c_char,
    mut len: *mut usize,
) -> ErrorKind {
    let mut num_readers: u32 = 0u32;
    let mut rc: isize;
    if SCardIsValidContext((*state).context) != 0x0i32 {
        rc = SCardEstablishContext(
            0x2u32,
            0i32 as (*mut c_void) as (*const c_void),
            0i32 as (*mut c_void) as (*const c_void),
            &mut (*state).context as (*mut i32),
        ) as (isize);
        if rc != 0x0isize {
            if (*state).verbose != 0 {
                eprintln!("error: SCardEstablishContext failed, rc={}", rc);
            }
            return ErrorKind::YKPIV_PCSC_ERROR;
        }
    }
    rc = SCardListReaders(
        (*state).context,
        ptr::null(),
        ptr::null_mut(),
        &mut num_readers as (*mut u32),
    ) as (isize);
    if rc != 0x0isize {
        if (*state).verbose != 0 {
            eprintln!("error: SCardListReaders failed, rc={}", rc);
        }
        SCardReleaseContext((*state).context);
        (*state).context = -1i32;
        ErrorKind::YKPIV_PCSC_ERROR
    } else {
        if num_readers as (usize) > *len {
            num_readers = *len as (u32);
        } else if num_readers as (usize) < *len {
            *len = num_readers as (usize);
        }
        rc = SCardListReaders(
            (*state).context,
            ptr::null(),
            readers,
            &mut num_readers as (*mut u32),
        ) as (isize);
        (if rc != 0x0isize {
            if (*state).verbose != 0 {
                eprintln!("error: SCardListReaders failed, rc={}", rc);
            }
            SCardReleaseContext((*state).context);
            (*state).context = -1i32;
            ErrorKind::YKPIV_PCSC_ERROR
        } else {
            *len = num_readers as (usize);
            ErrorKind::YKPIV_OK
        })
    }
}

unsafe fn reconnect(mut state: *mut ykpiv_state) -> ErrorKind {
    let mut active_protocol: u32 = 0u32;
    let mut rc: isize;
    let mut res: ErrorKind;
    let mut tries: i32;
    if (*state).verbose != 0 {
        eprintln!("trying to reconnect to current reader.");
    }
    rc = SCardReconnect(
        (*state).card,
        0x2u32,
        0x2u32,
        0x1u32,
        &mut active_protocol as (*mut u32),
    ) as (isize);
    if rc != 0x0isize {
        if (*state).verbose != 0 {
            eprintln!("SCardReconnect failed, rc={}", rc);
        }
        ErrorKind::YKPIV_PCSC_ERROR
    } else if {
        res = _ykpiv_select_application(state);
        res
    } as (i32)
        != ErrorKind::YKPIV_OK as (i32)
    {
        res
    } else if !(*state).pin.is_null() {
        ykpiv_verify(
            state,
            (*state).pin as *const c_char,
            &mut tries as (*mut i32),
        )
    } else {
        ErrorKind::YKPIV_OK
    }
}

pub fn _ykpiv_begin_transaction(mut state: *mut ykpiv_state) -> ErrorKind {
    let mut rc: isize;
    rc = SCardBeginTransaction((*state).card) as (isize);
    if (rc as (usize) & 0xffffffffusize) as (isize) as (usize) == 0x80100068usize {
        let mut res: ErrorKind = ErrorKind::YKPIV_OK;
        if {
            res = reconnect(state);
            res
        } as (i32)
            != ErrorKind::YKPIV_OK as (i32)
        {
            return res;
        } else {
            rc = SCardBeginTransaction((*state).card) as (isize);
        }
    }
    if rc != 0x0isize {
        if (*state).verbose != 0 {
            eprintln!("error: Failed to begin pcsc transaction, rc={}", rc);
        }
        ErrorKind::YKPIV_PCSC_ERROR
    } else {
        ErrorKind::YKPIV_OK
    }
}

pub fn _ykpiv_end_transaction(mut state: *mut ykpiv_state) -> ErrorKind {
    let mut rc: isize = SCardEndTransaction((*state).card, 0x0u32) as (isize);
    if rc != 0x0isize && ((*state).verbose != 0) {
        eprintln!("error: Failed to end pcsc transaction, rc={}", rc);
        ErrorKind::YKPIV_PCSC_ERROR
    } else {
        ErrorKind::YKPIV_OK
    }
}

pub fn _ykpiv_transfer_data(
    mut state: *mut ykpiv_state,
    mut templ: *const u8,
    mut in_data: *const u8,
    mut in_len: isize,
    mut out_data: *mut u8,
    mut out_len: *mut usize,
    mut sw: *mut i32,
) -> ErrorKind {
    let mut _currentBlock;
    let mut in_ptr: *const u8 = in_data;
    let mut max_out: usize = *out_len;
    let mut res: ErrorKind;
    let mut recv_len: u32;
    *out_len = 0usize;
    'loop1: loop {
        let mut this_size: usize = 0xffusize;
        let mut data: [u8; 261];
        recv_len = mem::size_of::<[u8; 261]>() as (u32);
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

        if (*state).verbose > 2i32 {
            eprintln!("Going to send {} bytes in this go.", this_size);
        }

        apdu.lc = this_size.try_into().unwrap();
        memcpy(
            apdu.data.as_mut_ptr() as *mut c_void,
            in_ptr as *const c_void,
            this_size,
        );

        res = _send_data(
            state,
            &mut apdu as (*mut APDU),
            data.as_mut_ptr(),
            &mut recv_len as (*mut u32),
            sw,
        );
        if res as (i32) != ErrorKind::YKPIV_OK as (i32) {
            _currentBlock = 24;
            break;
        }
        if *sw != 0x9000i32 && (*sw >> 8i32 != 0x61i32) {
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
        in_ptr = in_ptr.offset(this_size as (isize));
        if !(in_ptr < in_data.offset(in_len)) {
            _currentBlock = 10;
            break;
        }
    }
    if _currentBlock == 10 {
        'loop10: loop {
            if !(*sw >> 8i32 == 0x61i32) {
                _currentBlock = 24;
                break;
            }
            let mut data: [u8; 261];
            recv_len = mem::size_of::<[u8; 261]>() as (u32);
            if (*state).verbose > 2i32 {
                eprintln!(
                    "The card indicates there is {} bytes more data for us.",
                    *sw & 0xffi32
                );
            }

            let mut apdu = APDU::default();
            apdu.ins = YKPIV_INS_GET_RESPONSE_APDU;
            res = _send_data(
                state,
                &mut apdu as (*mut APDU),
                data.as_mut_ptr(),
                &mut recv_len as (*mut u32),
                sw,
            );
            if res as (i32) != ErrorKind::YKPIV_OK as (i32) {
                _currentBlock = 24;
                break;
            }
            if *sw != 0x9000i32 && (*sw >> 8i32 != 0x61i32) {
                _currentBlock = 24;
                break;
            }
            if (*out_len)
                .wrapping_add(recv_len as (usize))
                .wrapping_sub(2usize)
                > max_out
            {
                _currentBlock = 18;
                break;
            }
            if out_data.is_null() {
                continue;
            }
            memcpy(
                out_data as (*mut c_void),
                data.as_mut_ptr() as (*const c_void),
                recv_len.wrapping_sub(2u32) as (usize),
            );
            out_data = out_data.offset(recv_len.wrapping_sub(2u32) as (isize));
            *out_len = (*out_len).wrapping_add(recv_len.wrapping_sub(2u32) as (usize));
        }
        if _currentBlock == 24 {
        } else {
            if (*state).verbose != 0 {
                eprintln!(
                    "Output buffer to small, wanted to write {}, max was {}.",
                    (*out_len)
                        .wrapping_add(recv_len as (usize))
                        .wrapping_sub(2usize),
                    max_out
                );
            }
            res = ErrorKind::YKPIV_SIZE_ERROR;
        }
    } else if _currentBlock == 21 {
        if (*state).verbose != 0 {
            eprintln!(
                "Output buffer to small, wanted to write {}, max was {}.",
                (*out_len)
                    .wrapping_add(recv_len as (usize))
                    .wrapping_sub(2usize),
                max_out
            );
        }
        res = ErrorKind::YKPIV_SIZE_ERROR;
    }
    res
}

pub fn ykpiv_transfer_data(
    mut state: *mut ykpiv_state,
    mut templ: *const u8,
    mut in_data: *const u8,
    mut in_len: isize,
    mut out_data: *mut u8,
    mut out_len: *mut usize,
    mut sw: *mut i32,
) -> ErrorKind {
    let mut res: ErrorKind;
    if {
        res = _ykpiv_begin_transaction(state);
        res
    } as (i32)
        != ErrorKind::YKPIV_OK as (i32)
    {
        *out_len = 0usize;
        ErrorKind::YKPIV_PCSC_ERROR
    } else {
        res = _ykpiv_transfer_data(state, templ, in_data, in_len, out_data, out_len, sw);
        _ykpiv_end_transaction(state);
        res
    }
}

unsafe fn dump_hex(mut buf: *const u8, mut len: u32) {
    let mut i: u32;
    i = 0u32;
    'loop1: loop {
        if !(i < len) {
            break;
        }
        eprintln!("{:02x} ", *buf.offset(i as (isize)) as (i32));
        i = i.wrapping_add(1u32);
    }
}

pub fn _send_data(
    mut state: *mut ykpiv_state,
    mut apdu: *mut APDU,
    mut data: *mut u8,
    mut recv_len: *mut u32,
    mut sw: *mut i32,
) -> ErrorKind {
    let mut rc: isize;
    // FIXME(tarcieri): `send_len` is NOT supposed to be 0. Translate C code
    let mut send_len: u32 = 0u32; // (unsigned int)apdu->st.lc + 5;
    let mut tmp_len: u32 = *recv_len;

    // FIXME(tarcieri): Translate C code below
    /*
        if(state->verbose > 1) {
          fprintf(stderr, "> ");
          dump_hex(apdu->raw, send_len);
          fprintf(stderr, "\n");
        }

        rc = SCardTransmit(state->card, SCARD_PCI_T1, apdu->raw, send_len, NULL, data, &tmp_len);
        if(rc != SCARD_S_SUCCESS) {
          if(state->verbose) {
            fprintf (stderr, "error: SCardTransmit failed, rc=%08lx\n", rc);
          }
          return YKPIV_PCSC_ERROR;
        }
    */

    *recv_len = tmp_len;
    if (*state).verbose > 1i32 {
        eprint!("< ");
        dump_hex(data as (*const u8), *recv_len);
        eprintln!();
    }
    if *recv_len >= 2u32 {
        *sw = *data.offset((*recv_len).wrapping_sub(2u32) as (isize)) as (i32) << 8i32
            | *data.offset((*recv_len).wrapping_sub(1u32) as (isize)) as (i32);
    } else {
        *sw = 0i32;
    }
    ErrorKind::YKPIV_OK
}

#[derive(Clone, Copy)]
#[repr(i32)]
#[allow(non_camel_case_types)]
pub enum Enum6 {
    DES_OK = 0i32,
    DES_INVALID_PARAMETER = -1i32,
    DES_BUFFER_TOO_SMALL = -2i32,
    DES_MEMORY_ERROR = -3i32,
    DES_GENERAL_ERROR = -4i32,
}

pub fn ykpiv_authenticate(mut state: *mut ykpiv_state, mut key: *const u8) -> ErrorKind {
    let mut apdu: APDU;
    let mut data: [u8; 261];
    let mut challenge: [u8; 8];
    let mut recv_len: u32 = mem::size_of::<[u8; 261]>() as (u32);
    let mut sw: i32;
    let mut res: ErrorKind;
    let mut drc: Enum6 = Enum6::DES_OK;
    let mut mgm_key: *mut DesKey = 0i32 as (*mut c_void) as (*mut DesKey);
    let mut out_len: usize = 0usize;
    if 0i32 as (*mut c_void) as (*mut ykpiv_state) == state {
        ErrorKind::YKPIV_GENERIC_ERROR
    } else if ErrorKind::YKPIV_OK as (i32) != {
        res = _ykpiv_begin_transaction(state);
        res
    } as (i32)
    {
        ErrorKind::YKPIV_PCSC_ERROR
    } else {
        if !(ErrorKind::YKPIV_OK as (i32) != {
            res = _ykpiv_ensure_application_selected(state);
            res
        } as (i32))
        {
            if 0i32 as (*mut c_void) as (*const u8) == key {
                key = (*b"\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08\0").as_ptr(
                      );
            }
            if Enum6::DES_OK as (i32)
                != des_import_key(
                    1i32,
                    key,
                    (8i32 * 3i32) as (usize),
                    &mut mgm_key as (*mut *mut DesKey),
                ) as (i32)
            {
                res = ErrorKind::YKPIV_ALGORITHM_ERROR;
            } else {
                // get a challenge from the card
                // FIXME(tarcieri): Translate C code below
                /*
                  {
                    memset(apdu.raw, 0, sizeof(apdu));
                    apdu.st.ins = YKPIV_INS_AUTHENTICATE;
                    apdu.st.p1 = YKPIV_ALGO_3DES; // triple des
                    apdu.st.p2 = YKPIV_KEY_CARDMGM; // management key
                    apdu.st.lc = 0x04;
                    apdu.st.data[0] = 0x7c;
                    apdu.st.data[1] = 0x02;
                    apdu.st.data[2] = 0x80;
                    if ((res = _send_data(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
                      goto Cleanup;
                    }
                    else if (sw != SW_SUCCESS) {
                      res = YKPIV_AUTHENTICATION_ERROR;
                      goto Cleanup;
                    }
                    memcpy(challenge, data + 4, 8);
                  }
                */

                // send a response to the cards challenge and a challenge of our own.
                // FIXME(tarcieri): Translate C code below
                /*
                  {
                    unsigned char *dataptr = apdu.st.data;
                    unsigned char response[8];
                    out_len = sizeof(response);
                    drc = des_decrypt(mgm_key, challenge, sizeof(challenge), response, &out_len);

                    if (drc != DES_OK) {
                      res = YKPIV_AUTHENTICATION_ERROR;
                      goto Cleanup;
                    }

                    recv_len = sizeof(data);
                    memset(apdu.raw, 0, sizeof(apdu));
                    apdu.st.ins = YKPIV_INS_AUTHENTICATE;
                    apdu.st.p1 = YKPIV_ALGO_3DES; // triple des
                    apdu.st.p2 = YKPIV_KEY_CARDMGM; // management key
                    *dataptr++ = 0x7c;
                    *dataptr++ = 20; // 2 + 8 + 2 +8
                    *dataptr++ = 0x80;
                    *dataptr++ = 8;
                    memcpy(dataptr, response, 8);
                    dataptr += 8;
                    *dataptr++ = 0x81;
                    *dataptr++ = 8;
                    if (PRNG_GENERAL_ERROR == _ykpiv_prng_generate(dataptr, 8)) {
                      if (state->verbose) {
                        fprintf(stderr, "Failed getting randomness for authentication.\n");
                      }
                      res = YKPIV_RANDOMNESS_ERROR;
                      goto Cleanup;
                    }
                    memcpy(challenge, dataptr, 8);
                    dataptr += 8;
                    apdu.st.lc = (unsigned char)(dataptr - apdu.st.data);
                    if ((res = _send_data(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
                      goto Cleanup;
                    }
                    else if (sw != SW_SUCCESS) {
                      res = YKPIV_AUTHENTICATION_ERROR;
                      goto Cleanup;
                    }
                  }
                */
                let mut response: [u8; 8];
                out_len = mem::size_of::<[u8; 8]>();
                drc = des_encrypt(
                    mgm_key,
                    challenge.as_mut_ptr() as (*const u8),
                    mem::size_of::<[u8; 8]>(),
                    response.as_mut_ptr(),
                    &mut out_len as (*mut usize),
                );
                if drc as (i32) != Enum6::DES_OK as (i32) {
                    res = ErrorKind::YKPIV_AUTHENTICATION_ERROR;
                } else if memcmp(
                    response.as_mut_ptr() as (*const c_void),
                    data.as_mut_ptr().offset(4isize) as (*const c_void),
                    8usize,
                ) == 0i32
                {
                    res = ErrorKind::YKPIV_OK;
                } else {
                    res = ErrorKind::YKPIV_AUTHENTICATION_ERROR;
                }
            }
        }
        if !mgm_key.is_null() {
            des_destroy_key(mgm_key);
        }
        _ykpiv_end_transaction(state);
        res
    }
}

pub fn ykpiv_set_mgmkey(mut state: *mut ykpiv_state, mut new_key: *const u8) -> ErrorKind {
    ykpiv_set_mgmkey2(state, new_key, 0u8)
}

pub fn ykpiv_set_mgmkey2(
    mut state: *mut ykpiv_state,
    mut new_key: *const u8,
    touch: u8,
) -> ErrorKind {
    let mut data: [u8; 261];
    let mut recv_len: u32 = mem::size_of::<[u8; 261]>() as (u32);
    let mut sw: i32;
    let mut res: ErrorKind = ErrorKind::YKPIV_OK;
    let mut apdu = APDU::default();

    if _ykpiv_begin_transaction(state) != ErrorKind::YKPIV_OK {
        return ErrorKind::YKPIV_PCSC_ERROR;
    }

    if _ykpiv_ensure_application_selected(state) == ErrorKind::YKPIV_OK {
        if yk_des_is_weak_key(new_key, (8i32 * 3i32) as (usize)) {
            if (*state).verbose != 0 {
                // TODO(tarcieri): format string
                eprint!("Won\'t set new key \'");
                dump_hex(new_key, DES_LEN_3DES as u32);
                eprintln!("\' since it\'s weak (with odd parity).");
            }
            res = ErrorKind::YKPIV_KEY_ERROR;
            apdu.ins = YKPIV_INS_SET_MGMKEY;
            apdu.p1 = 0xff;

            apdu.p2 = match touch {
                0 => 0xff,
                1 => 0xfe,
                _ => {
                    _ykpiv_end_transaction(state);
                    return ErrorKind::YKPIV_GENERIC_ERROR;
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
            res = _send_data(
                state,
                &mut apdu as (*mut APDU),
                data.as_mut_ptr(),
                &mut recv_len as (*mut u32),
                &mut sw as (*mut i32),
            );

            if res != ErrorKind::YKPIV_OK {
                if !(sw == 0x9000i32) {
                    res = ErrorKind::YKPIV_GENERIC_ERROR;
                }
            }
        }
    }

    apdu.zeroize();
    _ykpiv_end_transaction(state);
    res
}

const HEX_TABLE: &[u8] = b"0123456789abcdef";

pub fn ykpiv_hex_decode(
    mut hex_in: *const u8,
    mut in_len: usize,
    mut hex_out: *mut u8,
    mut out_len: *mut usize,
) -> ErrorKind {
    let mut _currentBlock;
    let mut i: usize;
    let mut first: bool = true;

    if *out_len < in_len.wrapping_div(2) {
        return ErrorKind::YKPIV_SIZE_ERROR;
    }

    if in_len.wrapping_rem(2) != 0 {
        return ErrorKind::YKPIV_SIZE_ERROR;
    }

    *out_len = in_len.wrapping_div(2usize);
    i = 0usize;

    while i < in_len {
        let mut ind_ptr: *mut c_char = strchr(
            HEX_TABLE.as_ptr() as *const c_char,
            tolower(*{
                let _old = hex_in;
                hex_in = hex_in.offset(1isize);
                _old
            } as (i32)),
        );

        if ind_ptr.is_null() {
            _currentBlock = 6;
            break;
        }

        let index = ind_ptr as usize - HEX_TABLE.as_ptr() as usize;

        if first {
            *hex_out = (index << 4i32) as (u8);
        } else {
            let _rhs = index;

            let _lhs = &mut *{
                let _old = hex_out;
                hex_out = hex_out.offset(1isize);
                _old
            };

            *_lhs = (*_lhs as usize | _rhs) as (u8);
        }

        first = !first;
        i = i.wrapping_add(1usize);
    }

    if _currentBlock == 4 {
        ErrorKind::YKPIV_OK
    } else {
        ErrorKind::YKPIV_PARSE_ERROR
    }
}

unsafe fn _general_authenticate(
    mut state: *mut ykpiv_state,
    mut sign_in: *const u8,
    mut in_len: usize,
    mut out: *mut u8,
    mut out_len: *mut usize,
    mut algorithm: u8,
    mut key: u8,
    mut decipher: bool,
) -> ErrorKind {
    let mut _currentBlock;
    let mut indata: [u8; 1024];
    let mut dataptr: *mut u8 = indata.as_mut_ptr();
    let mut data: [u8; 1024];
    let mut templ: *mut u8 = 0i32 as (*mut u8);
    let mut recv_len: usize = mem::size_of::<[u8; 1024]>();
    let mut key_len: usize = 0usize;
    let mut sw: i32 = 0i32;
    let mut bytes: usize;
    let mut len: usize = 0usize;
    let mut res: ErrorKind;
    if algorithm as (i32) == 0x14i32 {
        _currentBlock = 12;
    } else if algorithm as (i32) == 0x11i32 {
        key_len = 32usize;
        _currentBlock = 12;
    } else {
        if !(algorithm as (i32) == 0x7i32) {
            if algorithm as (i32) == 0x6i32 {
                key_len = 128usize;
            } else {
                return ErrorKind::YKPIV_ALGORITHM_ERROR;
            }
        }
        if key_len == 0usize {
            key_len = 256usize;
        }
        if in_len != key_len {
            return ErrorKind::YKPIV_SIZE_ERROR;
        } else {
            _currentBlock = 16;
        }
    }
    if _currentBlock == 12 {
        if key_len == 0usize {
            key_len = 48usize;
        }
        if !decipher && (in_len > key_len) {
            return ErrorKind::YKPIV_SIZE_ERROR;
        } else if decipher && (in_len != key_len.wrapping_mul(2usize).wrapping_add(1usize)) {
            return ErrorKind::YKPIV_SIZE_ERROR;
        }
    }
    if in_len < 0x80usize {
        bytes = 1usize;
    } else if in_len < 0xffusize {
        bytes = 2usize;
    } else {
        bytes = 3usize;
    }
    *{
        let _old = dataptr;
        dataptr = dataptr.offset(1isize);
        _old
    } = 0x7cu8;
    dataptr = dataptr
        .offset(
            _ykpiv_set_length(dataptr, in_len.wrapping_add(bytes).wrapping_add(3usize)) as (isize),
        );
    *{
        let _old = dataptr;
        dataptr = dataptr.offset(1isize);
        _old
    } = 0x82u8;
    *{
        let _old = dataptr;
        dataptr = dataptr.offset(1isize);
        _old
    } = 0x0u8;
    *{
        let _old = dataptr;
        dataptr = dataptr.offset(1isize);
        _old
    } = if (algorithm as (i32) == 0x11i32 || algorithm as (i32) == 0x14i32) && decipher {
        0x85i32
    } else {
        0x81i32
    } as (u8);
    dataptr = dataptr.offset(_ykpiv_set_length(dataptr, in_len) as (isize));
    memcpy(dataptr as (*mut c_void), sign_in as (*const c_void), in_len);
    dataptr = dataptr.offset(in_len as (isize));
    if {
        res = ykpiv_transfer_data(
            state,
            templ as (*const u8),
            indata.as_mut_ptr() as (*const u8),
            (dataptr as (isize)).wrapping_sub(indata.as_mut_ptr() as (isize))
                / mem::size_of::<u8>() as (isize),
            data.as_mut_ptr(),
            &mut recv_len as (*mut usize),
            &mut sw as (*mut i32),
        );
        res
    } as (i32)
        != ErrorKind::YKPIV_OK as (i32)
    {
        if (*state).verbose != 0 {
            eprintln!("Sign command failed to communicate.");
        }
        res
    } else if sw != 0x9000i32 {
        if (*state).verbose != 0 {
            eprintln!("Failed sign command with code {:x}.\n\0", sw);
        }
        (if sw == 0x6982i32 {
            ErrorKind::YKPIV_AUTHENTICATION_ERROR
        } else {
            ErrorKind::YKPIV_GENERIC_ERROR
        })
    } else if data[0usize] as (i32) != 0x7ci32 {
        if (*state).verbose != 0 {
            eprintln!("Failed parsing signature reply.");
        }
        ErrorKind::YKPIV_PARSE_ERROR
    } else {
        dataptr = data.as_mut_ptr().offset(1isize);
        dataptr = dataptr.offset(_ykpiv_get_length(dataptr, &mut len as (*mut usize)) as (isize));
        (if *dataptr as (i32) != 0x82i32 {
            if (*state).verbose != 0 {
                eprintln!("Failed parsing signature reply.");
            }
            ErrorKind::YKPIV_PARSE_ERROR
        } else {
            dataptr = dataptr.offset(1isize);
            dataptr =
                dataptr.offset(_ykpiv_get_length(dataptr, &mut len as (*mut usize)) as (isize));
            (if len > *out_len {
                if (*state).verbose != 0 {
                    eprintln!("Wrong size on output buffer.");
                }
                ErrorKind::YKPIV_SIZE_ERROR
            } else {
                *out_len = len;
                memcpy(out as (*mut c_void), dataptr as (*const c_void), len);
                ErrorKind::YKPIV_OK
            })
        })
    }
}

pub fn ykpiv_sign_data(
    mut state: *mut ykpiv_state,
    mut raw_in: *const u8,
    mut in_len: usize,
    mut sign_out: *mut u8,
    mut out_len: *mut usize,
    mut algorithm: u8,
    mut key: u8,
) -> ErrorKind {
    let mut res: ErrorKind = ErrorKind::YKPIV_OK;
    if 0i32 as (*mut c_void) as (*mut ykpiv_state) == state {
        ErrorKind::YKPIV_GENERIC_ERROR
    } else if ErrorKind::YKPIV_OK as (i32) != {
        res = _ykpiv_begin_transaction(state);
        res
    } as (i32)
    {
        ErrorKind::YKPIV_PCSC_ERROR
    } else {
        res = _general_authenticate(
            state, raw_in, in_len, sign_out, out_len, algorithm, key, false,
        );
        _ykpiv_end_transaction(state);
        res
    }
}

pub fn ykpiv_decipher_data(
    mut state: *mut ykpiv_state,
    mut in_: *const u8,
    mut in_len: usize,
    mut out: *mut u8,
    mut out_len: *mut usize,
    mut algorithm: u8,
    mut key: u8,
) -> ErrorKind {
    let mut res: ErrorKind = ErrorKind::YKPIV_OK;
    if 0i32 as (*mut c_void) as (*mut ykpiv_state) == state {
        ErrorKind::YKPIV_GENERIC_ERROR
    } else if ErrorKind::YKPIV_OK as (i32) != {
        res = _ykpiv_begin_transaction(state);
        res
    } as (i32)
    {
        ErrorKind::YKPIV_PCSC_ERROR
    } else {
        res = _general_authenticate(state, in_, in_len, out, out_len, algorithm, key, true);
        _ykpiv_end_transaction(state);
        res
    }
}

unsafe fn _ykpiv_get_version(
    mut state: *mut ykpiv_state,
    mut p_version: *mut _ykpiv_version_t,
) -> ErrorKind {
    let mut apdu: APDU;
    let mut data: [u8; 261];
    let mut recv_len: u32 = mem::size_of::<[u8; 261]>() as (u32);
    let mut sw: i32;
    let mut res: ErrorKind;
    if state.is_null() {
        ErrorKind::YKPIV_ARGUMENT_ERROR
    } else if (*state).ver.major != 0 || (*state).ver.minor != 0 || (*state).ver.patch != 0 {
        if !p_version.is_null() {
            memcpy(
                p_version as (*mut c_void),
                &mut (*state).ver as (*mut _ykpiv_version_t) as (*const c_void),
                mem::size_of::<_ykpiv_version_t>(),
            );
        }
        ErrorKind::YKPIV_OK
    // get version from device
    // FIXME(tarcieri): Translate C code below (should go after the else clause)
    /*
        memset(apdu.raw, 0, sizeof(apdu));
        apdu.st.ins = YKPIV_INS_GET_VERSION;
    */
    } else if {
        res = _send_data(
            state,
            &mut apdu as (*mut APDU),
            data.as_mut_ptr(),
            &mut recv_len as (*mut u32),
            &mut sw as (*mut i32),
        );
        res
    } as (i32)
        != ErrorKind::YKPIV_OK as (i32)
    {
        res
    } else {
        if sw == 0x9000i32 {
            if recv_len < 3u32 {
                return ErrorKind::YKPIV_SIZE_ERROR;
            } else {
                (*state).ver.major = data[0usize];
                (*state).ver.minor = data[1usize];
                (*state).ver.patch = data[2usize];
                if !p_version.is_null() {
                    memcpy(
                        p_version as (*mut c_void),
                        &mut (*state).ver as (*mut _ykpiv_version_t) as (*const c_void),
                        mem::size_of::<_ykpiv_version_t>(),
                    );
                }
            }
        } else {
            res = ErrorKind::YKPIV_GENERIC_ERROR;
        }
        res
    }
}

pub fn ykpiv_get_version(
    mut state: *mut ykpiv_state,
    mut version: *mut u8,
    mut len: usize,
) -> ErrorKind {
    let mut res: ErrorKind;
    let mut result: i32 = 0i32;
    let mut ver: _ykpiv_version_t = _ykpiv_version_t {
        major: 0u8,
        minor: 0u8,
        patch: 0u8,
    };
    if {
        res = _ykpiv_begin_transaction(state);
        res
    } as (i32)
        < ErrorKind::YKPIV_OK as (i32)
    {
        ErrorKind::YKPIV_PCSC_ERROR
    } else {
        if !({
            res = _ykpiv_ensure_application_selected(state);
            res
        } as (i32)
            < ErrorKind::YKPIV_OK as (i32))
        {
            if {
                res = _ykpiv_get_version(state, &mut ver as (*mut _ykpiv_version_t));
                res
            } as (i32)
                >= ErrorKind::YKPIV_OK as (i32)
            {
                result = snprintf(
                    version,
                    len,
                    (*b"%d.%d.%d\0").as_ptr(),
                    ver.major as (i32),
                    ver.minor as (i32),
                    ver.patch as (i32),
                );
                if result < 0i32 {
                    res = ErrorKind::YKPIV_SIZE_ERROR;
                }
            }
        }
        _ykpiv_end_transaction(state);
        res
    }
}

unsafe fn _ykpiv_get_serial(
    mut state: *mut ykpiv_state,
    mut p_serial: *mut u32,
    mut f_force: bool,
) -> ErrorKind {
    let mut _currentBlock;
    let mut res: ErrorKind = ErrorKind::YKPIV_OK;
    let mut apdu: APDU;
    let mut yk_applet: *const u8 = 0xa0i32 as (*const u8);
    let mut data: [u8; 255];
    let mut recv_len: u32 = mem::size_of::<[u8; 255]>() as (u32);
    let mut sw: i32;
    let mut p_temp: *mut u8 = 0i32 as (*mut c_void) as (*mut u8);
    if state.is_null() {
        ErrorKind::YKPIV_ARGUMENT_ERROR
    } else if !f_force && ((*state).serial != 0u32) {
        if !p_serial.is_null() {
            *p_serial = (*state).serial;
        }
        ErrorKind::YKPIV_OK
    } else {
        if (*state).ver.major as (i32) < 5i32 {
            let mut temp: [u8; 255];
            recv_len = mem::size_of::<[u8; 255]>() as (u32);
            // FIXME(tarcieri): Translate C code below
            /*
                memset(apdu.raw, 0, sizeof(apdu));
                apdu.st.ins = YKPIV_INS_SELECT_APPLICATION;
                apdu.st.p1 = 0x04;
                apdu.st.lc = sizeof(yk_applet);
                memcpy(apdu.st.data, yk_applet, sizeof(yk_applet));
            */
            if {
                res = _send_data(
                    state,
                    &mut apdu as (*mut APDU),
                    temp.as_mut_ptr(),
                    &mut recv_len as (*mut u32),
                    &mut sw as (*mut i32),
                );
                res
            } as (i32)
                < ErrorKind::YKPIV_OK as (i32)
            {
                if (*state).verbose != 0 {
                    eprintln!(
                        "Failed communicating with card: \'{}\'",
                        ykpiv_strerror(res)
                    );
                    _currentBlock = 37;
                } else {
                    _currentBlock = 37;
                }
            } else if sw != 0x9000i32 {
                if (*state).verbose != 0 {
                    eprintln!("Failed selecting yk application: {:04x}", sw);
                }
                res = ErrorKind::YKPIV_GENERIC_ERROR;
                _currentBlock = 37;
            } else {
                recv_len = mem::size_of::<[u8; 255]>() as (u32);
                // FIXME(tarcieri): Translate C code below
                /*
                  memset(apdu.raw, 0, sizeof(apdu));
                  apdu.st.ins = 0x01;
                  apdu.st.p1 = 0x10;
                  apdu.st.lc = 0x00;
                */
                if {
                    res = _send_data(
                        state,
                        &mut apdu as (*mut APDU),
                        data.as_mut_ptr(),
                        &mut recv_len as (*mut u32),
                        &mut sw as (*mut i32),
                    );
                    res
                } as (i32)
                    < ErrorKind::YKPIV_OK as (i32)
                {
                    if (*state).verbose != 0 {
                        eprintln!(
                            "Failed communicating with card: \'{}\'",
                            ykpiv_strerror(res)
                        );
                        _currentBlock = 37;
                    } else {
                        _currentBlock = 37;
                    }
                } else if sw != 0x9000i32 {
                    if (*state).verbose != 0 {
                        eprintln!("Failed retrieving serial number: {:04x}", sw);
                    }
                    res = ErrorKind::YKPIV_GENERIC_ERROR;
                    _currentBlock = 37;
                } else {
                    recv_len = mem::size_of::<[u8; 255]>() as (u32);
                    // FIXME(tarcieri): Translate C code below
                    /*
                      memset(apdu.raw, 0, sizeof(apdu));
                      apdu.st.ins = YKPIV_INS_SELECT_APPLICATION;
                      apdu.st.p1 = 0x04;
                      apdu.st.lc = (unsigned char)sizeof(aid);
                      memcpy(apdu.st.data, aid, sizeof(aid));
                    */
                    if {
                        res = _send_data(
                            state,
                            &mut apdu as (*mut APDU),
                            temp.as_mut_ptr(),
                            &mut recv_len as (*mut u32),
                            &mut sw as (*mut i32),
                        );
                        res
                    } as (i32)
                        < ErrorKind::YKPIV_OK as (i32)
                    {
                        if (*state).verbose != 0 {
                            eprintln!(
                                "Failed communicating with card: \'{}\'",
                                ykpiv_strerror(res)
                            );
                        }
                        return res;
                    } else if sw != 0x9000i32 {
                        if (*state).verbose != 0 {
                            eprintln!("Failed selecting application: {:04x}", sw);
                        }
                        return ErrorKind::YKPIV_GENERIC_ERROR;
                    }
                    _currentBlock = 17;
                }
            }
        } else {
            // get serial from yk5 and later devices using the f8 command
            // FIXME(tarcieri): Translate C code below
            /*
                memset(apdu.raw, 0, sizeof(apdu));
                apdu.st.ins = YKPIV_INS_GET_SERIAL;
            */

            if {
                res = _send_data(
                    state,
                    &mut apdu as (*mut APDU),
                    data.as_mut_ptr(),
                    &mut recv_len as (*mut u32),
                    &mut sw as (*mut i32),
                );
                res
            } as (i32)
                != ErrorKind::YKPIV_OK as (i32)
            {
                if (*state).verbose != 0 {
                    eprintln!(
                        "Failed communicating with card: \'{}\'",
                        ykpiv_strerror(res)
                    );
                }
                return res;
            } else if sw != 0x9000i32 {
                if (*state).verbose != 0 {
                    eprintln!("Failed retrieving serial number: {:04x}", sw);
                }
                return ErrorKind::YKPIV_GENERIC_ERROR;
            }
            _currentBlock = 17;
        }
        if _currentBlock == 17 {
            if recv_len < 4u32 {
                return ErrorKind::YKPIV_SIZE_ERROR;
            } else {
                p_temp = &mut (*state).serial as (*mut u32) as (*mut u8);
                *{
                    let _old = p_temp;
                    p_temp = p_temp.offset(1isize);
                    _old
                } = data[3usize];
                *{
                    let _old = p_temp;
                    p_temp = p_temp.offset(1isize);
                    _old
                } = data[2usize];
                *{
                    let _old = p_temp;
                    p_temp = p_temp.offset(1isize);
                    _old
                } = data[1usize];
                *{
                    let _old = p_temp;
                    p_temp = p_temp.offset(1isize);
                    _old
                } = data[0usize];
                if !p_serial.is_null() {
                    *p_serial = (*state).serial;
                }
            }
        }
        res
    }
}

pub fn ykpiv_get_serial(mut state: *mut ykpiv_state, mut p_serial: *mut u32) -> ErrorKind {
    let mut res: ErrorKind = ErrorKind::YKPIV_OK;
    if {
        res = _ykpiv_begin_transaction(state);
        res
    } as (i32)
        != ErrorKind::YKPIV_OK as (i32)
    {
        ErrorKind::YKPIV_PCSC_ERROR
    } else {
        if !({
            res = _ykpiv_ensure_application_selected(state);
            res
        } as (i32)
            != ErrorKind::YKPIV_OK as (i32))
        {
            res = _ykpiv_get_serial(state, p_serial, false);
        }
        _ykpiv_end_transaction(state);
        res
    }
}

unsafe fn _cache_pin(
    mut state: *mut ykpiv_state,
    mut pin: *const c_char,
    mut len: usize,
) -> ErrorKind {
    if state.is_null() {
        return ErrorKind::YKPIV_ARGUMENT_ERROR;
    }

    if !pin.is_null() && ((*state).pin as *const c_char == pin) {
        return ErrorKind::YKPIV_OK;
    }

    if !(*state).pin.is_null() {
        memset_s(
            (*state).pin as (*mut c_void),
            strnlen((*state).pin as *const c_char, 8),
            0,
            strnlen((*state).pin as *const c_char, 8),
        );
        free((*state).pin as (*mut c_void));
        (*state).pin = ptr::null_mut();
    }
    if !pin.is_null() && (len > 0) {
        (*state).pin = malloc(len + 1) as (*mut u8);
        if (*state).pin == 0i32 as (*mut c_void) as (*mut u8) {
            return ErrorKind::YKPIV_MEMORY_ERROR;
        } else {
            memcpy((*state).pin as (*mut c_void), pin as (*const c_void), len);
            *(*state).pin.offset(len as (isize)) = 0u8;
        }
    }

    ErrorKind::YKPIV_OK
}

pub fn ykpiv_verify(
    mut state: *mut ykpiv_state,
    mut pin: *const c_char,
    mut tries: *mut i32,
) -> ErrorKind {
    ykpiv_verify_select(
        state,
        pin,
        if !pin.is_null() { strlen(pin) } else { 0 },
        tries,
        false,
    )
}

unsafe fn _verify(
    mut state: *mut ykpiv_state,
    mut pin: *const c_char,
    pin_len: usize,
    mut tries: *mut i32,
) -> ErrorKind {
    let mut apdu: APDU;
    let mut data: [u8; 261];
    let mut recv_len: u32 = mem::size_of::<[u8; 261]>() as (u32);
    let mut sw: i32;
    let mut res: ErrorKind;
    if pin_len > 8usize {
        ErrorKind::YKPIV_SIZE_ERROR
    } else {
        // FIXME(tarcieri): Translate C code below
        /*
            memset(apdu.raw, 0, sizeof(apdu.raw));
            apdu.st.ins = YKPIV_INS_VERIFY;
            apdu.st.p1 = 0x00;
            apdu.st.p2 = 0x80;
            apdu.st.lc = pin ? 0x08 : 0;
            if (pin) {
              memcpy(apdu.st.data, pin, pin_len);
              if (pin_len < CB_PIN_MAX) {
                memset(apdu.st.data + pin_len, 0xff, CB_PIN_MAX - pin_len);
              }
            }
        */
        res = _send_data(
            state,
            &mut apdu as (*mut APDU),
            data.as_mut_ptr(),
            &mut recv_len as (*mut u32),
            &mut sw as (*mut i32),
        );
        memset_s(
            &mut apdu as (*mut APDU) as (*mut c_void),
            mem::size_of::<APDU>(),
            0i32,
            mem::size_of::<APDU>(),
        );
        (if res as (i32) != ErrorKind::YKPIV_OK as (i32) {
            res
        } else if sw == 0x9000i32 {
            if !pin.is_null() && (pin_len != 0) {
                _cache_pin(state, pin, pin_len);
            }
            if !tries.is_null() {
                *tries = sw & 0xfi32;
            }
            ErrorKind::YKPIV_OK
        } else if sw >> 8i32 == 0x63i32 {
            if !tries.is_null() {
                *tries = sw & 0xfi32;
            }
            ErrorKind::YKPIV_WRONG_PIN
        } else if sw == 0x6983i32 {
            if !tries.is_null() {
                *tries = 0i32;
            }
            ErrorKind::YKPIV_WRONG_PIN
        } else {
            ErrorKind::YKPIV_GENERIC_ERROR
        })
    }
}

pub fn ykpiv_verify_select(
    mut state: *mut ykpiv_state,
    mut pin: *const c_char,
    pin_len: usize,
    mut tries: *mut i32,
    mut force_select: bool,
) -> ErrorKind {
    let mut _currentBlock;
    let mut res: ErrorKind = ErrorKind::YKPIV_OK;
    if ErrorKind::YKPIV_OK as (i32) != {
        res = _ykpiv_begin_transaction(state);
        res
    } as (i32)
    {
        ErrorKind::YKPIV_PCSC_ERROR
    } else {
        if force_select {
            if ErrorKind::YKPIV_OK as (i32) != {
                res = _ykpiv_ensure_application_selected(state);
                res
            } as (i32)
            {
                _currentBlock = 4;
            } else {
                _currentBlock = 3;
            }
        } else {
            _currentBlock = 3;
        }
        if _currentBlock == 3 {
            res = _verify(state, pin, pin_len, tries);
        }
        _ykpiv_end_transaction(state);
        res
    }
}

pub fn ykpiv_get_pin_retries(mut state: *mut ykpiv_state, mut tries: *mut i32) -> ErrorKind {
    let mut res: ErrorKind;
    let mut ykrc: ErrorKind;

    if state.is_null() || tries.is_null() {
        return ErrorKind::YKPIV_ARGUMENT_ERROR;
    }

    res = _ykpiv_select_application(state);

    if res != ErrorKind::YKPIV_OK {
        return res;
    }

    ykrc = ykpiv_verify(state, ptr::null(), tries);

    if ykrc == ErrorKind::YKPIV_WRONG_PIN {
        ErrorKind::YKPIV_OK
    } else {
        ykrc
    }
}

pub fn ykpiv_set_pin_retries(
    mut state: *mut ykpiv_state,
    mut pin_tries: i32,
    mut puk_tries: i32,
) -> ErrorKind {
    let mut res: ErrorKind = ErrorKind::YKPIV_OK;
    let mut templ: *mut u8 = 0i32 as (*mut u8);
    let mut data: [u8; 255];
    let mut recv_len: usize = mem::size_of::<[u8; 255]>();
    let mut sw: i32 = 0i32;
    if pin_tries == 0i32 || puk_tries == 0i32 {
        ErrorKind::YKPIV_OK
    } else if pin_tries > 0xffi32 || puk_tries > 0xffi32 || pin_tries < 1i32 || puk_tries < 1i32 {
        ErrorKind::YKPIV_RANGE_ERROR
    } else {
        *templ.offset(2isize) = pin_tries as (u8);
        *templ.offset(3isize) = puk_tries as (u8);
        (if ErrorKind::YKPIV_OK as (i32) != {
            res = _ykpiv_begin_transaction(state);
            res
        } as (i32)
        {
            ErrorKind::YKPIV_PCSC_ERROR
        } else {
            if !(ErrorKind::YKPIV_OK as (i32) != {
                res = _ykpiv_ensure_application_selected(state);
                res
            } as (i32))
            {
                res = ykpiv_transfer_data(
                    state,
                    templ as (*const u8),
                    0i32 as (*mut c_void) as (*const u8),
                    0isize,
                    data.as_mut_ptr(),
                    &mut recv_len as (*mut usize),
                    &mut sw as (*mut i32),
                );
                if ErrorKind::YKPIV_OK as (i32) == res as (i32) {
                    if !(0x9000i32 == sw) {
                        if sw == 0x6983i32 {
                            res = ErrorKind::YKPIV_AUTHENTICATION_ERROR;
                        } else if sw == 0x6982i32 {
                            res = ErrorKind::YKPIV_AUTHENTICATION_ERROR;
                        } else {
                            res = ErrorKind::YKPIV_GENERIC_ERROR;
                        }
                    }
                }
            }
            _ykpiv_end_transaction(state);
            res
        })
    }
}

unsafe fn _ykpiv_change_pin(
    mut state: *mut ykpiv_state,
    mut action: i32,
    mut current_pin: *const c_char,
    mut current_pin_len: usize,
    mut new_pin: *const c_char,
    mut new_pin_len: usize,
    mut tries: *mut i32,
) -> ErrorKind {
    let mut sw: i32;
    let mut templ: *mut u8 = 0i32 as (*mut u8);
    let mut indata: [u8; 16];
    let mut data: [u8; 255];
    let mut recv_len: usize = mem::size_of::<[u8; 255]>();
    let mut res: ErrorKind;
    if current_pin_len > 8usize {
        ErrorKind::YKPIV_SIZE_ERROR
    } else if new_pin_len > 8usize {
        ErrorKind::YKPIV_SIZE_ERROR
    } else {
        if action == 1i32 {
            *templ.offset(1isize) = 0x2cu8;
        } else if action == 2i32 {
            *templ.offset(3isize) = 0x81u8;
        }
        memcpy(
            indata.as_mut_ptr() as (*mut c_void),
            current_pin as (*const c_void),
            current_pin_len,
        );
        if current_pin_len < 8usize {
            memset(
                indata.as_mut_ptr().offset(current_pin_len as (isize)) as (*mut c_void),
                0xffi32,
                8usize.wrapping_sub(current_pin_len),
            );
        }
        memcpy(
            indata.as_mut_ptr().offset(8isize) as (*mut c_void),
            new_pin as (*const c_void),
            new_pin_len,
        );
        if new_pin_len < 8usize {
            memset(
                indata
                    .as_mut_ptr()
                    .offset(8isize)
                    .offset(new_pin_len as (isize)) as (*mut c_void),
                0xffi32,
                8usize.wrapping_sub(new_pin_len),
            );
        }
        res = ykpiv_transfer_data(
            state,
            templ as (*const u8),
            indata.as_mut_ptr() as (*const u8),
            mem::size_of::<[u8; 16]>() as (isize),
            data.as_mut_ptr(),
            &mut recv_len as (*mut usize),
            &mut sw as (*mut i32),
        );
        memset_s(
            indata.as_mut_ptr() as (*mut c_void),
            mem::size_of::<[u8; 16]>(),
            0i32,
            mem::size_of::<[u8; 16]>(),
        );
        (if res as (i32) != ErrorKind::YKPIV_OK as (i32) {
            res
        } else if sw != 0x9000i32 {
            (if sw >> 8i32 == 0x63i32 {
                if !tries.is_null() {
                    *tries = sw & 0xfi32;
                }
                ErrorKind::YKPIV_WRONG_PIN
            } else if sw == 0x6983i32 {
                ErrorKind::YKPIV_PIN_LOCKED
            } else {
                if (*state).verbose != 0 {
                    eprintln!("Failed changing pin, token response code: {:x}.", sw);
                }
                ErrorKind::YKPIV_GENERIC_ERROR
            })
        } else {
            ErrorKind::YKPIV_OK
        })
    }
}

pub fn ykpiv_change_pin(
    mut state: *mut ykpiv_state,
    mut current_pin: *const c_char,
    mut current_pin_len: usize,
    mut new_pin: *const c_char,
    mut new_pin_len: usize,
    mut tries: *mut i32,
) -> ErrorKind {
    let mut res: ErrorKind = ErrorKind::YKPIV_GENERIC_ERROR;

    if _ykpiv_begin_transaction(state) != ErrorKind::YKPIV_OK {
        return ErrorKind::YKPIV_PCSC_ERROR;
    }

    if _ykpiv_ensure_application_selected(state) == ErrorKind::YKPIV_OK {
        res = _ykpiv_change_pin(
            state,
            0i32,
            current_pin,
            current_pin_len,
            new_pin,
            new_pin_len,
            tries,
        );

        if res == ErrorKind::YKPIV_OK && !new_pin.is_null() {
            _cache_pin(state, new_pin, new_pin_len);
        }
    }

    _ykpiv_end_transaction(state);
    res
}

pub fn ykpiv_change_puk(
    mut state: *mut ykpiv_state,
    mut current_puk: *const c_char,
    mut current_puk_len: usize,
    mut new_puk: *const c_char,
    mut new_puk_len: usize,
    mut tries: *mut i32,
) -> ErrorKind {
    let mut res = ErrorKind::YKPIV_GENERIC_ERROR;

    if _ykpiv_begin_transaction(state) != ErrorKind::YKPIV_OK {
        return ErrorKind::YKPIV_PCSC_ERROR;
    }

    if _ykpiv_ensure_application_selected(state) == ErrorKind::YKPIV_OK {
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

pub fn ykpiv_unblock_pin(
    mut state: *mut ykpiv_state,
    mut puk: *const c_char,
    mut puk_len: usize,
    mut new_pin: *const c_char,
    mut new_pin_len: usize,
    mut tries: *mut i32,
) -> ErrorKind {
    let mut res: ErrorKind = ErrorKind::YKPIV_GENERIC_ERROR;
    if ErrorKind::YKPIV_OK as (i32) != {
        res = _ykpiv_begin_transaction(state);
        res
    } as (i32)
    {
        ErrorKind::YKPIV_PCSC_ERROR
    } else {
        if !(ErrorKind::YKPIV_OK as (i32) != {
            res = _ykpiv_ensure_application_selected(state);
            res
        } as (i32))
        {
            res = _ykpiv_change_pin(state, 1i32, puk, puk_len, new_pin, new_pin_len, tries);
        }
        _ykpiv_end_transaction(state);
        res
    }
}

pub fn ykpiv_fetch_object(
    mut state: *mut ykpiv_state,
    mut object_id: i32,
    mut data: *mut u8,
    mut len: *mut usize,
) -> ErrorKind {
    let mut res: ErrorKind;
    if ErrorKind::YKPIV_OK as (i32) != {
        res = _ykpiv_begin_transaction(state);
        res
    } as (i32)
    {
        ErrorKind::YKPIV_PCSC_ERROR
    } else {
        if !(ErrorKind::YKPIV_OK as (i32) != {
            res = _ykpiv_ensure_application_selected(state);
            res
        } as (i32))
        {
            res = _ykpiv_fetch_object(state, object_id, data, len);
        }
        _ykpiv_end_transaction(state);
        res
    }
}

unsafe fn set_object(mut object_id: i32, mut buffer: *mut u8) -> *mut u8 {
    *{
        let _old = buffer;
        buffer = buffer.offset(1isize);
        _old
    } = 0x5cu8;
    if object_id == 0x7ei32 {
        *{
            let _old = buffer;
            buffer = buffer.offset(1isize);
            _old
        } = 1u8;
        *{
            let _old = buffer;
            buffer = buffer.offset(1isize);
            _old
        } = 0x7eu8;
    } else if object_id > 0xffffi32 && (object_id <= 0xffffffi32) {
        *{
            let _old = buffer;
            buffer = buffer.offset(1isize);
            _old
        } = 3u8;
        *{
            let _old = buffer;
            buffer = buffer.offset(1isize);
            _old
        } = (object_id >> 16i32 & 0xffi32) as (u8);
        *{
            let _old = buffer;
            buffer = buffer.offset(1isize);
            _old
        } = (object_id >> 8i32 & 0xffi32) as (u8);
        *{
            let _old = buffer;
            buffer = buffer.offset(1isize);
            _old
        } = (object_id & 0xffi32) as (u8);
    }
    buffer
}

pub fn _ykpiv_fetch_object(
    mut state: *mut ykpiv_state,
    mut object_id: i32,
    mut data: *mut u8,
    mut len: *mut usize,
) -> ErrorKind {
    let mut sw: i32;
    let mut indata: [u8; 5];
    let mut inptr: *mut u8 = indata.as_mut_ptr();
    let mut templ: *mut u8 = 0i32 as (*mut u8);
    let mut res: ErrorKind;
    inptr = set_object(object_id, inptr);
    if inptr == 0i32 as (*mut c_void) as (*mut u8) {
        ErrorKind::YKPIV_INVALID_OBJECT
    } else if {
        res = ykpiv_transfer_data(
            state,
            templ as (*const u8),
            indata.as_mut_ptr() as (*const u8),
            (inptr as (isize)).wrapping_sub(indata.as_mut_ptr() as (isize))
                / mem::size_of::<u8>() as (isize),
            data,
            len,
            &mut sw as (*mut i32),
        );
        res
    } as (i32)
        != ErrorKind::YKPIV_OK as (i32)
    {
        res
    } else if sw == 0x9000i32 {
        let mut outlen: usize = 0usize;
        let mut offs: u32 = 0u32;
        (if *len < 2usize
            || !_ykpiv_has_valid_length(
                data.offset(1isize) as (*const u8),
                (*len).wrapping_sub(1usize),
            )
        {
            ErrorKind::YKPIV_SIZE_ERROR
        } else {
            offs = _ykpiv_get_length(
                data.offset(1isize) as (*const u8),
                &mut outlen as (*mut usize),
            );
            (if offs == 0u32 {
                ErrorKind::YKPIV_SIZE_ERROR
            } else if outlen.wrapping_add(offs as (usize)).wrapping_add(1usize) != *len {
                if (*state).verbose != 0 {
                    eprintln!(
                          "Invalid length indicated in object, total objlen is {}, indicated length is {}.",
                          *len,
                          outlen
                      );
                }
                ErrorKind::YKPIV_SIZE_ERROR
            } else {
                memmove(
                    data as (*mut c_void),
                    data.offset(1isize).offset(offs as (isize)) as (*const c_void),
                    outlen,
                );
                *len = outlen;
                ErrorKind::YKPIV_OK
            })
        })
    } else {
        ErrorKind::YKPIV_GENERIC_ERROR
    }
}

pub fn ykpiv_save_object(
    mut state: *mut ykpiv_state,
    mut object_id: i32,
    mut indata: *mut u8,
    mut len: usize,
) -> ErrorKind {
    let mut res: ErrorKind;
    if ErrorKind::YKPIV_OK as (i32) != {
        res = _ykpiv_begin_transaction(state);
        res
    } as (i32)
    {
        ErrorKind::YKPIV_PCSC_ERROR
    } else {
        if !(ErrorKind::YKPIV_OK as (i32) != {
            res = _ykpiv_ensure_application_selected(state);
            res
        } as (i32))
        {
            res = _ykpiv_save_object(state, object_id, indata, len);
        }
        _ykpiv_end_transaction(state);
        res
    }
}

pub fn _ykpiv_save_object(
    mut state: *mut ykpiv_state,
    mut object_id: i32,
    mut indata: *mut u8,
    mut len: usize,
) -> ErrorKind {
    let mut data: [u8; 3072];
    let mut dataptr: *mut u8 = data.as_mut_ptr();
    let mut templ: *mut u8 = 0i32 as (*mut u8);
    let mut sw: i32;
    let mut res: ErrorKind;
    let mut outlen: usize = 0usize;
    if len > mem::size_of::<[u8; 3072]>().wrapping_sub(9usize) {
        ErrorKind::YKPIV_SIZE_ERROR
    } else {
        dataptr = set_object(object_id, dataptr);
        (if dataptr == 0i32 as (*mut c_void) as (*mut u8) {
            ErrorKind::YKPIV_INVALID_OBJECT
        } else {
            *{
                let _old = dataptr;
                dataptr = dataptr.offset(1isize);
                _old
            } = 0x53u8;
            dataptr = dataptr.offset(_ykpiv_set_length(dataptr, len) as (isize));
            memcpy(dataptr as (*mut c_void), indata as (*const c_void), len);
            dataptr = dataptr.offset(len as (isize));
            (if {
                res = _ykpiv_transfer_data(
                    state,
                    templ as (*const u8),
                    data.as_mut_ptr() as (*const u8),
                    (dataptr as (isize)).wrapping_sub(data.as_mut_ptr() as (isize))
                        / mem::size_of::<u8>() as (isize),
                    0i32 as (*mut c_void) as (*mut u8),
                    &mut outlen as (*mut usize),
                    &mut sw as (*mut i32),
                );
                res
            } as (i32)
                != ErrorKind::YKPIV_OK as (i32)
            {
                res
            } else if 0x9000i32 == sw {
                ErrorKind::YKPIV_OK
            } else if 0x6982i32 == sw {
                ErrorKind::YKPIV_AUTHENTICATION_ERROR
            } else {
                ErrorKind::YKPIV_GENERIC_ERROR
            })
        })
    }
}

pub fn ykpiv_import_private_key(
    mut state: *mut ykpiv_state,
    key: u8,
    mut algorithm: u8,
    mut p: *const u8,
    mut p_len: usize,
    mut q: *const u8,
    mut q_len: usize,
    mut dp: *const u8,
    mut dp_len: usize,
    mut dq: *const u8,
    mut dq_len: usize,
    mut qinv: *const u8,
    mut qinv_len: usize,
    mut ec_data: *const u8,
    mut ec_data_len: u8,
    pin_policy: u8,
    touch_policy: u8,
) -> ErrorKind {
    let mut _currentBlock;
    let mut key_data: [u8; 1024];
    let mut in_ptr: *mut u8 = key_data.as_mut_ptr();
    let mut templ: *mut u8 = 0i32 as (*mut u8);
    let mut data: [u8; 256];
    let mut recv_len: usize = mem::size_of::<[u8; 256]>();
    let mut elem_len: u32;
    let mut sw: i32;
    let mut params: [*const u8; 5];
    let mut lens: [usize; 5];
    let mut padding: usize;
    let mut n_params: u8;
    let mut i: i32;
    let mut param_tag: i32;
    let mut res: ErrorKind;
    if state == 0i32 as (*mut c_void) as (*mut ykpiv_state) {
        ErrorKind::YKPIV_GENERIC_ERROR
    } else if key as (i32) == 0x9bi32
        || key as (i32) < 0x82i32
        || key as (i32) > 0x95i32 && (key as (i32) < 0x9ai32)
        || key as (i32) > 0x9ei32 && (key as (i32) != 0xf9i32)
    {
        ErrorKind::YKPIV_KEY_ERROR
    } else if pin_policy as (i32) != 0i32
        && (pin_policy as (i32) != 1i32)
        && (pin_policy as (i32) != 2i32)
        && (pin_policy as (i32) != 3i32)
    {
        ErrorKind::YKPIV_GENERIC_ERROR
    } else if touch_policy as (i32) != 0i32
        && (touch_policy as (i32) != 1i32)
        && (touch_policy as (i32) != 2i32)
        && (touch_policy as (i32) != 3i32)
    {
        ErrorKind::YKPIV_GENERIC_ERROR
    } else {
        if algorithm as (i32) == 0x6i32 || algorithm as (i32) == 0x7i32 {
            if p_len
                .wrapping_add(q_len)
                .wrapping_add(dp_len)
                .wrapping_add(dq_len)
                .wrapping_add(qinv_len)
                >= mem::size_of::<[u8; 1024]>()
            {
                return ErrorKind::YKPIV_SIZE_ERROR;
            } else {
                if algorithm as (i32) == 0x6i32 {
                    elem_len = 64u32;
                }
                if algorithm as (i32) == 0x7i32 {
                    elem_len = 128u32;
                }
                if p == 0i32 as (*mut c_void) as (*const u8)
                    || q == 0i32 as (*mut c_void) as (*const u8)
                    || dp == 0i32 as (*mut c_void) as (*const u8)
                    || dq == 0i32 as (*mut c_void) as (*const u8)
                    || qinv == 0i32 as (*mut c_void) as (*const u8)
                {
                    return ErrorKind::YKPIV_GENERIC_ERROR;
                } else {
                    params[0usize] = p;
                    lens[0usize] = p_len;
                    params[1usize] = q;
                    lens[1usize] = q_len;
                    params[2usize] = dp;
                    lens[2usize] = dp_len;
                    params[3usize] = dq;
                    lens[3usize] = dq_len;
                    params[4usize] = qinv;
                    lens[4usize] = qinv_len;
                    param_tag = 0x1i32;
                    n_params = 5u8;
                }
            }
        } else if algorithm as (i32) == 0x11i32 || algorithm as (i32) == 0x14i32 {
            if ec_data_len as (usize) >= mem::size_of::<[u8; 1024]>() {
                return ErrorKind::YKPIV_SIZE_ERROR;
            } else {
                if algorithm as (i32) == 0x11i32 {
                    elem_len = 32u32;
                }
                if algorithm as (i32) == 0x14i32 {
                    elem_len = 48u32;
                }
                if ec_data == 0i32 as (*mut c_void) as (*const u8) {
                    return ErrorKind::YKPIV_GENERIC_ERROR;
                } else {
                    params[0usize] = ec_data;
                    lens[0usize] = ec_data_len as (usize);
                    param_tag = 0x6i32;
                    n_params = 1u8;
                }
            }
        } else {
            return ErrorKind::YKPIV_ALGORITHM_ERROR;
        }
        i = 0i32;
        'loop24: loop {
            if !(i < n_params as (i32)) {
                _currentBlock = 25;
                break;
            }
            let mut remaining: usize;
            *{
                let _old = in_ptr;
                in_ptr = in_ptr.offset(1isize);
                _old
            } = (param_tag + i) as (u8);
            in_ptr = in_ptr.offset(_ykpiv_set_length(in_ptr, elem_len as (usize)) as (isize));
            padding = (elem_len as (usize)).wrapping_sub(lens[i as (usize)]);
            remaining = (key_data.as_mut_ptr() as (usize))
                .wrapping_add(mem::size_of::<[u8; 1024]>())
                .wrapping_sub(in_ptr as (usize));
            if padding > remaining {
                _currentBlock = 39;
                break;
            }
            memset(in_ptr as (*mut c_void), 0i32, padding);
            in_ptr = in_ptr.offset(padding as (isize));
            memcpy(
                in_ptr as (*mut c_void),
                params[i as (usize)] as (*const c_void),
                lens[i as (usize)],
            );
            in_ptr = in_ptr.offset(lens[i as (usize)] as (isize));
            i = i + 1;
        }
        if _currentBlock == 25 {
            if pin_policy as (i32) != 0i32 {
                *{
                    let _old = in_ptr;
                    in_ptr = in_ptr.offset(1isize);
                    _old
                } = 0xaau8;
                *{
                    let _old = in_ptr;
                    in_ptr = in_ptr.offset(1isize);
                    _old
                } = 0x1u8;
                *{
                    let _old = in_ptr;
                    in_ptr = in_ptr.offset(1isize);
                    _old
                } = pin_policy;
            }
            if touch_policy as (i32) != 0i32 {
                *{
                    let _old = in_ptr;
                    in_ptr = in_ptr.offset(1isize);
                    _old
                } = 0xabu8;
                *{
                    let _old = in_ptr;
                    in_ptr = in_ptr.offset(1isize);
                    _old
                } = 0x1u8;
                *{
                    let _old = in_ptr;
                    in_ptr = in_ptr.offset(1isize);
                    _old
                } = touch_policy;
            }
            if ErrorKind::YKPIV_OK as (i32) != {
                res = _ykpiv_begin_transaction(state);
                res
            } as (i32)
            {
                return ErrorKind::YKPIV_PCSC_ERROR;
            } else if !(ErrorKind::YKPIV_OK as (i32) != {
                res = _ykpiv_ensure_application_selected(state);
                res
            } as (i32))
            {
                if !({
                    res = ykpiv_transfer_data(
                        state,
                        templ as (*const u8),
                        key_data.as_mut_ptr() as (*const u8),
                        (in_ptr as (isize)).wrapping_sub(key_data.as_mut_ptr() as (isize))
                            / mem::size_of::<u8>() as (isize),
                        data.as_mut_ptr(),
                        &mut recv_len as (*mut usize),
                        &mut sw as (*mut i32),
                    );
                    res
                } as (i32)
                    != ErrorKind::YKPIV_OK as (i32))
                {
                    if 0x9000i32 != sw {
                        res = ErrorKind::YKPIV_GENERIC_ERROR;
                        if sw == 0x6982i32 {
                            res = ErrorKind::YKPIV_AUTHENTICATION_ERROR;
                        }
                    }
                }
            }
        } else {
            res = ErrorKind::YKPIV_ALGORITHM_ERROR;
        }
        memset_s(
            key_data.as_mut_ptr() as (*mut c_void),
            mem::size_of::<[u8; 1024]>(),
            0i32,
            mem::size_of::<[u8; 1024]>(),
        );
        _ykpiv_end_transaction(state);
        res
    }
}

pub fn ykpiv_attest(
    mut state: *mut ykpiv_state,
    key: u8,
    mut data: *mut u8,
    mut data_len: *mut usize,
) -> ErrorKind {
    let mut res = ErrorKind::YKPIV_GENERIC_ERROR;
    let mut templ: *mut u8 = 0i32 as (*mut u8);
    let mut sw: i32;
    let mut ul_data_len: usize;
    if state.is_null() || data.is_null() || data_len.is_null() {
        return ErrorKind::YKPIV_ARGUMENT_ERROR;
    }

    ul_data_len = *data_len;

    if _ykpiv_begin_transaction(state) != ErrorKind::YKPIV_OK {
        return ErrorKind::YKPIV_PCSC_ERROR;
    }

    if _ykpiv_ensure_application_selected(state) == ErrorKind::YKPIV_OK {
        res = ykpiv_transfer_data(
            state,
            templ as (*const u8),
            0i32 as (*mut c_void) as (*const u8),
            0isize,
            data,
            &mut ul_data_len as (*mut usize),
            &mut sw as (*mut i32),
        );

        if res == ErrorKind::YKPIV_OK {
            if 0x9000i32 != sw {
                res = ErrorKind::YKPIV_GENERIC_ERROR;
                if 0x6d00i32 == sw {
                    res = ErrorKind::YKPIV_NOT_SUPPORTED;
                }
            } else if *data as i32 != 0x30 {
                res = ErrorKind::YKPIV_GENERIC_ERROR;
            } else {
                *data_len = ul_data_len;
            }
        }
    }

    _ykpiv_end_transaction(state);
    res
}

pub fn ykpiv_auth_getchallenge(
    mut state: *mut ykpiv_state,
    mut challenge: *mut u8,
    challenge_len: usize,
) -> ErrorKind {
    let mut res = ErrorKind::YKPIV_OK;
    let mut data = [0u8; 261];
    let mut recv_len: u32 = mem::size_of::<[u8; 261]>() as (u32);
    let mut sw: i32 = 0i32;

    if state.is_null() || challenge.is_null() {
        return ErrorKind::YKPIV_GENERIC_ERROR;
    }

    if challenge_len != 8 {
        return ErrorKind::YKPIV_SIZE_ERROR;
    }

    if _ykpiv_begin_transaction(state) != ErrorKind::YKPIV_OK {
        return ErrorKind::YKPIV_PCSC_ERROR;
    }

    if _ykpiv_ensure_application_selected(state) == ErrorKind::YKPIV_OK {
        let mut apdu = APDU::default();
        apdu.ins = YKPIV_INS_AUTHENTICATE;
        apdu.p1 = YKPIV_ALGO_3DES; // triple des
        apdu.p2 = YKPIV_KEY_CARDMGM; // management key
        apdu.lc = 0x04;
        apdu.data[0] = 0x7c;
        apdu.data[1] = 0x02;
        apdu.data[2] = 0x81; //0x80;

        res = _send_data(
            state,
            &mut apdu as (*mut APDU),
            data.as_mut_ptr(),
            &mut recv_len as (*mut u32),
            &mut sw as (*mut i32),
        );

        if res != ErrorKind::YKPIV_OK {
            if sw != 0x9000i32 {
                res = ErrorKind::YKPIV_AUTHENTICATION_ERROR;
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

pub fn ykpiv_auth_verifyresponse(
    mut state: *mut ykpiv_state,
    mut response: *mut u8,
    response_len: usize,
) -> ErrorKind {
    let mut res: ErrorKind = ErrorKind::YKPIV_OK;
    let mut data = [0u8; 261];
    let mut recv_len = data.len() as u32;
    let mut sw: i32 = 0i32;
    let mut apdu = APDU::default();

    let mut dataptr = apdu.data.as_mut_ptr();

    if state.is_null() || response.is_null() {
        return ErrorKind::YKPIV_GENERIC_ERROR;
    }

    if response_len != 8 {
        return ErrorKind::YKPIV_SIZE_ERROR;
    }

    if _ykpiv_begin_transaction(state) != ErrorKind::YKPIV_OK {
        return ErrorKind::YKPIV_PCSC_ERROR;
    }

    // send the response to the card and a challenge of our own.
    apdu.ins = YKPIV_INS_AUTHENTICATE;
    apdu.p1 = YKPIV_ALGO_3DES; // triple des
    apdu.p2 = YKPIV_KEY_CARDMGM; // management key

    *{
        let _old = dataptr;
        dataptr = dataptr.offset(1isize);
        _old
    } = 0x7cu8;

    *{
        let _old = dataptr;
        dataptr = dataptr.offset(1isize);
        _old
    } = 0xau8;

    *{
        let _old = dataptr;
        dataptr = dataptr.offset(1isize);
        _old
    } = 0x82u8;

    *{
        let _old = dataptr;
        dataptr = dataptr.offset(1isize);
        _old
    } = 8u8;

    memcpy(
        dataptr as *mut c_void,
        response as *const c_void,
        response_len,
    );

    dataptr = dataptr.offset(8isize);
    apdu.lc = (dataptr as usize - apdu.data.as_ptr() as usize)
        .try_into()
        .unwrap();

    res = _send_data(
        state,
        &mut apdu as (*mut APDU),
        data.as_mut_ptr(),
        &mut recv_len,
        &mut sw,
    );

    if res == ErrorKind::YKPIV_OK && sw != 0x9000i32 {
        res = ErrorKind::YKPIV_AUTHENTICATION_ERROR;
    }

    apdu.zeroize();
    _ykpiv_end_transaction(state);
    res
}

static mut MGMT_AID: *const u8 = 0xa0i32 as (*const u8);

pub fn ykpiv_auth_deauthenticate(mut state: *mut ykpiv_state) -> ErrorKind {
    let mut res: ErrorKind = ErrorKind::YKPIV_OK;
    let mut apdu: APDU;
    let mut data: [u8; 255];
    let mut recv_len: u32 = mem::size_of::<[u8; 255]>() as (u32);
    let mut sw: i32;
    if state.is_null() {
        ErrorKind::YKPIV_ARGUMENT_ERROR
    } else if {
        res = _ykpiv_begin_transaction(state);
        res
    } as (i32)
        < ErrorKind::YKPIV_OK as (i32)
    {
        res
    } else {
        // FIXME(tarcieri): Translate C code below
        /*
            memset(apdu.raw, 0, sizeof(apdu));
            apdu.st.ins = YKPIV_INS_SELECT_APPLICATION;
            apdu.st.p1 = 0x04;
            apdu.st.lc = sizeof(MGMT_AID);
            memcpy(apdu.st.data, MGMT_AID, sizeof(MGMT_AID));
        */
        if {
            res = _send_data(
                state,
                &mut apdu as (*mut APDU),
                data.as_mut_ptr(),
                &mut recv_len as (*mut u32),
                &mut sw as (*mut i32),
            );
            res
        } as (i32)
            < ErrorKind::YKPIV_OK as (i32)
        {
            if (*state).verbose != 0 {
                eprintln!(
                    "Failed communicating with card: \'{}\'",
                    ykpiv_strerror(res)
                );
            }
        } else if sw != 0x9000i32 {
            if (*state).verbose != 0 {
                eprintln!("Failed selecting mgmt application: {:04x}", sw);
            }
            res = ErrorKind::YKPIV_GENERIC_ERROR;
        }
        _ykpiv_end_transaction(state);
        res
    }
}
