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

use libc::{
    c_char, c_int, fclose, feof, fgets, fopen, free, getenv, malloc, memcpy, memset, strcasecmp,
    strcmp, strlen,
};
use std::ptr;

extern "C" {
    fn DES_ecb3_encrypt(
        input: *mut [u8; 8],
        output: *mut [u8; 8],
        ks1: *mut DES_ks,
        ks2: *mut DES_ks,
        ks3: *mut DES_ks,
        enc: i32,
    );
    fn DES_is_weak_key(key: *mut [u8; 8]) -> i32;
    fn DES_set_key_unchecked(key: *mut [u8; 8], schedule: *mut DES_ks);
    fn PKCS5_PBKDF2_HMAC_SHA1(
        pass: *const u8,
        passlen: i32,
        salt: *const u8,
        saltlen: i32,
        iter: i32,
        keylen: i32,
        out: *mut u8,
    ) -> i32;
    fn RAND_bytes(buf: *mut u8, num: i32) -> i32;
    static mut _DefaultRuneLocale: Struct1;
    fn __maskrune(arg1: i32, arg2: usize) -> i32;
    fn __tolower(arg1: i32) -> i32;
    fn __toupper(arg1: i32) -> i32;
    fn snprintf(__str: *mut u8, __size: usize, __format: *const u8, ...) -> i32;
    fn sscanf(arg1: *const u8, arg2: *const u8, ...) -> i32;
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
    pub __sgetrune: unsafe extern "C" fn(*const u8, usize, *mut *const u8) -> i32,
    pub __sputrune: unsafe extern "C" fn(i32, *mut u8, usize, *mut *mut u8) -> i32,
    pub __invalid_rune: i32,
    pub __runetype: [u32; 256],
    pub __maplower: [i32; 256],
    pub __mapupper: [i32; 256],
    pub __runetype_ext: Struct2,
    pub __maplower_ext: Struct2,
    pub __mapupper_ext: Struct2,
    pub __variable: *mut ::std::os::raw::c_void,
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

pub static mut szLOG_SOURCE: *const u8 = (*b"YubiKey PIV Library\0").as_ptr();

#[derive(Clone, Copy)]
#[repr(i32)]
#[allow(non_camel_case_types)]
pub enum Enum5 {
    DES_OK = 0i32,
    DES_INVALID_PARAMETER = -1i32,
    DES_BUFFER_TOO_SMALL = -2i32,
    DES_MEMORY_ERROR = -3i32,
    DES_GENERAL_ERROR = -4i32,
}

#[derive(Copy)]
#[repr(C)]
pub struct DES_ks {
    pub ks: [u8; 16],
}

impl Clone for DES_ks {
    fn clone(&self) -> Self {
        *self
    }
}

#[derive(Copy)]
#[repr(C)]
pub struct DesKey {
    pub ks1: DES_ks,
    pub ks2: DES_ks,
    pub ks3: DES_ks,
}

impl Clone for DesKey {
    fn clone(&self) -> Self {
        *self
    }
}

pub fn des_import_key(
    type_: i32,
    mut keyraw: *const u8,
    keyrawlen: usize,
    mut key: *mut *mut DesKey,
) -> Enum5 {
    let mut _currentBlock;
    let mut rc: Enum5 = Enum5::DES_OK;
    let mut cb_expectedkey: usize = (8i32 * 3i32) as (usize);
    let mut key_tmp: [u8; 8];
    let mut cb_keysize: usize = 8usize;
    if type_ == 1i32 {
        cb_expectedkey = (8i32 * 3i32) as (usize);
        cb_keysize = 8usize;
        if cb_keysize > ::std::mem::size_of::<[u8; 8]>() {
            rc = Enum5::DES_MEMORY_ERROR;
            _currentBlock = 15;
        } else if keyraw.is_null() {
            rc = Enum5::DES_INVALID_PARAMETER;
            _currentBlock = 15;
        } else if keyrawlen != cb_expectedkey {
            rc = Enum5::DES_INVALID_PARAMETER;
            _currentBlock = 15;
        } else if key.is_null() {
            rc = Enum5::DES_INVALID_PARAMETER;
            _currentBlock = 15;
        } else if {
            *key = malloc(::std::mem::size_of::<DesKey>()) as (*mut DesKey);
            *key
        }
        .is_null()
        {
            rc = Enum5::DES_MEMORY_ERROR;
            _currentBlock = 15;
        } else {
            memset(
                *key as (*mut ::std::os::raw::c_void),
                0i32,
                ::std::mem::size_of::<DesKey>(),
            );
            memcpy(
                key_tmp.as_mut_ptr() as (*mut ::std::os::raw::c_void),
                keyraw as (*const ::std::os::raw::c_void),
                cb_keysize,
            );
            DES_set_key_unchecked(
                &mut key_tmp as (*mut [u8; 8]),
                &mut (**key).ks1 as (*mut DES_ks),
            );
            memcpy(
                key_tmp.as_mut_ptr() as (*mut ::std::os::raw::c_void),
                keyraw.offset(cb_keysize as (isize)) as (*const ::std::os::raw::c_void),
                cb_keysize,
            );
            DES_set_key_unchecked(
                &mut key_tmp as (*mut [u8; 8]),
                &mut (**key).ks2 as (*mut DES_ks),
            );
            memcpy(
                key_tmp.as_mut_ptr() as (*mut ::std::os::raw::c_void),
                keyraw.offset(2usize.wrapping_mul(cb_keysize) as (isize))
                    as (*const ::std::os::raw::c_void),
                cb_keysize,
            );
            DES_set_key_unchecked(
                &mut key_tmp as (*mut [u8; 8]),
                &mut (**key).ks3 as (*mut DES_ks),
            );
            _currentBlock = 17;
        }
    } else {
        rc = Enum5::DES_INVALID_PARAMETER;
        _currentBlock = 15;
    }
    if _currentBlock == 15 {
        if !key.is_null() {
            des_destroy_key(*key);
            *key = 0i32 as (*mut ::std::os::raw::c_void) as (*mut DesKey);
        }
    }
    rc
}

pub fn des_destroy_key(mut key: *mut DesKey) -> Enum5 {
    if !key.is_null() {
        free(key as (*mut ::std::os::raw::c_void));
    }
    Enum5::DES_OK
}

pub fn des_encrypt(
    mut key: *mut DesKey,
    mut in_: *const u8,
    inlen: usize,
    mut out: *mut u8,
    mut outlen: *mut usize,
) -> Enum5 {
    let mut rc: Enum5 = Enum5::DES_OK;
    if key.is_null() || outlen.is_null() || *outlen < inlen || in_.is_null() || out.is_null() {
        rc = Enum5::DES_INVALID_PARAMETER;
    } else {
        DES_ecb3_encrypt(
            in_ as (*mut [u8; 8]),
            out as (*mut [u8; 8]),
            &mut (*key).ks1 as (*mut DES_ks),
            &mut (*key).ks2 as (*mut DES_ks),
            &mut (*key).ks3 as (*mut DES_ks),
            1i32,
        );
    }
    rc
}

pub fn des_decrypt(
    mut key: *mut DesKey,
    mut in_: *const u8,
    inlen: usize,
    mut out: *mut u8,
    mut outlen: *mut usize,
) -> Enum5 {
    let mut rc: Enum5 = Enum5::DES_OK;
    if key.is_null() || outlen.is_null() || *outlen < inlen || in_.is_null() || out.is_null() {
        rc = Enum5::DES_INVALID_PARAMETER;
    } else {
        DES_ecb3_encrypt(
            in_ as (*mut [u8; 8]),
            out as (*mut [u8; 8]),
            &mut (*key).ks1 as (*mut DES_ks),
            &mut (*key).ks2 as (*mut DES_ks),
            &mut (*key).ks3 as (*mut DES_ks),
            0i32,
        );
    }
    rc
}

pub fn yk_des_is_weak_key(mut key: *const u8, cb_key: usize) -> bool {
    cb_key;
    DES_is_weak_key(key as (*mut [u8; 8])) != 0
}

#[derive(Clone, Copy)]
#[repr(i32)]
#[allow(non_camel_case_types)]
pub enum Enum7 {
    PRNG_OK = 0i32,
    PRNG_GENERAL_ERROR = -1i32,
}

pub fn _ykpiv_prng_generate(mut buffer: *mut u8, cb_req: usize) -> Enum7 {
    let mut rc: Enum7 = Enum7::PRNG_OK;
    if -1i32 == RAND_bytes(buffer, cb_req as (i32)) {
        rc = Enum7::PRNG_GENERAL_ERROR;
    }
    rc
}

#[derive(Clone, Copy)]
#[repr(i32)]
#[allow(non_camel_case_types)]
pub enum Enum8 {
    PKCS5_OK = 0i32,
    PKCS5_GENERAL_ERROR = -1i32,
}

pub fn pkcs5_pbkdf2_sha1(
    mut password: *const u8,
    cb_password: usize,
    mut salt: *const u8,
    cb_salt: usize,
    mut iterations: usize,
    mut key: *const u8,
    cb_key: usize,
) -> Enum8 {
    let mut rc: Enum8 = Enum8::PKCS5_OK;
    PKCS5_PBKDF2_HMAC_SHA1(
        password,
        cb_password as (i32),
        salt,
        cb_salt as (i32),
        iterations as (i32),
        cb_key as (i32),
        key as (*mut u8),
    );
    rc
}

pub fn _strip_ws(mut sz: *mut c_char) -> *mut c_char {
    let mut psz_head: *mut c_char = sz;
    let mut psz_tail: *mut c_char = sz
        .offset(strlen(sz as *const c_char) as (isize))
        .offset(-1isize);
    'loop1: loop {
        if isspace(*psz_head as i32) == 0 {
            break;
        }
        psz_head = psz_head.offset(1isize);
    }
    'loop2: loop {
        if !(psz_tail >= psz_head && (isspace(*psz_tail as (i32)) != 0)) {
            break;
        }
        *{
            let _old = psz_tail;
            psz_tail = psz_tail.offset(-1isize);
            _old
        } = 0;
    }
    psz_head
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub enum SettingSource {
    SETTING_SOURCE_USER,
    SETTING_SOURCE_ADMIN,
    SETTING_SOURCE_DEFAULT,
}

#[derive(Copy)]
pub struct SettingBool {
    pub value: bool,
    pub source: SettingSource,
}

impl Clone for SettingBool {
    fn clone(&self) -> Self {
        *self
    }
}

pub unsafe fn _get_bool_config(mut sz_setting: *const c_char) -> SettingBool {
    let mut setting: SettingBool = SettingBool {
        value: false,
        source: SettingSource::SETTING_SOURCE_DEFAULT,
    };
    let mut sz_line = [0u8; 256];
    let mut psz_name: *mut c_char = ptr::null_mut();
    let mut psz_value: *mut c_char = ptr::null_mut();
    let mut sz_name = [0u8; 256];
    let mut sz_value = [0u8; 256];

    let mut pf = unsafe {
        fopen(
            b"/etc/yubico/yubikeypiv.conf\0".as_ptr() as *const c_char,
            b"r\0".as_ptr() as *const c_char,
        )
    };

    if pf.is_null() {
        return setting;
    }

    while feof(pf) == 0 {
        if fgets(
            sz_line.as_mut_ptr() as *mut c_char,
            sz_line.len() as c_int,
            pf,
        )
        .is_null()
        {
            continue;
        }

        if sz_line[0] == b'#' {
            continue;
        }

        if sz_line[0] == b'\r' {
            continue;
        }

        if sz_line[0] == b'\n' {
            continue;
        }

        if !(sscanf(
            sz_line.as_mut_ptr(),
            (*b"%255[^=]=%255s\0").as_ptr(),
            sz_name.as_mut_ptr(),
            sz_value.as_mut_ptr(),
        ) == 2)
        {
            continue;
        }

        psz_name = _strip_ws(sz_name.as_mut_ptr() as *mut c_char);

        if !(strcasecmp(psz_name as *const c_char, sz_setting as *const c_char) == 0) {
            continue;
        }

        psz_value = _strip_ws(sz_value.as_mut_ptr() as *mut c_char);
        setting.source = SettingSource::SETTING_SOURCE_ADMIN;
        setting.value = strcmp(psz_value as *const c_char, b"1\0".as_ptr() as *const c_char) == 0
            || strcasecmp(
                psz_value as *const c_char,
                b"true\0".as_ptr() as *const c_char,
            ) == 0;
    }

    fclose(pf);
    setting
}

pub fn _get_bool_env(mut sz_setting: *const c_char) -> SettingBool {
    let mut setting: SettingBool = SettingBool {
        value: false,
        source: SettingSource::SETTING_SOURCE_DEFAULT,
    };
    let mut psz_value: *mut c_char = ptr::null_mut();
    let mut sz_name = [0u8; 256];

    snprintf(
        sz_name.as_mut_ptr(),
        ::std::mem::size_of::<[u8; 256]>().wrapping_sub(1usize),
        b"%s%s\0".as_ptr(),
        b"YUBIKEY_PIV_\0".as_ptr(),
        sz_setting,
    );

    psz_value = getenv(sz_name.as_mut_ptr() as *const c_char);

    if !psz_value.is_null() {
        setting.source = SettingSource::SETTING_SOURCE_USER;
        setting.value = strcmp(psz_value as *const c_char, b"1\0".as_ptr() as *const c_char) == 0
            || strcasecmp(
                psz_value as *const c_char,
                b"true\0".as_ptr() as *const c_char,
            ) == 0;
    }

    setting
}

pub fn setting_get_bool(mut sz_setting: *const c_char, mut def: bool) -> SettingBool {
    let mut setting: SettingBool = SettingBool {
        value: def,
        source: SettingSource::SETTING_SOURCE_DEFAULT,
    };

    setting = _get_bool_config(sz_setting);

    if setting.source == SettingSource::SETTING_SOURCE_DEFAULT {
        setting = _get_bool_env(sz_setting);
    }

    if setting.source == SettingSource::SETTING_SOURCE_DEFAULT {
        setting.value = def;
    }

    setting
}
