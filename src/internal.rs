//! Internal functions (mostly 3DES)

// TODO(tarcieri): replace OpenSSL extern "C" invocations with `des` crate
// - crate: https://crates.io/crates/des
// - docs: https://docs.rs/des/0

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

// TODO(tarcieri): investigate and remove dead code
#![allow(non_upper_case_globals, dead_code)]
#![allow(clippy::missing_safety_doc)]

use crate::consts::*;
use libc::{
    c_char, c_int, fclose, feof, fgets, fopen, free, getenv, malloc, memcpy, memset, sscanf,
    strcasecmp, strcmp,
};
use std::{
    ffi::{CStr, CString},
    mem,
    os::raw::c_void,
};

extern "C" {
    fn DES_ecb3_encrypt(
        input: *mut [u8; 8],
        output: *mut [u8; 8],
        ks1: *mut DesSubKey,
        ks2: *mut DesSubKey,
        ks3: *mut DesSubKey,
        enc: i32,
    );
    fn DES_is_weak_key(key: *mut [u8; 8]) -> i32;
    fn DES_set_key_unchecked(key: *mut [u8; 8], schedule: *mut DesSubKey);
}

/// DES-related errors
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum DesErrorKind {
    /// Ok
    Ok = 0,

    /// Invalid parameter
    InvalidParameter = -1,

    /// Buffer too small
    BufferTooSmall = -2,

    /// Memory error
    MemoryError = -3,

    /// General error
    GeneralError = -4,
}

/// 3DES subkeys
#[derive(Copy, Clone)]
#[repr(C)]
pub struct DesSubKey([u8; 16]);

/// 3DES keys
#[derive(Copy, Clone)]
pub struct DesKey {
    /// subkey 1
    pub ks1: DesSubKey,

    /// subkey 2
    pub ks2: DesSubKey,

    /// subkey 3
    pub ks3: DesSubKey,
}

/// Import DES key
pub unsafe fn des_import_key(
    key_type: i32,
    keyraw: *const u8,
    keyrawlen: usize,
    key: *mut *mut DesKey,
) -> DesErrorKind {
    let mut key_tmp = [0u8; 8];
    let cb_expectedkey: usize;
    let cb_keysize: usize;

    if key_type != DES_TYPE_3DES as i32 {
        return DesErrorKind::InvalidParameter;
    }

    cb_expectedkey = (8i32 * 3i32) as (usize);
    cb_keysize = 8usize;

    if cb_keysize > 8 {
        return DesErrorKind::MemoryError;
    }

    if key.is_null() || keyraw.is_null() || keyrawlen != cb_expectedkey {
        return DesErrorKind::InvalidParameter;
    }

    *key = malloc(mem::size_of::<DesKey>()) as (*mut DesKey);

    if (*key).is_null() {
        return DesErrorKind::MemoryError;
    }

    memset(*key as (*mut c_void), 0i32, mem::size_of::<DesKey>());

    memcpy(
        key_tmp.as_mut_ptr() as (*mut c_void),
        keyraw as (*const c_void),
        cb_keysize,
    );

    DES_set_key_unchecked(&mut key_tmp, &mut (**key).ks1);

    memcpy(
        key_tmp.as_mut_ptr() as (*mut c_void),
        keyraw.add(cb_keysize) as (*const c_void),
        cb_keysize,
    );

    DES_set_key_unchecked(&mut key_tmp, &mut (**key).ks2);

    memcpy(
        key_tmp.as_mut_ptr() as (*mut c_void),
        keyraw.add(2usize.wrapping_mul(cb_keysize)) as (*const c_void),
        cb_keysize,
    );

    DES_set_key_unchecked(&mut key_tmp, &mut (**key).ks3);

    DesErrorKind::Ok
}

/// Destroy DES key
pub unsafe fn des_destroy_key(key: *mut DesKey) -> DesErrorKind {
    if !key.is_null() {
        free(key as (*mut c_void));
    }

    DesErrorKind::Ok
}

/// Encrypt with DES key
pub unsafe fn des_encrypt(
    key: *mut DesKey,
    input: *const u8,
    inputlen: usize,
    out: *mut u8,
    outlen: *mut usize,
) -> DesErrorKind {
    if key.is_null() || outlen.is_null() || *outlen < inputlen || input.is_null() || out.is_null() {
        return DesErrorKind::InvalidParameter;
    }

    DES_ecb3_encrypt(
        input as *mut [u8; 8],
        out as *mut [u8; 8],
        &mut (*key).ks1,
        &mut (*key).ks2,
        &mut (*key).ks3,
        1,
    );

    DesErrorKind::Ok
}

/// Decrypt with DES key
pub unsafe fn des_decrypt(
    key: *mut DesKey,
    in_: *const u8,
    inlen: usize,
    out: *mut u8,
    outlen: *mut usize,
) -> DesErrorKind {
    if key.is_null() || outlen.is_null() || *outlen < inlen || in_.is_null() || out.is_null() {
        return DesErrorKind::InvalidParameter;
    }

    DES_ecb3_encrypt(
        in_ as *mut [u8; 8],
        out as *mut [u8; 8],
        &mut (*key).ks1,
        &mut (*key).ks2,
        &mut (*key).ks3,
        0,
    );

    DesErrorKind::Ok
}

/// Is the given DES key weak?
pub unsafe fn yk_des_is_weak_key(key: *const u8, _cb_key: usize) -> bool {
    DES_is_weak_key(key as (*mut [u8; 8])) != 0
}

/// PKCS#5 error types
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum Pkcs5ErrorKind {
    /// OK
    Ok = 0,

    /// General error
    GeneralError = -1,
}

/// Strip whitespace
// TODO(tarcieri): implement this
pub unsafe fn _strip_ws(sz: *mut c_char) -> *mut c_char {
    sz
}

/// Source of how a setting was configured
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettingSource {
    /// User-specified setting
    User,

    /// Admin-specified setting
    Admin,

    /// Default setting
    Default,
}

/// Setting booleans
#[derive(Copy, Clone, Debug)]
pub struct SettingBool {
    /// Boolean value
    pub value: bool,

    /// Source of the configuration setting (user/admin/default)
    pub source: SettingSource,
}

/// Get a boolean config value
pub unsafe fn _get_bool_config(sz_setting: *const c_char) -> SettingBool {
    let mut setting: SettingBool = SettingBool {
        value: false,
        source: SettingSource::Default,
    };
    let mut sz_line = [0u8; 256];
    let mut psz_name: *mut c_char;
    let mut psz_value: *mut c_char;
    let mut sz_name = [0u8; 256];
    let mut sz_value = [0u8; 256];

    let pf = fopen(
        b"/etc/yubico/yubikeypiv.conf\0".as_ptr() as *const c_char,
        b"r\0".as_ptr() as *const c_char,
    );

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

        if sscanf(
            sz_line.as_ptr() as *const c_char,
            b"%255[^=]=%255s\0".as_ptr() as *const c_char,
            sz_name.as_mut_ptr(),
            sz_value.as_mut_ptr(),
        ) != 2
        {
            continue;
        }

        psz_name = _strip_ws(sz_name.as_mut_ptr() as *mut c_char);

        if strcasecmp(psz_name, sz_setting) != 0 {
            continue;
        }

        psz_value = _strip_ws(sz_value.as_mut_ptr() as *mut c_char);
        setting.source = SettingSource::Admin;
        setting.value = strcmp(psz_value, b"1\0".as_ptr() as *const c_char) == 0
            || strcasecmp(psz_value, b"true\0".as_ptr() as *const c_char) == 0;
    }

    fclose(pf);
    setting
}

/// Get a setting boolean from an environment variable
pub unsafe fn _get_bool_env(sz_setting: *const c_char) -> SettingBool {
    let mut setting: SettingBool = SettingBool {
        value: false,
        source: SettingSource::Default,
    };

    let sz_name = CString::new(format!(
        "YUBIKEY_PIV_{}",
        CStr::from_ptr(sz_setting).to_string_lossy()
    ))
    .unwrap();

    let psz_value = getenv(sz_name.as_ptr());

    if !psz_value.is_null() {
        setting.source = SettingSource::User;
        setting.value = strcmp(psz_value, b"1\0".as_ptr() as *const c_char) == 0
            || strcasecmp(psz_value, b"true\0".as_ptr() as *const c_char) == 0;
    }

    setting
}

/// Get a setting boolean
pub unsafe fn setting_get_bool(sz_setting: *const c_char, def: bool) -> SettingBool {
    let mut setting = _get_bool_config(sz_setting);

    if setting.source == SettingSource::Default {
        setting = _get_bool_env(sz_setting);
    }

    if setting.source == SettingSource::Default {
        setting.value = def;
    }

    setting
}
