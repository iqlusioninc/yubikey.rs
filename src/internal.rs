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
use des::{
    block_cipher_trait::{generic_array::GenericArray, BlockCipher},
    TdesEde3,
};
use libc::{c_char, c_int, fclose, feof, fgets, fopen, getenv, sscanf, strcasecmp, strcmp};
use std::ffi::{CStr, CString};
use zeroize::Zeroize;

/// 3DES keys. The three subkeys are concatenated.
pub struct DesKey([u8; DES_LEN_3DES]);

impl DesKey {
    pub fn from_bytes(bytes: [u8; DES_LEN_3DES]) -> Self {
        DesKey(bytes)
    }

    pub fn write(&self, out: &mut [u8]) {
        out.copy_from_slice(&self.0);
    }
}

impl AsRef<[u8; 24]> for DesKey {
    fn as_ref(&self) -> &[u8; 24] {
        &self.0
    }
}

impl Zeroize for DesKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for DesKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Encrypt with DES key
pub fn des_encrypt(key: &DesKey, input: &[u8; DES_LEN_DES], output: &mut [u8; DES_LEN_DES]) {
    output.copy_from_slice(input);
    TdesEde3::new(GenericArray::from_slice(&key.0))
        .encrypt_block(GenericArray::from_mut_slice(output));
}

/// Decrypt with DES key
pub fn des_decrypt(key: &DesKey, input: &[u8; DES_LEN_DES], output: &mut [u8; DES_LEN_DES]) {
    output.copy_from_slice(input);
    TdesEde3::new(GenericArray::from_slice(&key.0))
        .encrypt_block(GenericArray::from_mut_slice(output));
}

/// Is the given DES key weak?
pub fn yk_des_is_weak_key(key: &[u8; DES_LEN_3DES]) -> bool {
    /// Weak and semi weak keys as taken from
    /// %A D.W. Davies
    /// %A W.L. Price
    /// %T Security for Computer Networks
    /// %I John Wiley & Sons
    /// %D 1984
    const weak_keys: [[u8; DES_LEN_DES]; 16] = [
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

    // set odd parity of key
    let mut tmp = [0u8; DES_LEN_3DES];
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
    let mut rv = false;
    for weak_key in weak_keys.iter() {
        if weak_key == &tmp[0..DES_LEN_DES]
            || weak_key == &tmp[DES_LEN_DES..2 * DES_LEN_DES]
            || weak_key == &tmp[2 * DES_LEN_DES..3 * DES_LEN_DES]
        {
            rv = true;
            break;
        }
    }

    tmp.zeroize();
    rv
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
