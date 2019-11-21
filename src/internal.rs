//! Internal functions (mostly 3DES)

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
use std::fs::File;
use std::io::{BufReader, Result as IoResult, BufRead};
use std::path::Path;
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
#[allow(clippy::trivially_copy_pass_by_ref)]
pub fn des_encrypt(key: &DesKey, input: &[u8; DES_LEN_DES], output: &mut [u8; DES_LEN_DES]) {
    output.copy_from_slice(input);
    TdesEde3::new(GenericArray::from_slice(&key.0))
        .encrypt_block(GenericArray::from_mut_slice(output));
}

/// Decrypt with DES key
#[allow(clippy::trivially_copy_pass_by_ref)]
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
pub fn get_bool_config<P: AsRef<Path>>(setting: &str, file: P)
    -> IoResult<Option<SettingBool>> {

    let config_file_reader = BufReader::new(
        File::open(file)?
    );

    let setting_len = setting.len();
    for line in config_file_reader.lines() {
        let line = line?;
        // match a line of the form `<key>=<value>` where key == setting
        if &line.as_str()[..setting_len] == setting  && &line.as_str()[setting_len..setting_len] == "="{
            // check for specified "truthy" values
            let truthy = &line[setting_len+1..] == "1" || &line[setting_len+1..] == "true";
            return Ok(
                Some(
                    SettingBool {
                        value: truthy,
                        source: SettingSource::Admin
                    }
                )
            )
        }
    }

    Ok(None)
}

/// Get a setting boolean from an environment variable
pub fn get_bool_env(setting_name: &str) -> Option<SettingBool> {
    let setting = format!("YUBIKEY_PIV_{}", setting_name.to_uppercase());

    match std::env::var(setting).ok() {
        Some(val) => Some(
                SettingBool {
                    value: val.as_str() == "1" || val.as_str() == "true",
                    source: SettingSource::User
                }
        ),
        None => None
    }
}

/// Get a setting boolean
pub fn setting_get_bool(setting_name: &str, def: bool) -> SettingBool {
    match get_bool_config(setting_name.as_ref(), "/etc/yubico/yubikeypiv.conf") {
        Ok(Some(setting)) => setting,
        Ok(None) => {
            //try env instead
            match get_bool_env(setting_name.as_ref()) {
                Some(setting) => setting,
                None => SettingBool {
                    value: def,
                    source: SettingSource::Default
                }
            }
        }
        _ => SettingBool { // ignore IO errors for now
            value: def,
            source: SettingSource::Default
        }
    }
}
