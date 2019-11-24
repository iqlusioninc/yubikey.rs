//! Configuration setting values parsed from the environment and config file:
//! `/etc/yubico/yubikeypiv.conf`

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

/// Default location of the YubiKey PIV configuration file
pub const DEFAULT_CONFIG_FILE: &str = "/etc/yubico/yubikeypiv.conf";

use std::{
    env,
    fs::File,
    io::{BufRead, BufReader},
};

/// Source of how a setting was configured
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Source {
    /// User-specified setting
    User,

    /// Admin-specified setting
    Admin,

    /// Default setting
    Default,
}

/// Setting booleans
#[derive(Copy, Clone, Debug)]
pub struct BoolValue {
    /// Boolean value
    pub value: bool,

    /// Source of the configuration setting (user/admin/default)
    pub source: Source,
}

impl BoolValue {
    /// Get a [`BoolValue`] value
    pub fn get(key: &str, def: bool) -> Self {
        let mut setting = get_setting_from_file(key);

        if setting.source == Source::Default {
            setting = get_setting_from_env(key);
        }

        if setting.source == Source::Default {
            setting.value = def;
        }

        setting
    }
}

/// Get a boolean config value
fn get_setting_from_file(key: &str) -> BoolValue {
    let mut setting: BoolValue = BoolValue {
        value: false,
        source: Source::Default,
    };

    let file = match File::open(DEFAULT_CONFIG_FILE) {
        Ok(f) => f,
        Err(_) => return setting,
    };

    for line in BufReader::new(file).lines() {
        let line = match line {
            Ok(line) => line,
            _ => continue,
        };

        if line.starts_with('#') || line.starts_with('\r') || line.starts_with('\n') {
            continue;
        }

        let (name, value) = {
            let mut parts = line.splitn(1, '=');
            let name = parts.next();
            let value = parts.next();
            match (name, value, parts.next()) {
                (Some(name), Some(value), None) => (name.trim(), value.trim()),
                _ => continue,
            }
        };

        if name == key {
            setting.source = Source::Admin;
            setting.value = value == "1" || value == "true";
            break;
        }
    }

    setting
}

/// Get a setting boolean from an environment variable
fn get_setting_from_env(key: &str) -> BoolValue {
    let mut setting: BoolValue = BoolValue {
        value: false,
        source: Source::Default,
    };

    if let Ok(value) = env::var(format!("YUBIKEY_PIV_{}", key)) {
        setting.source = Source::User;
        setting.value = value == "1" || value == "true";
    }

    setting
}
