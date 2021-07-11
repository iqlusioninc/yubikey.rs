//! YubiKey Configuration Values

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

use crate::{
    metadata::{AdminData, ProtectedData},
    mgm::{MgmType, ADMIN_FLAGS_1_PROTECTED_MGM},
    yubikey::{YubiKey, ADMIN_FLAGS_1_PUK_BLOCKED},
    Result, TAG_ADMIN_FLAGS_1, TAG_ADMIN_SALT, TAG_ADMIN_TIMESTAMP, TAG_PROTECTED_FLAGS_1,
    TAG_PROTECTED_MGM,
};
use log::error;
use std::{
    convert::TryInto,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const CB_ADMIN_TIMESTAMP: usize = 0x04;
const PROTECTED_FLAGS_1_PUK_NOBLOCK: u8 = 0x01;

/// Config
#[derive(Copy, Clone, Debug)]
pub struct Config {
    /// Protected data available
    protected_data_available: bool,

    /// PUK blocked
    puk_blocked: bool,

    /// No block on upgrade
    puk_noblock_on_upgrade: bool,

    /// PIN last changed
    pin_last_changed: Option<SystemTime>,

    /// MGM type
    mgm_type: MgmType,
}

impl Config {
    /// Get YubiKey config
    pub fn get(yubikey: &mut YubiKey) -> Result<Config> {
        let mut config = Config {
            protected_data_available: false,
            puk_blocked: false,
            puk_noblock_on_upgrade: false,
            pin_last_changed: None,
            mgm_type: MgmType::Manual,
        };

        let txn = yubikey.begin_transaction()?;

        if let Ok(admin_data) = AdminData::read(&txn) {
            if let Ok(item) = admin_data.get_item(TAG_ADMIN_FLAGS_1) {
                if item.is_empty() {
                    error!("empty response for admin flags metadata item! ignoring");
                } else {
                    if item[0] & ADMIN_FLAGS_1_PUK_BLOCKED != 0 {
                        config.puk_blocked = true;
                    }

                    if item[0] & ADMIN_FLAGS_1_PROTECTED_MGM != 0 {
                        config.mgm_type = MgmType::Protected;
                    }
                }
            }

            if admin_data.get_item(TAG_ADMIN_SALT).is_ok() {
                if config.mgm_type != MgmType::Manual {
                    error!("conflicting types of MGM key administration configured");
                } else {
                    config.mgm_type = MgmType::Derived;
                }
            }

            if let Ok(item) = admin_data.get_item(TAG_ADMIN_TIMESTAMP) {
                if item.len() != CB_ADMIN_TIMESTAMP {
                    error!("pin timestamp in admin metadata is an invalid size");
                } else {
                    // TODO(tarcieri): double-check endianness is correct
                    let pin_last_changed = u32::from_le_bytes(item.try_into().unwrap());

                    if pin_last_changed != 0 {
                        config.pin_last_changed =
                            Some(UNIX_EPOCH + Duration::from_secs(pin_last_changed as u64));
                    }
                }
            }
        }

        if let Ok(protected_data) = ProtectedData::read(&txn) {
            config.protected_data_available = true;

            if let Ok(item) = protected_data.get_item(TAG_PROTECTED_FLAGS_1) {
                if item.is_empty() {
                    error!("empty response for protected flags metadata item! ignoring");
                } else if item[0] & PROTECTED_FLAGS_1_PUK_NOBLOCK != 0 {
                    config.puk_noblock_on_upgrade = true;
                }
            }

            if protected_data.get_item(TAG_PROTECTED_MGM).is_ok() {
                if config.mgm_type != MgmType::Protected {
                    error!(
                        "conflicting types of mgm key administration configured: protected MGM exists"
                    );
                }

                // Always favor protected MGM
                config.mgm_type = MgmType::Protected;
            }
        }

        Ok(config)
    }
}
