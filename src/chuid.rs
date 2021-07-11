//! Cardholder Unique Identifier (CHUID) Support

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

use crate::{error::Error, yubikey::YubiKey};
use getrandom::getrandom;
use std::fmt::{self, Debug, Display};
use subtle_encoding::hex;

/// CHUID size
pub const CHUID_SIZE: usize = 59;

/// CARDID size
pub const CARDID_SIZE: usize = 16;

/// FASC-N component size
pub const FASCN_SIZE: usize = 25;

/// Expiration size
pub const EXPIRATION_SIZE: usize = 8;

/// FASC-N offset
const CHUID_FASCN_OFFS: usize = 2;

/// GUID offset
const CHUID_GUID_OFFS: usize = 29;

/// Expiration offset
const CHUID_EXPIRATION_OFFS: usize = 47;

/// CHUID Object ID
const OBJ_CHUID: u32 = 0x005f_c102;

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
const CHUID_TMPL: &[u8] = &[
    0x30, 0x19, 0xd4, 0xe7, 0x39, 0xda, 0x73, 0x9c, 0xed, 0x39, 0xce, 0x73, 0x9d, 0x83, 0x68, 0x58,
    0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0xc8, 0x42, 0x10, 0xc3, 0xeb, 0x34, 0x10, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x35, 0x08, 0x32,
    0x30, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x3e, 0x00, 0xfe, 0x00,
];

/// Cardholder Unique Identifier (CHUID) Card UUID/GUID value
#[derive(Copy, Clone, Debug)]
pub struct Uuid(pub [u8; CARDID_SIZE]);

impl Uuid {
    /// Generate a random Cardholder Unique Identifier (CHUID) UUID
    pub fn generate() -> Result<Self, Error> {
        let mut id = [0u8; CARDID_SIZE];
        getrandom(&mut id).map_err(|_| Error::RandomnessError)?;
        Ok(Self(id))
    }
}

/// Cardholder Unique Identifier (CHUID)
#[derive(Copy, Clone)]
pub struct ChuId(pub [u8; CHUID_SIZE]);

impl ChuId {
    /// Return FASC-N component of CHUID
    pub fn fascn(&self) -> Result<[u8; FASCN_SIZE], Error> {
        let mut fascn = [0u8; FASCN_SIZE];
        fascn.copy_from_slice(&self.0[CHUID_FASCN_OFFS..(CHUID_FASCN_OFFS + FASCN_SIZE)]);
        Ok(fascn)
    }

    /// Return Card UUID/GUID component of CHUID
    pub fn uuid(&self) -> Result<[u8; CARDID_SIZE], Error> {
        let mut uuid = [0u8; CARDID_SIZE];
        uuid.copy_from_slice(&self.0[CHUID_GUID_OFFS..(CHUID_GUID_OFFS + CARDID_SIZE)]);
        Ok(uuid)
    }

    /// Return expiration date component of CHUID
    // TODO(tarcieri): parse expiration?
    pub fn expiration(&self) -> Result<[u8; EXPIRATION_SIZE], Error> {
        let mut expiration = [0u8; EXPIRATION_SIZE];
        expiration.copy_from_slice(
            &self.0[CHUID_EXPIRATION_OFFS..(CHUID_EXPIRATION_OFFS + EXPIRATION_SIZE)],
        );
        Ok(expiration)
    }

    /// Get Cardholder Unique Identifier (CHUID)
    pub fn get(yubikey: &mut YubiKey) -> Result<ChuId, Error> {
        let txn = yubikey.begin_transaction()?;
        let response = txn.fetch_object(OBJ_CHUID)?;

        if response.len() != CHUID_TMPL.len() {
            return Err(Error::GenericError);
        }

        let mut chuid = [0u8; CHUID_SIZE];
        chuid.copy_from_slice(&response[0..CHUID_SIZE]);
        let retval = ChuId { 0: chuid };
        Ok(retval)
    }

    /// Set Cardholder Unique Identifier (CHUID)
    #[cfg(feature = "untested")]
    pub fn set(&self, yubikey: &mut YubiKey) -> Result<(), Error> {
        let mut buf = CHUID_TMPL.to_vec();
        buf[0..self.0.len()].copy_from_slice(&self.0);

        let txn = yubikey.begin_transaction()?;
        txn.save_object(OBJ_CHUID, &buf)
    }
}

impl Display for ChuId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            String::from_utf8(hex::encode(&self.0[..])).unwrap()
        )
    }
}

impl Debug for ChuId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CHUID({:?})", &self.0[..])
    }
}
