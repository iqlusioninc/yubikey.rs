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

use crate::{Error, Result, YubiKey};
use std::fmt::{self, Debug, Display};
use uuid::Uuid;

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
#[allow(dead_code)]
const CHUID_TMPL: &[u8] = &[
    0x30, 0x19, // FASC-N tag + length
    0xd4, 0xe7, 0x39, 0xda, 0x73, 0x9c, 0xed, 0x39, 0xce, 0x73, 0x9d, 0x83, 0x68, 0x58, 0x21, 0x08,
    0x42, 0x10, 0x84, 0x21, 0xc8, 0x42, 0x10, 0xc3, 0xeb, // FASC-N
    0x34, 0x10, // Card UUID tag + length
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, // Card UUID
    0x35, 0x08, // Exp Date tag + length
    0x32, 0x30, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31, // Exp Date as ascii bytes (20300101)
    0x3e, 0x00, // Signature + length
    0xfe, 0x00, // Error detection code
];

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Fascn {
    data: [u8; ChuId::FASCN_SIZE],
}

impl Default for Fascn {
    /// FASC-N containing S9999F9999F999999F0F1F0000000000300001E encoded in 4-bit BCD with 1 bit parity.
    /// For most users of PIV this is the correct value per SP-800-73-4 which states that "since non-Federal
    /// issuers do not have Agency Codes assigned to them, which means that they are
    /// unable to create unique FASC-N identifiers for the cards they issue. As a result, PIV-I FAQ requires the first 14 digits of
    /// the FASC-Ns for PIV-I cards (the Agency Code, System Code, and Credential Number) to be populated with all nines."
    fn default() -> Self {
        Self {
            data: [
                0xd4, 0xe7, 0x39, 0xda, 0x73, 0x9c, 0xed, 0x39, 0xce, 0x73, 0x9d, 0x83, 0x68, 0x58,
                0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0xc8, 0x42, 0x10, 0xc3, 0xeb, // FASC-N
            ],
        }
    }
}

impl Display for Fascn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::upper::encode_string(&self.data),)
    }
}

/// Cardholder Unique Identifier (CHUID).
#[derive(Copy, Clone, Debug)]
pub struct ChuId {
    fascn: Fascn,
    uuid: Uuid,
    expiration: [u8; ChuId::EXPIRATION_SIZE],
}

impl ChuId {
    /// CHUID size in bytes
    pub const BYTE_SIZE: usize = 59;

    /// FASC-N component size
    pub const FASCN_SIZE: usize = 25;

    /// Expiration size
    pub const EXPIRATION_SIZE: usize = 8;

    /// Return a builder that allows construction of a new ChuId value from it's
    /// components.
    pub fn builder(uuid: Uuid, expiration: &[u8; ChuId::EXPIRATION_SIZE]) -> ChuIdBuilder {
        ChuIdBuilder::new(uuid, expiration)
    }

    /// Return FASC-N component of CHUID
    pub fn fascn(&self) -> Fascn {
        self.fascn
    }

    /// Return Card UUID/GUID component of CHUID
    pub fn uuid(&self) -> Uuid {
        self.uuid
    }

    /// Return expiration date component of CHUID
    // TODO(tarcieri): parse expiration?
    pub fn expiration(&self) -> [u8; Self::EXPIRATION_SIZE] {
        self.expiration
    }

    /// Get Cardholder Unique Identifier (CHUID)
    pub fn get(yubikey: &mut YubiKey) -> Result<ChuId> {
        let txn = yubikey.begin_transaction()?;
        let response = txn.fetch_object(OBJ_CHUID)?;

        Self::parse(&response)
    }

    /// Set Cardholder Unique Identifier (CHUID)
    pub fn set(&self, yubikey: &mut YubiKey) -> Result<()> {
        let buf = self.serialise();

        let txn = yubikey.begin_transaction()?;
        txn.save_object(OBJ_CHUID, &buf)
    }

    fn serialise(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::with_capacity(Self::BYTE_SIZE);

        buf.extend([0x30, ChuId::FASCN_SIZE as u8]);
        buf.extend(&self.fascn.data);

        buf.extend([0x34, 0x10]);
        buf.extend(self.uuid.as_bytes());

        buf.extend([0x35, ChuId::EXPIRATION_SIZE as u8]);
        buf.extend(&self.expiration);

        buf.extend([0x3e, 0x00]);
        buf.extend([0xfe, 0x00]);

        buf
    }

    fn parse(input: &[u8]) -> Result<Self> {
        let mut fascn = None;
        let mut uuid = None;
        let mut expiration = None;

        let mut view = input;
        loop {
            if view.len() < 2 {
                // Insufficient bytes to continue.
                break;
            }

            let tag = view[0];
            let length = view[1] as usize;

            // Advance the buffer.
            view = view.get(2..).ok_or(Error::ParseError)?;

            if length > 0 {
                let data = view.get(..length).ok_or(Error::ParseError)?;

                match (tag, length) {
                    (0x30, 0x19) => {
                        let mut buf = [0; ChuId::FASCN_SIZE];
                        buf.copy_from_slice(data);
                        fascn = Some(Fascn { data: buf });
                    }
                    (0x34, 0x10) => {
                        let guid = Uuid::from_slice(data).map_err(|_| Error::ParseError)?;
                        uuid = Some(guid);
                    }
                    (0x35, 0x08) => {
                        let mut buf = [0; ChuId::EXPIRATION_SIZE];
                        buf.copy_from_slice(data);
                        expiration = Some(buf);
                    }
                    _ => {}
                }

                // Advance the buffer.
                view = view.get(length..).ok_or(Error::ParseError)?;
            }
        }

        match (fascn, uuid, expiration) {
            (Some(fascn), Some(uuid), Some(expiration)) => Ok(Self {
                fascn,
                uuid,
                expiration,
            }),
            _ => Err(Error::ParseError),
        }
    }
}

impl Display for ChuId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "fascn: {}, uuid: {}, expiration: {}",
            self.fascn,
            self.uuid,
            str::from_utf8(&self.expiration).unwrap_or("invalid")
        )
    }
}

#[derive(Copy, Clone, Debug)]
pub struct ChuIdBuilder {
    fascn: Option<Fascn>,
    uuid: Uuid,
    expiration: [u8; ChuId::EXPIRATION_SIZE],
}

impl ChuIdBuilder {
    pub fn new(uuid: Uuid, expiration: &[u8; ChuId::EXPIRATION_SIZE]) -> Self {
        Self {
            fascn: None,
            uuid,
            expiration: expiration.to_owned(),
        }
    }

    pub fn fascn(mut self, fascn: Option<Fascn>) -> Self {
        self.fascn = fascn;
        self
    }

    pub fn build(self) -> ChuId {
        ChuId {
            fascn: self.fascn.unwrap_or_default(),
            uuid: self.uuid,
            expiration: self.expiration,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CHUID_TMPL, ChuId, Fascn};

    #[test]
    fn parse_chuid_tmpl() {
        let chuid = ChuId::parse(CHUID_TMPL).expect("Failed to parse template ChuId");

        eprintln!("{}", chuid);

        assert_eq!(chuid.fascn, Fascn::default());

        assert_eq!(
            chuid.uuid(),
            uuid::uuid!("00000000-0000-0000-0000-000000000000")
        );

        assert_eq!(
            chuid.expiration(),
            [
                0x32, 0x30, 0x33, 0x30, 0x30, 0x31, 0x30,
                0x31, // Exp Date as ascii bytes (20300101)
            ]
        );

        // Assert that serialisation works too.
        let bytes = chuid.serialise();

        assert_eq!(&bytes, CHUID_TMPL);
    }
}
