//! MS Container Map Records
//!
//! These appear(?) to be defined in Microsoft's Smart Card Minidriver Specification:
//! <https://docs.microsoft.com/en-us/previous-versions/windows/hardware/design/dn631754(v=vs.85)>

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

use crate::{error::Error, key::SlotId, serialization::*, yubikey::YubiKey, CB_OBJ_MAX};
use log::error;
use std::{
    convert::{TryFrom, TryInto},
    fmt::{self, Debug},
};

/// Container name length
const CONTAINER_NAME_LEN: usize = 40;

/// Container record length: 27 = 80 + 1 + 1 + 2 + 1 + 1 + 1 + 20
const CONTAINER_REC_LEN: usize = (2 * CONTAINER_NAME_LEN) + 27;

const OBJ_MSCMAP: u32 = 0x005f_ff10;

const TAG_MSCMAP: u8 = 0x81;

/// MS Container Map(?) Records
#[derive(Copy, Clone)]
pub struct Container {
    /// Container name
    pub name: [u16; CONTAINER_NAME_LEN],

    /// Card slot
    pub slot: SlotId,

    /// Key spec
    pub key_spec: u8,

    /// Key size in bits
    pub key_size_bits: u16,

    /// Flags
    pub flags: u8,

    /// PIN ID
    pub pin_id: u8,

    /// Associated ECHD(?) container (typo of "ecdh" perhaps?)
    pub associated_echd_container: u8,

    /// Cert fingerprint
    pub cert_fingerprint: [u8; 20],
}

impl Container {
    /// Read MS Container Map records
    pub fn read_mscmap(yubikey: &mut YubiKey) -> Result<Vec<Self>, Error> {
        let txn = yubikey.begin_transaction()?;
        let response = txn.fetch_object(OBJ_MSCMAP)?;
        let mut containers = vec![];

        let (_, tlv) = match Tlv::parse(&response) {
            Ok(res) => res,
            Err(_) => {
                // TODO(tarcieri): is this really OK?
                return Ok(containers);
            }
        };

        if tlv.tag != TAG_MSCMAP {
            // TODO(tarcieri): yubico-piv-tool returned success here? should we?
            return Err(Error::InvalidObject);
        }

        for chunk in tlv.value.chunks_exact(CONTAINER_REC_LEN) {
            containers.push(Container::new(chunk)?);
        }

        Ok(containers)
    }

    /// Write MS Container Map records.
    pub fn write_mscmap(yubikey: &mut YubiKey, containers: &[Self]) -> Result<(), Error> {
        let mut buf = [0u8; CB_OBJ_MAX];
        let mut offset = 0;
        let n_containers = containers.len();
        let data_len = n_containers * CONTAINER_REC_LEN;

        let txn = yubikey.begin_transaction()?;

        if n_containers == 0 {
            return txn.save_object(OBJ_MSCMAP, &[]);
        }

        let req_len = 1 + set_length(&mut buf, data_len) + data_len;

        if req_len > CB_OBJ_MAX {
            return Err(Error::SizeError);
        }

        buf[offset] = TAG_MSCMAP;
        offset += 1;
        offset += set_length(&mut buf[offset..], data_len);

        for (i, chunk) in buf[..data_len]
            .chunks_exact_mut(CONTAINER_REC_LEN)
            .enumerate()
        {
            chunk.copy_from_slice(&containers[i].to_bytes());
        }

        offset += data_len;
        txn.save_object(OBJ_MSCMAP, &buf[..offset])
    }

    /// Parse a container record from a byte slice
    pub fn new(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != CONTAINER_REC_LEN {
            error!(
                "couldn't parse PIV container: expected {}-bytes, got {}-bytes",
                CONTAINER_REC_LEN,
                bytes.len()
            );
            return Err(Error::ParseError);
        }

        let mut name = [0u16; CONTAINER_NAME_LEN];
        let name_bytes_len = CONTAINER_NAME_LEN * 2;

        for (i, chunk) in bytes[..name_bytes_len].chunks_exact(2).enumerate() {
            name[i] = u16::from_le_bytes(chunk.try_into().unwrap());
        }

        let mut cert_fingerprint = [0u8; 20];
        cert_fingerprint.copy_from_slice(&bytes[(bytes.len() - 20)..]);

        Ok(Container {
            name,
            slot: bytes[name_bytes_len].try_into()?,
            key_spec: bytes[name_bytes_len + 1],
            key_size_bits: u16::from_le_bytes(
                bytes[(name_bytes_len + 2)..(name_bytes_len + 4)]
                    .try_into()
                    .unwrap(),
            ),
            flags: bytes[name_bytes_len + 4],
            pin_id: bytes[name_bytes_len + 5],
            associated_echd_container: bytes[name_bytes_len + 6],
            cert_fingerprint,
        })
    }

    /// Parse the container name as a UTF-16 string
    pub fn parse_name(&self) -> Result<String, Error> {
        String::from_utf16(&self.name).map_err(|_| Error::ParseError)
    }

    /// Serialize a container record as a byte size
    pub fn to_bytes(&self) -> [u8; CONTAINER_REC_LEN] {
        let mut bytes = Vec::with_capacity(CONTAINER_REC_LEN);

        for i in 0..CONTAINER_NAME_LEN {
            bytes.extend_from_slice(&self.name[i].to_le_bytes());
        }

        bytes.push(self.slot.into());
        bytes.push(self.key_spec);
        bytes.extend_from_slice(&self.key_size_bits.to_le_bytes());
        bytes.push(self.flags);
        bytes.push(self.pin_id);
        bytes.push(self.associated_echd_container);
        bytes.extend_from_slice(&self.cert_fingerprint);

        // TODO(tarcieri): use TryInto here when const generics are available
        let mut result = [0u8; CONTAINER_REC_LEN];
        result.copy_from_slice(&bytes);
        result
    }
}

impl Debug for Container {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PivContainer {{ name: {:?}, slot: {:?}, key_spec: {}, key_size_bits: {}, \
             flags: {}, pin_id: {}, associated_echd_container: {}, cert_fingerprint: {:?} }}",
            &self.name[..],
            self.slot,
            self.key_spec,
            self.key_size_bits,
            self.flags,
            self.pin_id,
            self.associated_echd_container,
            &self.cert_fingerprint[..]
        )
    }
}

impl<'a> TryFrom<&'a [u8]> for Container {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Error> {
        Self::new(bytes)
    }
}
