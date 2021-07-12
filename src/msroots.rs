//! PKCS#7 formatted certificate store for enterprise trusted roots.

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
    consts::{CB_OBJ_MAX, CB_OBJ_TAG_MAX},
    serialization::*,
    Error, Result, YubiKey,
};
use log::error;

const OBJ_MSROOTS1: u32 = 0x005f_ff11;
#[allow(dead_code)]
const OBJ_MSROOTS2: u32 = 0x005f_ff12;
#[allow(dead_code)]
const OBJ_MSROOTS3: u32 = 0x005f_ff13;
#[allow(dead_code)]
const OBJ_MSROOTS4: u32 = 0x005f_ff14;
const OBJ_MSROOTS5: u32 = 0x005f_ff15;

const TAG_MSROOTS_END: u8 = 0x82;
const TAG_MSROOTS_MID: u8 = 0x83;

/// PKCS#7-formatted certificate store for enterprise trust roots.
///
/// The `msroots` file contains a bag of certificates with empty content and
/// an empty signature, allowing an enterprise root certificate truststore to
/// be written to and read from a YubiKey.
///
/// For more information, see:
/// <https://docs.microsoft.com/en-us/windows-hardware/drivers/smartcard/developer-guidelines#-interoperability-with-msroots>
#[cfg_attr(docsrs, doc(cfg(feature = "untested")))]
pub struct MsRoots(Vec<u8>);

impl MsRoots {
    /// Initialize a local certificate struct from the given bytebuffer
    pub fn new(msroots: impl AsRef<[u8]>) -> Result<Self> {
        Ok(MsRoots(msroots.as_ref().into()))
    }

    /// Read `msroots` file from YubiKey
    pub fn read(yubikey: &mut YubiKey) -> Result<Option<Self>> {
        let txn = yubikey.begin_transaction()?;

        // allocate first page
        let mut data = Vec::with_capacity(CB_OBJ_MAX);

        for object_id in OBJ_MSROOTS1..OBJ_MSROOTS5 {
            let buf = txn.fetch_object(object_id)?;

            let (_, tlv) = match Tlv::parse(&buf) {
                Ok(res) => res,
                Err(_) => return Ok(None),
            };

            if (TAG_MSROOTS_MID != tlv.tag || OBJ_MSROOTS5 == object_id)
                && (TAG_MSROOTS_END != tlv.tag)
            {
                // the current object doesn't contain a valid part of a msroots file

                // treat condition as object isn't found
                return Ok(None);
            }

            data.extend_from_slice(tlv.value);

            if tlv.tag == TAG_MSROOTS_END {
                break;
            }
        }

        MsRoots::new(&data).map(Some).map_err(|e| {
            error!("error parsing msroots: {:?}", e);
            e
        })
    }

    /// Write `msroots` file to YubiKey
    pub fn write(&self, yubikey: &mut YubiKey) -> Result<()> {
        let mut buf = [0u8; CB_OBJ_MAX];
        let mut offset: usize;
        let mut data_offset: usize = 0;
        let mut data_chunk: usize;
        let data = &self.0;
        let data_len = data.len();
        let n_objs: usize;
        let txn = yubikey.begin_transaction()?;

        if data_len == 0 {
            return txn.save_object(OBJ_MSROOTS1, &[]);
        }

        // Calculate number of objects required to store blob
        n_objs = (data_len / (CB_OBJ_MAX - CB_OBJ_TAG_MAX)) + 1;

        if n_objs > 5 {
            return Err(Error::SizeError);
        }

        for i in 0..n_objs {
            offset = 0;

            data_chunk = if CB_OBJ_MAX - CB_OBJ_TAG_MAX < data_len - data_offset {
                CB_OBJ_MAX - CB_OBJ_TAG_MAX
            } else {
                data_len - data_offset
            };

            offset += Tlv::write(
                &mut buf,
                if i == n_objs - 1 {
                    TAG_MSROOTS_END
                } else {
                    TAG_MSROOTS_MID
                },
                &data[data_offset..(data_offset + data_chunk)],
            )?;

            txn.save_object(OBJ_MSROOTS1 + i as u32, &buf[..offset])?;

            data_offset += data_chunk;
        }

        Ok(())
    }
}

impl AsRef<[u8]> for MsRoots {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
