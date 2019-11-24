//! `msroots`: PKCS#7 formatted certificate store for enterprise trusted roots.
//!
//! This `msroots` file contains a bag of certificates with empty content and
//! an empty signature, allowing an enterprise root certificate truststore to
//! be written to and read from a YubiKey.
//!
//! For more information, see:
//! <https://docs.microsoft.com/en-us/windows-hardware/drivers/smartcard/developer-guidelines#-interoperability-with-msroots>

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

use crate::{consts::*, error::Error, serialization::*, yubikey::YubiKey};
use log::error;
use std::{ptr, slice};

/// `msroots` file: PKCS#7-formatted certificate store for enterprise trust roots
pub struct MsRoots(Vec<u8>);

impl MsRoots {
    /// Initialize a local certificate struct from the given bytebuffer
    pub fn new(msroots: impl AsRef<[u8]>) -> Result<Self, Error> {
        Ok(MsRoots(msroots.as_ref().into()))
    }

    /// Read `msroots` file from YubiKey
    pub fn read(yubikey: &mut YubiKey) -> Result<Vec<Self>, Error> {
        let mut len: usize = 0;
        let mut ptr: *mut u8;
        let mut tag: u8;
        let mut offset: usize = 0;

        let mut results = vec![];
        let cb_data = yubikey.obj_size_max();
        let txn = yubikey.begin_transaction()?;

        // allocate first page
        let mut p_data = vec![0u8; cb_data];

        for object_id in YKPIV_OBJ_MSROOTS1..YKPIV_OBJ_MSROOTS5 {
            let mut buf = txn.fetch_object(object_id)?;
            let cb_buf = buf.len();

            ptr = buf.as_mut_ptr();

            if cb_buf < CB_OBJ_TAG_MIN {
                return Ok(results);
            }

            unsafe {
                tag = *ptr;
                ptr = ptr.add(1);
            }

            if tag != TAG_MSROOTS_MID && (tag != TAG_MSROOTS_END || object_id == YKPIV_OBJ_MSROOTS5)
            {
                // the current object doesn't contain a valid part of a msroots file

                // treat condition as object isn't found
                return Ok(results);
            }

            unsafe {
                ptr = ptr.add(get_length(
                    slice::from_raw_parts(ptr, buf.as_ptr() as usize + buf.len() - ptr as usize),
                    &mut len,
                ));
            }

            // check that decoded length represents object contents
            if len > cb_buf - (ptr as isize - buf.as_mut_ptr() as isize) as usize {
                return Ok(results);
            }

            unsafe {
                ptr::copy(ptr, p_data.as_mut_ptr().add(offset), len);
            }

            offset += len;

            match MsRoots::new(&p_data[..offset]) {
                Ok(msroots) => results.push(msroots),
                Err(res) => error!("error parsing msroots: {:?}", res),
            }

            if tag == TAG_MSROOTS_END {
                break;
            }
        }

        Ok(results)
    }

    /// Write `msroots` file to YubiKey
    pub fn write(&self, yubikey: &mut YubiKey) -> Result<(), Error> {
        let mut buf = [0u8; CB_OBJ_MAX];
        let mut offset: usize;
        let mut data_offset: usize = 0;
        let mut data_chunk: usize;
        let data = &self.0;
        let data_len = data.len();
        let n_objs: usize;
        let cb_obj_max = yubikey.obj_size_max();
        let txn = yubikey.begin_transaction()?;

        if data_len == 0 {
            return txn.save_object(YKPIV_OBJ_MSROOTS1, &[]);
        }

        n_objs = (data_len / (cb_obj_max - 4)) + 1;

        if n_objs > 5 {
            return Err(Error::SizeError);
        }

        for i in 0..n_objs {
            offset = 0;

            data_chunk = if cb_obj_max - 4 < data_len - data_offset {
                cb_obj_max - 4
            } else {
                data_len - data_offset
            };

            buf[offset] = if i == n_objs - 1 {
                TAG_MSROOTS_END
            } else {
                TAG_MSROOTS_MID
            };

            offset += 1;
            offset += set_length(&mut buf[offset..], data_chunk);
            buf[offset..].copy_from_slice(&data[data_offset..(data_offset + data_chunk)]);
            offset += data_chunk;

            txn.save_object(YKPIV_OBJ_MSROOTS1 + i as u32, &buf[..offset])?;

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
