//! YubiKey Certificates

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
    consts::*,
    error::Error,
    key::{self, SlotId},
    serialization::*,
    transaction::Transaction,
    yubikey::YubiKey,
    Buffer,
};
use log::error;
use zeroize::Zeroizing;

/// Certificates
#[derive(Clone, Debug)]
pub struct Certificate(Buffer);

impl Certificate {
    /// Read a certificate from the given slot in the YubiKey
    pub fn read(yubikey: &mut YubiKey, slot: SlotId) -> Result<Self, Error> {
        let txn = yubikey.begin_transaction()?;
        let buf = read_certificate(&txn, slot)?;

        if buf.is_empty() {
            return Err(Error::InvalidObject);
        }

        Ok(Certificate(buf))
    }

    /// Write this certificate into the YubiKey in the given slot
    pub fn write(&self, yubikey: &mut YubiKey, slot: SlotId, certinfo: u8) -> Result<(), Error> {
        let max_size = yubikey.obj_size_max();
        let txn = yubikey.begin_transaction()?;
        write_certificate(&txn, slot, Some(&self.0), certinfo, max_size)
    }

    /// Delete a certificate located at the given slot of the given YubiKey
    pub fn delete(yubikey: &mut YubiKey, slot: SlotId) -> Result<(), Error> {
        let max_size = yubikey.obj_size_max();
        let txn = yubikey.begin_transaction()?;
        write_certificate(&txn, slot, None, 0, max_size)
    }

    /// Initialize a local certificate struct from the given bytebuffer
    pub fn new(cert: impl Into<Buffer>) -> Result<Self, Error> {
        let cert = cert.into();

        if cert.is_empty() {
            error!("certificate cannot be empty");
            return Err(Error::SizeError);
        }

        Ok(Certificate(cert))
    }

    /// Extract the inner buffer
    pub fn into_buffer(self) -> Buffer {
        self.0
    }
}

impl AsRef<[u8]> for Certificate {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Read certificate
pub(crate) fn read_certificate(txn: &Transaction<'_>, slot: SlotId) -> Result<Buffer, Error> {
    let mut len: usize = 0;
    let object_id = key::slot_object(slot)?;

    let mut buf = match txn.fetch_object(object_id) {
        Ok(b) => b,
        Err(_) => {
            // TODO(tarcieri): is this really ok?
            return Ok(Zeroizing::new(vec![]));
        }
    };

    if buf.len() < CB_OBJ_TAG_MIN {
        // TODO(tarcieri): is this really ok?
        return Ok(Zeroizing::new(vec![]));
    }

    if buf[0] == TAG_CERT {
        let offset = 1 + get_length(&buf[1..], &mut len);

        if len > buf.len() - offset {
            // TODO(tarcieri): is this really ok?
            return Ok(Zeroizing::new(vec![]));
        }

        buf.copy_within(offset..offset + len, 0);
        buf.truncate(len);
    }

    Ok(buf)
}

/// Write certificate
pub(crate) fn write_certificate(
    txn: &Transaction<'_>,
    slot: SlotId,
    data: Option<&[u8]>,
    certinfo: u8,
    max_size: usize,
) -> Result<(), Error> {
    let mut buf = [0u8; CB_OBJ_MAX];
    let mut offset = 0;

    let object_id = key::slot_object(slot)?;

    if data.is_none() {
        return txn.save_object(object_id, &[]);
    }

    let data = data.unwrap();

    let mut req_len = 1 /* cert tag */ + 3 /* compression tag + data*/ + 2 /* lrc */;
    req_len += set_length(&mut buf, data.len());
    req_len += data.len();

    if req_len < data.len() || req_len > max_size {
        return Err(Error::SizeError);
    }

    buf[offset] = TAG_CERT;
    offset += 1;
    offset += set_length(&mut buf[offset..], data.len());

    buf[offset..(offset + data.len())].copy_from_slice(&data);

    offset += data.len();

    // write compression info and LRC trailer
    buf[offset] = TAG_CERT_COMPRESS;
    buf[offset + 1] = 0x01;
    buf[offset + 2] = if certinfo == YKPIV_CERTINFO_GZIP {
        0x01
    } else {
        0x00
    };
    buf[offset + 3] = TAG_CERT_LRC;
    buf[offset + 4] = 00;

    offset += 5;

    txn.save_object(object_id, &buf[..offset])
}
