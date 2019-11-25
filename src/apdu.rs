//! Application Protocol Data Unit (APDU)

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

use crate::{error::Error, response::Response, transaction::Transaction, Buffer};
use std::fmt::{self, Debug};
use zeroize::{Zeroize, Zeroizing};

/// Maximum amount of command data that can be included in an APDU
const APDU_DATA_MAX: usize = 0xFF;

/// Application Protocol Data Unit (APDU).
///
/// These messages are packets used to communicate with the YubiKey.
#[derive(Clone)]
pub(crate) struct APDU {
    /// Instruction class: indicates the type of command (e.g. inter-industry or proprietary)
    cla: u8,

    /// Instruction code: indicates the specific command (e.g. "write data")
    ins: u8,

    /// Instruction parameter 1 for the command (e.g. offset into file at which to write the data)
    p1: u8,

    /// Instruction parameter 2 for the command
    p2: u8,

    /// Command data to be sent (`lc` is calculated as `data.len()`)
    data: Vec<u8>,
}

impl APDU {
    /// Create a new APDU with the given instruction code
    pub fn new(ins: u8) -> Self {
        Self {
            cla: 0,
            ins,
            p1: 0,
            p2: 0,
            data: vec![],
        }
    }

    /// Set this APDU's class
    #[cfg(feature = "untested")]
    pub fn cla(&mut self, value: u8) -> &mut Self {
        self.cla = value;
        self
    }

    /// Set this APDU's first parameter only
    pub fn p1(&mut self, value: u8) -> &mut Self {
        self.p1 = value;
        self
    }

    /// Set both parameters for this APDU
    #[cfg(feature = "untested")]
    pub fn params(&mut self, p1: u8, p2: u8) -> &mut Self {
        self.p1 = p1;
        self.p2 = p2;
        self
    }

    /// Set the command data for this APDU.
    ///
    /// Panics if the byte slice is more than 255 bytes!
    pub fn data(&mut self, bytes: impl AsRef<[u8]>) -> &mut Self {
        assert!(self.data.is_empty(), "APDU command already set!");

        let bytes = bytes.as_ref();

        assert!(
            bytes.len() <= APDU_DATA_MAX,
            "APDU command data too long: {} (max: {})",
            bytes.len(),
            APDU_DATA_MAX
        );

        self.data.extend_from_slice(bytes);
        self
    }

    /// Transmit this APDU using the given card transaction
    pub fn transmit(&self, txn: &Transaction<'_>, recv_len: usize) -> Result<Response, Error> {
        let response_bytes = txn.transmit(&self.to_bytes(), recv_len)?;
        Ok(Response::from_bytes(response_bytes))
    }

    /// Consume this APDU and return a self-zeroizing buffer
    pub fn to_bytes(&self) -> Buffer {
        let mut bytes = Vec::with_capacity(5 + self.data.len());
        bytes.push(self.cla);
        bytes.push(self.ins);
        bytes.push(self.p1);
        bytes.push(self.p2);
        bytes.push(self.data.len() as u8);
        bytes.extend_from_slice(self.data.as_ref());
        Zeroizing::new(bytes)
    }
}

impl Debug for APDU {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "APDU {{ cla: {}, ins: {}, p1: {}, p2: {}, lc: {}, data: {:?} }}",
            self.cla,
            self.ins,
            self.p1,
            self.p2,
            self.data.len(),
            self.data.as_slice()
        )
    }
}

impl Drop for APDU {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for APDU {
    fn zeroize(&mut self) {
        self.cla.zeroize();
        self.ins.zeroize();
        self.p1.zeroize();
        self.p2.zeroize();
        self.data.zeroize();
    }
}
