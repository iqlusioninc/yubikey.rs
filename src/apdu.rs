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

use crate::{error::Error, transaction::Transaction, Buffer};
use log::trace;
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
        trace!(">>> {:?}", self);
        let response = Response::from(txn.transmit(&self.to_bytes(), recv_len)?);
        trace!("<<< {:?}", &response);
        Ok(response)
    }

    /// Serialize this APDU as a self-zeroizing byte buffer
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

/// APDU responses
#[derive(Debug)]
pub(crate) struct Response {
    /// Status words
    status_words: StatusWords,

    /// Buffer
    data: Vec<u8>,
}

impl Response {
    /// Create a new response from the given status words and buffer
    #[cfg(feature = "untested")]
    pub fn new(status_words: StatusWords, data: Vec<u8>) -> Response {
        Response { status_words, data }
    }

    /// Get the [`StatusWords`] for this response.
    pub fn status_words(&self) -> StatusWords {
        self.status_words
    }

    /// Get the raw [`StatusWords`] code for this response.
    #[cfg(feature = "untested")]
    pub fn code(&self) -> u32 {
        self.status_words.code()
    }

    /// Do the status words for this response indicate success?
    pub fn is_success(&self) -> bool {
        self.status_words.is_success()
    }

    /// Borrow the response data
    pub fn data(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl AsRef<[u8]> for Response {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

impl Drop for Response {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl From<Vec<u8>> for Response {
    fn from(mut bytes: Vec<u8>) -> Self {
        if bytes.len() < 2 {
            return Response {
                status_words: StatusWords::None,
                data: bytes,
            };
        }

        let sw = StatusWords::from(
            (bytes[bytes.len() - 2] as u32) << 8 | (bytes[bytes.len() - 1] as u32),
        );

        let len = bytes.len() - 2;
        bytes.truncate(len);

        Response {
            status_words: sw,
            data: bytes,
        }
    }
}

impl Zeroize for Response {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

/// Status Words (SW) are 2-byte values returned by a card command.
///
/// The first byte of a status word is referred to as SW1 and the second byte
/// of a status word is referred to as SW2.
///
/// See NIST special publication 800-73-4, section 5.6:
/// <https://csrc.nist.gov/publications/detail/sp/800-73/4/final>
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum StatusWords {
    /// No status words present in response
    None,

    /// Successful execution
    Success,

    /// Security status not satisfied
    SecurityStatusError,

    /// Authentication method blocked
    AuthBlockedError,

    /// Incorrect parameter in command data field
    IncorrectParamError,

    //
    // Custom Yubico Status Word extensions
    //
    /// Incorrect card slot error
    IncorrectSlotError,

    /// Not supported error
    NotSupportedError,

    /// Other/unrecognized status words
    Other(u32),
}

impl StatusWords {
    /// Get the numerical response code for these status words
    pub fn code(self) -> u32 {
        match self {
            StatusWords::None => 0,
            StatusWords::SecurityStatusError => 0x6982,
            StatusWords::AuthBlockedError => 0x6983,
            StatusWords::IncorrectParamError => 0x6a80,
            StatusWords::IncorrectSlotError => 0x6b00,
            StatusWords::NotSupportedError => 0x6d00,
            StatusWords::Success => 0x9000,
            StatusWords::Other(n) => n,
        }
    }

    /// Do these status words indicate success?
    pub fn is_success(self) -> bool {
        self == StatusWords::Success
    }
}

impl From<u32> for StatusWords {
    fn from(sw: u32) -> Self {
        match sw {
            0x0000 => StatusWords::None,
            0x6982 => StatusWords::SecurityStatusError,
            0x6983 => StatusWords::AuthBlockedError,
            0x6a80 => StatusWords::IncorrectParamError,
            0x6b00 => StatusWords::IncorrectSlotError,
            0x6d00 => StatusWords::NotSupportedError,
            0x9000 => StatusWords::Success,
            _ => StatusWords::Other(sw),
        }
    }
}

impl From<StatusWords> for u32 {
    fn from(sw: StatusWords) -> u32 {
        sw.code()
    }
}
