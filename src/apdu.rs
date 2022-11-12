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

use crate::{transaction::Transaction, Buffer, Result};
use log::trace;
use zeroize::{Zeroize, Zeroizing};

/// Maximum amount of command data that can be included in an APDU
const APDU_DATA_MAX: usize = 0xFF;

/// Application Protocol Data Unit (APDU).
///
/// These messages are packets used to communicate with the YubiKey.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Apdu {
    /// Instruction class: indicates the type of command (e.g. inter-industry or proprietary)
    cla: u8,

    /// Instruction code: indicates the specific command (e.g. "write data")
    ins: Ins,

    /// Instruction parameter 1 for the command (e.g. offset into file at which to write the data)
    p1: u8,

    /// Instruction parameter 2 for the command
    p2: u8,

    /// Command data to be sent (`lc` is calculated as `data.len()`)
    data: Vec<u8>,
}

impl Apdu {
    /// Create a new APDU with the given instruction code
    pub fn new(ins: impl Into<Ins>) -> Self {
        Self {
            cla: 0,
            ins: ins.into(),
            p1: 0,
            p2: 0,
            data: vec![],
        }
    }

    /// Set this APDU's class
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
    pub fn transmit(&self, txn: &Transaction<'_>, recv_len: usize) -> Result<Response> {
        trace!(">>> {:?}", self);
        let response = Response::from(txn.transmit(&self.to_bytes(), recv_len)?);
        trace!("<<< {:?}", &response);
        Ok(response)
    }

    /// Serialize this APDU as a self-zeroizing byte buffer
    pub fn to_bytes(&self) -> Buffer {
        let mut bytes = Vec::with_capacity(5 + self.data.len());
        bytes.push(self.cla);
        bytes.push(self.ins.code());
        bytes.push(self.p1);
        bytes.push(self.p2);
        bytes.push(self.data.len() as u8);
        bytes.extend_from_slice(self.data.as_ref());
        Zeroizing::new(bytes)
    }
}

impl Drop for Apdu {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for Apdu {
    fn zeroize(&mut self) {
        // Only `data` may contain secrets
        self.data.zeroize();
    }
}

/// APDU instruction codes
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Ins {
    /// Verify
    Verify,

    /// Change reference
    ChangeReference,

    /// Reset retry
    ResetRetry,

    /// Generate asymmetric
    GenerateAsymmetric,

    /// Authenticate
    Authenticate,

    /// Get data
    GetData,

    /// Put data
    PutData,

    /// Select application
    SelectApplication,

    /// Get response APDU
    GetResponseApdu,

    // Yubico vendor specific instructions
    // <https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html>
    /// Set MGM key
    SetMgmKey,

    /// Import key
    ImportKey,

    /// Get version
    GetVersion,

    /// Reset device
    Reset,

    /// Set PIN retries
    SetPinRetries,

    /// Generate attestation certificate for asymmetric key
    Attest,

    /// Get device serial
    GetSerial,

    /// Get slot metadata
    GetMetadata,

    /// Other/unrecognized instruction codes
    Other(u8),
}

impl Ins {
    /// Get the code that corresponds to this instruction
    pub fn code(self) -> u8 {
        match self {
            Ins::Verify => 0x20,
            Ins::ChangeReference => 0x24,
            Ins::ResetRetry => 0x2c,
            Ins::GenerateAsymmetric => 0x47,
            Ins::Authenticate => 0x87,
            Ins::GetData => 0xcb,
            Ins::PutData => 0xdb,
            Ins::SelectApplication => 0xa4,
            Ins::GetResponseApdu => 0xc0,
            Ins::SetMgmKey => 0xff,
            Ins::ImportKey => 0xfe,
            Ins::GetVersion => 0xfd,
            Ins::Reset => 0xfb,
            Ins::SetPinRetries => 0xfa,
            Ins::Attest => 0xf9,
            Ins::GetSerial => 0xf8,
            Ins::GetMetadata => 0xf7,
            Ins::Other(code) => code,
        }
    }
}

impl From<u8> for Ins {
    fn from(code: u8) -> Self {
        match code {
            0x20 => Ins::Verify,
            0x24 => Ins::ChangeReference,
            0x2c => Ins::ResetRetry,
            0x47 => Ins::GenerateAsymmetric,
            0x87 => Ins::Authenticate,
            0xcb => Ins::GetData,
            0xdb => Ins::PutData,
            0xa4 => Ins::SelectApplication,
            0xc0 => Ins::GetResponseApdu,
            0xff => Ins::SetMgmKey,
            0xfe => Ins::ImportKey,
            0xfd => Ins::GetVersion,
            0xfb => Ins::Reset,
            0xfa => Ins::SetPinRetries,
            0xf9 => Ins::Attest,
            0xf8 => Ins::GetSerial,
            0xf7 => Ins::GetMetadata,
            code => Ins::Other(code),
        }
    }
}

impl From<Ins> for u8 {
    fn from(ins: Ins) -> u8 {
        ins.code()
    }
}

/// APDU responses
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Response {
    /// Status words
    status_words: StatusWords,

    /// Buffer
    data: Vec<u8>,
}

impl Response {
    /// Create a new response from the given status words and buffer
    pub fn new(status_words: StatusWords, data: Vec<u8>) -> Response {
        Response { status_words, data }
    }

    /// Get the [`StatusWords`] for this response.
    pub fn status_words(&self) -> StatusWords {
        self.status_words
    }

    /// Get the raw [`StatusWords`] code for this response.
    pub fn code(&self) -> u16 {
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
            (bytes[bytes.len() - 2] as u16) << 8 | (bytes[bytes.len() - 1] as u16),
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
        // Only `data` may contain secrets
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

    /// https://github.com/Yubico/yubikey-manager/blob/1f22620b623c6b345dd9f9193ec765a542dddc80/ykman/driver_ccid.py#L53
    NoInputDataError,

    /// PIN verification failure
    VerifyFailError {
        /// Remaining verification attempts
        tries: u8,
    },

    /// https://github.com/Yubico/yubikey-manager/blob/1f22620b623c6b345dd9f9193ec765a542dddc80/ykman/driver_ccid.py#L55
    WrongLengthError,

    /// Security status not satisfied
    SecurityStatusError,

    /// Authentication method blocked
    AuthBlockedError,

    /// https://github.com/Yubico/yubikey-manager/blob/1f22620b623c6b345dd9f9193ec765a542dddc80/ykman/driver_ccid.py#L58
    DataInvalidError,

    /// https://github.com/Yubico/yubikey-manager/blob/1f22620b623c6b345dd9f9193ec765a542dddc80/ykman/driver_ccid.py#L59
    ConditionsNotSatisfiedError,

    /// https://github.com/Yubico/yubikey-manager/blob/1f22620b623c6b345dd9f9193ec765a542dddc80/ykman/driver_ccid.py#L60
    CommandNotAllowedError,

    /// Incorrect parameter in command data field
    IncorrectParamError,

    /// Data object or application not found
    NotFoundError,

    /// Not enough memory
    NoSpaceError,

    //
    // Custom Yubico Status Word extensions
    //
    /// Incorrect card slot error
    IncorrectSlotError,

    /// Not supported error
    NotSupportedError,

    /// https://github.com/Yubico/yubikey-manager/blob/1f22620b623c6b345dd9f9193ec765a542dddc80/ykman/driver_ccid.py#L65
    CommandAbortedError,

    /// Other/unrecognized status words
    Other(u16),
}

impl StatusWords {
    /// Get the numerical response code for these status words
    pub fn code(self) -> u16 {
        match self {
            StatusWords::None => 0,
            StatusWords::NoInputDataError => 0x6285,
            StatusWords::VerifyFailError { tries } => 0x63c0 & tries as u16,
            StatusWords::WrongLengthError => 0x6700,
            StatusWords::SecurityStatusError => 0x6982,
            StatusWords::AuthBlockedError => 0x6983,
            StatusWords::DataInvalidError => 0x6984,
            StatusWords::ConditionsNotSatisfiedError => 0x6985,
            StatusWords::CommandNotAllowedError => 0x6986,
            StatusWords::IncorrectParamError => 0x6a80,
            StatusWords::NotFoundError => 0x6a82,
            StatusWords::NoSpaceError => 0x6a84,
            StatusWords::IncorrectSlotError => 0x6b00,
            StatusWords::NotSupportedError => 0x6d00,
            StatusWords::CommandAbortedError => 0x6f00,
            StatusWords::Success => 0x9000,
            StatusWords::Other(n) => n,
        }
    }

    /// Do these status words indicate success?
    pub fn is_success(self) -> bool {
        self == StatusWords::Success
    }
}

impl From<u16> for StatusWords {
    fn from(sw: u16) -> Self {
        match sw {
            0x0000 => StatusWords::None,
            0x6285 => StatusWords::NoInputDataError,
            sw if sw & 0xfff0 == 0x63c0 => StatusWords::VerifyFailError {
                tries: (sw & 0x000f) as u8,
            },
            0x6700 => StatusWords::WrongLengthError,
            0x6982 => StatusWords::SecurityStatusError,
            0x6983 => StatusWords::AuthBlockedError,
            0x6984 => StatusWords::DataInvalidError,
            0x6985 => StatusWords::ConditionsNotSatisfiedError,
            0x6986 => StatusWords::CommandNotAllowedError,
            0x6a80 => StatusWords::IncorrectParamError,
            0x6a82 => StatusWords::NotFoundError,
            0x6a84 => StatusWords::NoSpaceError,
            0x6b00 => StatusWords::IncorrectSlotError,
            0x6d00 => StatusWords::NotSupportedError,
            0x6f00 => StatusWords::CommandAbortedError,
            0x9000 => StatusWords::Success,
            _ => StatusWords::Other(sw),
        }
    }
}

impl From<StatusWords> for u16 {
    fn from(sw: StatusWords) -> u16 {
        sw.code()
    }
}
