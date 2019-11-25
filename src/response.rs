//! Responses to issued commands

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

use crate::Buffer;

/// Parsed response to a command
pub(crate) struct Response {
    /// Status words
    status_words: StatusWords,

    /// Buffer
    buffer: Buffer,
}

impl Response {
    /// Parse a response from the given buffer
    pub fn from_bytes(mut buffer: Buffer) -> Self {
        if buffer.len() >= 2 {
            let sw = StatusWords::from(
                (buffer[buffer.len() - 2] as u32) << 8 | (buffer[buffer.len() - 1] as u32),
            );

            let len = buffer.len() - 2;
            buffer.truncate(len);
            Response {
                status_words: sw,
                buffer,
            }
        } else {
            Response {
                status_words: StatusWords::None,
                buffer,
            }
        }
    }

    /// Create a new response from the given status words and buffer
    #[cfg(feature = "untested")]
    pub fn new(status_words: StatusWords, buffer: Buffer) -> Response {
        Response {
            status_words,
            buffer,
        }
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

    /// Borrow the response buffer
    pub fn buffer(&self) -> &[u8] {
        self.buffer.as_ref()
    }

    /// Consume this response, returning its buffer
    #[cfg(feature = "untested")]
    pub fn into_buffer(self) -> Buffer {
        self.buffer
    }
}

impl AsRef<[u8]> for Response {
    fn as_ref(&self) -> &[u8] {
        self.buffer()
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
