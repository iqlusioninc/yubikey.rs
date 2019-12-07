//! Error types

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

use std::fmt::{self, Display};

/// Kinds of errors
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Memory error
    MemoryError,

    /// PCSC error
    PcscError {
        /// Original PC/SC error
        inner: Option<pcsc::Error>,
    },

    /// Size error
    SizeError,

    /// Applet error
    AppletError,

    /// Authentication error
    AuthenticationError,

    /// Randomness error
    RandomnessError,

    /// Generic error
    GenericError,

    /// Key error
    KeyError,

    /// Parse error
    ParseError,

    /// Wrong PIN
    WrongPin {
        /// Number of tries remaining
        tries: u8,
    },

    /// Invalid object
    InvalidObject,

    /// Algorithm error
    AlgorithmError,

    /// PIN locked
    PinLocked,

    /// Argument error
    ArgumentError,

    /// Range error
    RangeError,

    /// Not supported
    NotSupported,

    /// Not found
    NotFound,
}

impl Error {
    /// Name of the error.
    ///
    /// These names map to the legacy names from the Yubico C library, to
    /// assist in web searches for relevant information for these errors.
    pub fn name(self) -> &'static str {
        match self {
            Error::MemoryError => "YKPIV_MEMORY_ERROR",
            Error::PcscError { .. } => "YKPIV_PCSC_ERROR",
            Error::SizeError => "YKPIV_SIZE_ERROR",
            Error::AppletError => "YKPIV_APPLET_ERROR",
            Error::AuthenticationError => "YKPIV_AUTHENTICATION_ERROR",
            Error::RandomnessError => "YKPIV_RANDOMNESS_ERROR",
            Error::GenericError => "YKPIV_GENERIC_ERROR",
            Error::KeyError => "YKPIV_KEY_ERROR",
            Error::ParseError => "YKPIV_PARSE_ERROR",
            Error::WrongPin { .. } => "YKPIV_WRONG_PIN",
            Error::InvalidObject => "YKPIV_INVALID_OBJECT",
            Error::AlgorithmError => "YKPIV_ALGORITHM_ERROR",
            Error::PinLocked => "YKPIV_PIN_LOCKED",
            Error::ArgumentError => "YKPIV_ARGUMENT_ERROR",
            Error::RangeError => "YKPIV_RANGE_ERROR",
            Error::NotSupported => "YKPIV_NOT_SUPPORTED",
            Error::NotFound => "<not found>",
        }
    }

    /// Error message
    pub fn msg(self) -> &'static str {
        match self {
            Error::MemoryError => "memory error",
            Error::PcscError { .. } => "PCSC error",
            Error::SizeError => "size error",
            Error::AppletError => "applet error",
            Error::AuthenticationError => "authentication error",
            Error::RandomnessError => "randomness error",
            Error::GenericError => "generic error",
            Error::KeyError => "key error",
            Error::ParseError => "parse error",
            Error::WrongPin { .. } => "wrong pin",
            Error::InvalidObject => "invalid object",
            Error::AlgorithmError => "algorithm error",
            Error::PinLocked => "PIN locked",
            Error::ArgumentError => "argument error",
            Error::RangeError => "range error",
            Error::NotSupported => "not supported",
            Error::NotFound => "not found",
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.msg())
    }
}

impl From<pcsc::Error> for Error {
    fn from(err: pcsc::Error) -> Error {
        Error::PcscError { inner: Some(err) }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            #[allow(trivial_casts)] // why doesn't this work without the cast???
            Error::PcscError { inner } => inner
                .as_ref()
                .map(|err| err as &(dyn std::error::Error + 'static)),
            _ => None,
        }
    }
}
