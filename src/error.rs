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

/// Result type with [`Error`].
pub type Result<T> = core::result::Result<T, Error>;

/// Kinds of errors
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Algorithm error
    AlgorithmError,

    /// Applet error
    AppletError,

    /// Argument error
    ArgumentError,

    /// Authentication error
    AuthenticationError,

    /// Generic error
    GenericError,

    /// Invalid object
    InvalidObject,

    /// Key error
    KeyError,

    /// Memory error
    MemoryError,

    /// Not supported
    NotSupported,

    /// Not found
    NotFound,

    /// Parse error
    ParseError,

    /// PCSC error
    PcscError {
        /// Original PC/SC error
        inner: Option<pcsc::Error>,
    },

    /// PIN locked
    PinLocked,

    /// Randomness error
    RandomnessError,

    /// Range error
    RangeError,

    /// Size error
    SizeError,

    /// Wrong PIN
    WrongPin {
        /// Number of tries remaining
        tries: u8,
    },
}

impl Error {
    /// Name of the error.
    ///
    /// These names map to the legacy names from the Yubico C library, to
    /// assist in web searches for relevant information for these errors.
    pub fn name(self) -> Option<&'static str> {
        Some(match self {
            Error::AlgorithmError => "YKPIV_ALGORITHM_ERROR",
            Error::AppletError => "YKPIV_APPLET_ERROR",
            Error::ArgumentError => "YKPIV_ARGUMENT_ERROR",
            Error::AuthenticationError => "YKPIV_AUTHENTICATION_ERROR",
            Error::GenericError => "YKPIV_GENERIC_ERROR",
            Error::InvalidObject => "YKPIV_INVALID_OBJECT",
            Error::KeyError => "YKPIV_KEY_ERROR",
            Error::MemoryError => "YKPIV_MEMORY_ERROR",
            Error::NotSupported => "YKPIV_NOT_SUPPORTED",
            Error::ParseError => "YKPIV_PARSE_ERROR",
            Error::PcscError { .. } => "YKPIV_PCSC_ERROR",
            Error::PinLocked => "YKPIV_PIN_LOCKED",
            Error::RandomnessError => "YKPIV_RANDOMNESS_ERROR",
            Error::RangeError => "YKPIV_RANGE_ERROR",
            Error::SizeError => "YKPIV_SIZE_ERROR",
            Error::WrongPin { .. } => "YKPIV_WRONG_PIN",
            _ => return None,
        })
    }

    /// Error message
    pub fn msg(self) -> &'static str {
        match self {
            Error::AlgorithmError => "algorithm error",
            Error::AppletError => "applet error",
            Error::ArgumentError => "argument error",
            Error::AuthenticationError => "authentication error",
            Error::GenericError => "generic error",
            Error::InvalidObject => "invalid object",
            Error::KeyError => "key error",
            Error::MemoryError => "memory error",
            Error::NotSupported => "not supported",
            Error::NotFound => "not found",
            Error::ParseError => "parse error",
            Error::PcscError { .. } => "PC/SC error",
            Error::PinLocked => "PIN locked",
            Error::RandomnessError => "randomness error",
            Error::RangeError => "range error",
            Error::SizeError => "size error",
            Error::WrongPin { .. } => "wrong pin",
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
            #[allow(trivial_casts)]
            Error::PcscError { inner } => inner.as_ref().map(|err| err as &_),
            _ => None,
        }
    }
}
