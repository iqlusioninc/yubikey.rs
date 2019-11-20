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

use std::fmt;

/// Kinds of errors
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// Memory error
    MemoryError,

    /// PCSC error
    PcscError,

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
    WrongPin { tries: i32 },

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
}

impl ErrorKind {
    /// Name of the error.
    ///
    /// These names map to the legacy names from the Yubico C library, to
    /// assist in web searches for relevant information for these errors.
    pub fn name(self) -> &'static str {
        match self {
            ErrorKind::MemoryError => "YKPIV_MEMORY_ERROR",
            ErrorKind::PcscError => "YKPIV_PCSC_ERROR",
            ErrorKind::SizeError => "YKPIV_SIZE_ERROR",
            ErrorKind::AppletError => "YKPIV_APPLET_ERROR",
            ErrorKind::AuthenticationError => "YKPIV_AUTHENTICATION_ERROR",
            ErrorKind::RandomnessError => "YKPIV_RANDOMNESS_ERROR",
            ErrorKind::GenericError => "YKPIV_GENERIC_ERROR",
            ErrorKind::KeyError => "YKPIV_KEY_ERROR",
            ErrorKind::ParseError => "YKPIV_PARSE_ERROR",
            ErrorKind::WrongPin { .. } => "YKPIV_WRONG_PIN",
            ErrorKind::InvalidObject => "YKPIV_INVALID_OBJECT",
            ErrorKind::AlgorithmError => "YKPIV_ALGORITHM_ERROR",
            ErrorKind::PinLocked => "YKPIV_PIN_LOCKED",
            ErrorKind::ArgumentError => "YKPIV_ARGUMENT_ERROR",
            ErrorKind::RangeError => "YKPIV_RANGE_ERROR",
            ErrorKind::NotSupported => "YKPIV_NOT_SUPPORTED",
        }
    }

    /// Error message
    pub fn msg(self) -> &'static str {
        match self {
            ErrorKind::MemoryError => "memory error",
            ErrorKind::PcscError => "PCSC error",
            ErrorKind::SizeError => "size error",
            ErrorKind::AppletError => "applet error",
            ErrorKind::AuthenticationError => "authentication error",
            ErrorKind::RandomnessError => "randomness error",
            ErrorKind::GenericError => "generic error",
            ErrorKind::KeyError => "key error",
            ErrorKind::ParseError => "parse error",
            ErrorKind::WrongPin { .. } => "wrong pin",
            ErrorKind::InvalidObject => "invalid object",
            ErrorKind::AlgorithmError => "algorithm error",
            ErrorKind::PinLocked => "PIN locked",
            ErrorKind::ArgumentError => "argument error",
            ErrorKind::RangeError => "range error",
            ErrorKind::NotSupported => "not supported",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.msg())
    }
}

impl std::error::Error for ErrorKind {}

/// Get a string representation of this error
// TODO(tarcieri): completely replace this with `Display`
pub fn ykpiv_strerror(err: ErrorKind) -> &'static str {
    err.msg()
}

/// Get the name of this error
// TODO(tarcieri): completely replace this with debug
pub fn ykpiv_strerror_name(err: ErrorKind) -> &'static str {
    err.name()
}
