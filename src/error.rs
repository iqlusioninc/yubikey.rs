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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
#[allow(non_camel_case_types)]
pub enum ErrorKind {
    YKPIV_OK = 0,
    YKPIV_MEMORY_ERROR = -1,
    YKPIV_PCSC_ERROR = -2,
    YKPIV_SIZE_ERROR = -3,
    YKPIV_APPLET_ERROR = -4,
    YKPIV_AUTHENTICATION_ERROR = -5,
    YKPIV_RANDOMNESS_ERROR = -6,
    YKPIV_GENERIC_ERROR = -7,
    YKPIV_KEY_ERROR = -8,
    YKPIV_PARSE_ERROR = -9,
    YKPIV_WRONG_PIN = -10,
    YKPIV_INVALID_OBJECT = -11,
    YKPIV_ALGORITHM_ERROR = -12,
    YKPIV_PIN_LOCKED = -13,
    YKPIV_ARGUMENT_ERROR = -14,
    YKPIV_RANGE_ERROR = -15,
    YKPIV_NOT_SUPPORTED = -16,
}

impl ErrorKind {
    /// Name of the error
    pub fn name(self) -> &'static str {
        match self {
            ErrorKind::YKPIV_OK => "YKPIV_OK",
            ErrorKind::YKPIV_MEMORY_ERROR => "YKPIV_MEMORY_ERROR",
            ErrorKind::YKPIV_PCSC_ERROR => "YKPIV_PCSC_ERROR",
            ErrorKind::YKPIV_SIZE_ERROR => "YKPIV_SIZE_ERROR",
            ErrorKind::YKPIV_APPLET_ERROR => "YKPIV_APPLET_ERROR",
            ErrorKind::YKPIV_AUTHENTICATION_ERROR => "YKPIV_AUTHENTICATION_ERROR",
            ErrorKind::YKPIV_RANDOMNESS_ERROR => "YKPIV_RANDOMNESS_ERROR",
            ErrorKind::YKPIV_GENERIC_ERROR => "YKPIV_GENERIC_ERROR",
            ErrorKind::YKPIV_KEY_ERROR => "YKPIV_KEY_ERROR",
            ErrorKind::YKPIV_PARSE_ERROR => "YKPIV_PARSE_ERROR",
            ErrorKind::YKPIV_WRONG_PIN => "YKPIV_WRONG_PIN",
            ErrorKind::YKPIV_INVALID_OBJECT => "YKPIV_INVALID_OBJECT",
            ErrorKind::YKPIV_ALGORITHM_ERROR => "YKPIV_ALGORITHM_ERROR",
            ErrorKind::YKPIV_PIN_LOCKED => "YKPIV_PIN_LOCKED",
            ErrorKind::YKPIV_ARGUMENT_ERROR => "YKPIV_ARGUMENT_ERROR",
            ErrorKind::YKPIV_RANGE_ERROR => "YKPIV_RANGE_ERROR",
            ErrorKind::YKPIV_NOT_SUPPORTED => "YKPIV_NOT_SUPPORTED",
        }
    }

    /// Error message
    pub fn msg(self) -> &'static str {
        match self {
            ErrorKind::YKPIV_OK => "OK",
            ErrorKind::YKPIV_MEMORY_ERROR => "memory error",
            ErrorKind::YKPIV_PCSC_ERROR => "PCSC error",
            ErrorKind::YKPIV_SIZE_ERROR => "size error",
            ErrorKind::YKPIV_APPLET_ERROR => "applet error",
            ErrorKind::YKPIV_AUTHENTICATION_ERROR => "authentication error",
            ErrorKind::YKPIV_RANDOMNESS_ERROR => "randomness error",
            ErrorKind::YKPIV_GENERIC_ERROR => "generic error",
            ErrorKind::YKPIV_KEY_ERROR => "key error",
            ErrorKind::YKPIV_PARSE_ERROR => "parse error",
            ErrorKind::YKPIV_WRONG_PIN => "wrong pin",
            ErrorKind::YKPIV_INVALID_OBJECT => "invalid object",
            ErrorKind::YKPIV_ALGORITHM_ERROR => "algorithm error",
            ErrorKind::YKPIV_PIN_LOCKED => "PIN locked",
            ErrorKind::YKPIV_ARGUMENT_ERROR => "argument error",
            ErrorKind::YKPIV_RANGE_ERROR => "range error",
            ErrorKind::YKPIV_NOT_SUPPORTED => "not supported",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.msg())
    }
}

impl std::error::Error for ErrorKind {}

#[derive(Copy)]
#[repr(C)]
pub struct Error {
    pub rc: ErrorKind,
    pub name: *const u8,
    pub description: *const u8,
}

impl Clone for Error {
    fn clone(&self) -> Self {
        *self
    }
}

pub fn ykpiv_strerror(err: ErrorKind) -> &'static str {
    err.msg()
}

pub fn ykpiv_strerror_name(err: ErrorKind) -> &'static str {
    err.name()
}
