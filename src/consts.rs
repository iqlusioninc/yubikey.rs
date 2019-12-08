//! Constant values
// TODO(tarcieri): refactor these into enums!

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

// TODO(tarcieri): document these!
#![allow(missing_docs, non_upper_case_globals)]
#![cfg_attr(not(feature = "untested"), allow(dead_code))]

pub const ADMIN_FLAGS_1_PUK_BLOCKED: u8 = 0x01;
pub const ADMIN_FLAGS_1_PROTECTED_MGM: u8 = 0x02;

pub const CB_BUF_MAX: usize = 3072;

pub const CB_OBJ_MAX: usize = CB_BUF_MAX - 9;
pub const CB_OBJ_TAG_MIN: usize = 2; // 1 byte tag + 1 byte len
pub const CB_OBJ_TAG_MAX: usize = (CB_OBJ_TAG_MIN + 2); // 1 byte tag + 3 bytes len

pub const TAG_CERT: u8 = 0x70;
pub const TAG_CERT_COMPRESS: u8 = 0x71;
pub const TAG_CERT_LRC: u8 = 0xFE;
pub const TAG_ADMIN: u8 = 0x80;
pub const TAG_ADMIN_FLAGS_1: u8 = 0x81;
pub const TAG_ADMIN_SALT: u8 = 0x82;
pub const TAG_ADMIN_TIMESTAMP: u8 = 0x83;
pub const TAG_PROTECTED: u8 = 0x88;
pub const TAG_PROTECTED_FLAGS_1: u8 = 0x81;
pub const TAG_PROTECTED_MGM: u8 = 0x89;
pub const TAG_MSCMAP: u8 = 0x81;
pub const TAG_MSROOTS_END: u8 = 0x82;
pub const TAG_MSROOTS_MID: u8 = 0x83;

pub const TAG_RSA_MODULUS: u8 = 0x81;
pub const TAG_RSA_EXP: u8 = 0x82;
pub const TAG_ECC_POINT: u8 = 0x86;
