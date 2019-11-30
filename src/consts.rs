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

pub const szLOG_SOURCE: &str = "yubikey-piv.rs";

pub const ADMIN_FLAGS_1_PUK_BLOCKED: u8 = 0x01;
pub const ADMIN_FLAGS_1_PROTECTED_MGM: u8 = 0x02;

pub const CB_ADMIN_TIMESTAMP: usize = 0x04;
pub const CB_ADMIN_SALT: usize = 16;

pub const CB_ATR_MAX: usize = 33;

pub const CB_BUF_MAX_NEO: usize = 2048;
pub const CB_BUF_MAX_YK4: usize = 3072;
pub const CB_BUF_MAX: usize = CB_BUF_MAX_YK4;

pub const CB_ECC_POINTP256: usize = 65;
pub const CB_ECC_POINTP384: usize = 97;

pub const CB_OBJ_MAX_YK4: usize = CB_BUF_MAX_YK4 - 9;
pub const CB_OBJ_MAX: usize = CB_OBJ_MAX_YK4;
pub const CB_OBJ_MAX_NEO: usize = CB_BUF_MAX_NEO - 9;

pub const CB_OBJ_TAG_MIN: usize = 2; // 1 byte tag + 1 byte len
pub const CB_OBJ_TAG_MAX: usize = (CB_OBJ_TAG_MIN + 2); // 1 byte tag + 3 bytes len

pub const CB_PAGE: usize = 4096;
pub const CB_PIN_MAX: usize = 8;

pub const CCC_ID_OFFS: usize = 9;

pub const CHUID_FASCN_OFFS: usize = 2;
pub const CHUID_GUID_OFFS: usize = 29;
pub const CHUID_EXPIRATION_OFFS: usize = 47;

pub const CHREF_ACT_CHANGE_PIN: i32 = 0;
pub const CHREF_ACT_UNBLOCK_PIN: i32 = 1;
pub const CHREF_ACT_CHANGE_PUK: i32 = 2;

pub const CONTAINER_NAME_LEN: usize = 40;
pub const CONTAINER_REC_LEN: usize = (2 * CONTAINER_NAME_LEN) + 27; // 80 + 1 + 1 + 2 + 1 + 1 + 1 + 20

pub const DES_TYPE_3DES: u8 = 1;

pub const DES_LEN_DES: usize = 8;
pub const DES_LEN_3DES: usize = DES_LEN_DES * 3;

// device types

pub const DEVTYPE_UNKNOWN: u32 = 0x0000_0000;
pub const DEVTYPE_NEO: u32 = 0x4E45_0000; //"NE"
pub const DEVTYPE_YK: u32 = 0x594B_0000; //"YK"
pub const DEVTYPE_NEOr3: u32 = (DEVTYPE_NEO | 0x0000_7233); //"r3"
pub const DEVTYPE_YK4: u32 = (DEVTYPE_YK | 0x0000_0034); // "4"
pub const DEVYTPE_YK5: u32 = (DEVTYPE_YK | 0x0000_0035); // "5"

pub const ITER_MGM_PBKDF2: usize = 10000;

pub const PROTECTED_FLAGS_1_PUK_NOBLOCK: u8 = 0x01;

// sw is status words, see NIST special publication 800-73-4, section 5.6

pub const SW_SUCCESS: i32 = 0x9000;
pub const SW_ERR_SECURITY_STATUS: i32 = 0x6982;
pub const SW_ERR_AUTH_BLOCKED: i32 = 0x6983;
pub const SW_ERR_INCORRECT_PARAM: i32 = 0x6a80;

// this is a custom sw for yubikey

pub const SW_ERR_INCORRECT_SLOT: i32 = 0x6b00;
pub const SW_ERR_NOT_SUPPORTED: i32 = 0x6d00;

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

pub const YKPIV_ALGO_TAG: u8 = 0x80;
pub const YKPIV_ALGO_3DES: u8 = 0x03;

pub const YKPIV_ATR_NEO_R3: &[u8] = b";\xFC\x13\0\0\x811\xFE\x15YubikeyNEOr3\xE1\0";

pub const YKPIV_CHUID_SIZE: usize = 59;
pub const YKPIV_CARDID_SIZE: usize = 16;
pub const YKPIV_FASCN_SIZE: usize = 25;
pub const YKPIV_EXPIRATION_SIZE: usize = 8;

pub const YKPIV_CCCID_SIZE: usize = 14;

pub const YKPIV_CERTINFO_UNCOMPRESSED: u8 = 0;
pub const YKPIV_CERTINFO_GZIP: u8 = 1;

pub const YKPIV_KEY_CARDMGM: u8 = 0x9b;

pub const YKPIV_OBJ_CAPABILITY: u32 = 0x005f_c107;
pub const YKPIV_OBJ_CHUID: u32 = 0x005f_c102;
pub const YKPIV_OBJ_FINGERPRINTS: u32 = 0x005f_c103;
pub const YKPIV_OBJ_SECURITY: u32 = 0x005f_c106;
pub const YKPIV_OBJ_FACIAL: u32 = 0x005f_c108;
pub const YKPIV_OBJ_PRINTED: u32 = 0x005f_c109;
pub const YKPIV_OBJ_DISCOVERY: u32 = 0x7e;
pub const YKPIV_OBJ_KEY_HISTORY: u32 = 0x005f_c10c;
pub const YKPIV_OBJ_IRIS: u32 = 0x005f_c121;

// Internal object IDs

pub const YKPIV_OBJ_ADMIN_DATA: u32 = 0x005f_ff00;
pub const YKPIV_OBJ_MSCMAP: u32 = 0x005f_ff10;
pub const YKPIV_OBJ_MSROOTS1: u32 = 0x005f_ff11;
pub const YKPIV_OBJ_MSROOTS2: u32 = 0x005f_ff12;
pub const YKPIV_OBJ_MSROOTS3: u32 = 0x005f_ff13;
pub const YKPIV_OBJ_MSROOTS4: u32 = 0x005f_ff14;
pub const YKPIV_OBJ_MSROOTS5: u32 = 0x005f_ff15;

pub const YKPIV_PINPOLICY_TAG: u8 = 0xaa;
pub const YKPIV_PINPOLICY_DEFAULT: u8 = 0;
pub const YKPIV_PINPOLICY_NEVER: u8 = 1;
pub const YKPIV_PINPOLICY_ONCE: u8 = 2;
pub const YKPIV_PINPOLICY_ALWAYS: u8 = 3;

pub const YKPIV_TOUCHPOLICY_TAG: u8 = 0xab;
pub const YKPIV_TOUCHPOLICY_DEFAULT: u8 = 0;
pub const YKPIV_TOUCHPOLICY_NEVER: u8 = 1;
pub const YKPIV_TOUCHPOLICY_ALWAYS: u8 = 2;
pub const YKPIV_TOUCHPOLICY_CACHED: u8 = 3;
