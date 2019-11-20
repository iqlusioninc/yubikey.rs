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

pub const CB_OBJ_MAX: usize = 3063;

pub const CB_OBJ_TAG_MIN: usize = 2; // 1 byte tag + 1 byte len
pub const CB_OBJ_TAG_MAX: usize = (CB_OBJ_TAG_MIN + 2); // 1 byte tag + 3 bytes len

pub const CB_PIN_MAX: usize = 8;
pub const CB_ECC_POINTP256: usize = 65;
pub const CB_ECC_POINTP384: usize = 97;

pub const CHUID_GUID_OFFS: usize = 29;

pub const CHREF_ACT_CHANGE_PIN: i32 = 0;
pub const CHREF_ACT_UNBLOCK_PIN: i32 = 1;
pub const CHREF_ACT_CHANGE_PUK: i32 = 2;

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
pub const YKPIV_ALGO_RSA1024: u8 = 0x06;
pub const YKPIV_ALGO_RSA2048: u8 = 0x07;
pub const YKPIV_ALGO_ECCP256: u8 = 0x11;
pub const YKPIV_ALGO_ECCP384: u8 = 0x14;

pub const YKPIV_ATR_NEO_R3: &[u8] = b";\xFC\x13\0\0\x811\xFE\x15YubikeyNEOr3\xE1\0";

pub const YKPIV_CARDID_SIZE: usize = 16;

pub const YKPIV_CCCID_SIZE: usize = 14;

pub const YKPIV_CERTINFO_UNCOMPRESSED: u8 = 0;
pub const YKPIV_CERTINFO_GZIP: u8 = 1;

pub const YKPIV_INS_VERIFY: u8 = 0x20;
pub const YKPIV_INS_CHANGE_REFERENCE: u8 = 0x24;
pub const YKPIV_INS_RESET_RETRY: u8 = 0x2c;
pub const YKPIV_INS_GENERATE_ASYMMETRIC: u8 = 0x47;
pub const YKPIV_INS_AUTHENTICATE: u8 = 0x87;
pub const YKPIV_INS_GET_DATA: u8 = 0xcb;
pub const YKPIV_INS_PUT_DATA: u8 = 0xdb;
pub const YKPIV_INS_SELECT_APPLICATION: u8 = 0xa4;
pub const YKPIV_INS_GET_RESPONSE_APDU: u8 = 0xc0;

// Yubico vendor specific instructions
pub const YKPIV_INS_SET_MGMKEY: u8 = 0xff;
pub const YKPIV_INS_IMPORT_KEY: u8 = 0xfe;
pub const YKPIV_INS_GET_VERSION: u8 = 0xfd;
pub const YKPIV_INS_RESET: u8 = 0xfb;
pub const YKPIV_INS_SET_PIN_RETRIES: u8 = 0xfa;
pub const YKPIV_INS_ATTEST: u8 = 0xf9;
pub const YKPIV_INS_GET_SERIAL: u8 = 0xf8;

pub const YKPIV_KEY_AUTHENTICATION: u8 = 0x9a;
pub const YKPIV_KEY_CARDMGM: u8 = 0x9b;
pub const YKPIV_KEY_SIGNATURE: u8 = 0x9c;
pub const YKPIV_KEY_KEYMGM: u8 = 0x9d;
pub const YKPIV_KEY_CARDAUTH: u8 = 0x9e;
pub const YKPIV_KEY_RETIRED1: u8 = 0x82;
pub const YKPIV_KEY_RETIRED2: u8 = 0x83;
pub const YKPIV_KEY_RETIRED3: u8 = 0x84;
pub const YKPIV_KEY_RETIRED4: u8 = 0x85;
pub const YKPIV_KEY_RETIRED5: u8 = 0x86;
pub const YKPIV_KEY_RETIRED6: u8 = 0x87;
pub const YKPIV_KEY_RETIRED7: u8 = 0x88;
pub const YKPIV_KEY_RETIRED8: u8 = 0x89;
pub const YKPIV_KEY_RETIRED9: u8 = 0x8a;
pub const YKPIV_KEY_RETIRED10: u8 = 0x8b;
pub const YKPIV_KEY_RETIRED11: u8 = 0x8c;
pub const YKPIV_KEY_RETIRED12: u8 = 0x8d;
pub const YKPIV_KEY_RETIRED13: u8 = 0x8e;
pub const YKPIV_KEY_RETIRED14: u8 = 0x8f;
pub const YKPIV_KEY_RETIRED15: u8 = 0x90;
pub const YKPIV_KEY_RETIRED16: u8 = 0x91;
pub const YKPIV_KEY_RETIRED17: u8 = 0x92;
pub const YKPIV_KEY_RETIRED18: u8 = 0x93;
pub const YKPIV_KEY_RETIRED19: u8 = 0x94;
pub const YKPIV_KEY_RETIRED20: u8 = 0x95;
pub const YKPIV_KEY_ATTESTATION: u8 = 0xf9;

pub const YKPIV_OBJ_CAPABILITY: u32 = 0x005f_c107;
pub const YKPIV_OBJ_CHUID: u32 = 0x005f_c102;
pub const YKPIV_OBJ_AUTHENTICATION: u32 = 0x005f_c105; // cert for 9a key
pub const YKPIV_OBJ_FINGERPRINTS: u32 = 0x005f_c103;
pub const YKPIV_OBJ_SECURITY: u32 = 0x005f_c106;
pub const YKPIV_OBJ_FACIAL: u32 = 0x005f_c108;
pub const YKPIV_OBJ_PRINTED: u32 = 0x005f_c109;
pub const YKPIV_OBJ_SIGNATURE: u32 = 0x005f_c10a; // cert for 9c key
pub const YKPIV_OBJ_KEY_MANAGEMENT: u32 = 0x005f_c10b; // cert for 9d key
pub const YKPIV_OBJ_CARD_AUTH: u32 = 0x005f_c101; // cert for 9e key
pub const YKPIV_OBJ_DISCOVERY: u32 = 0x7e;
pub const YKPIV_OBJ_KEY_HISTORY: u32 = 0x005f_c10c;
pub const YKPIV_OBJ_IRIS: u32 = 0x005f_c121;

pub const YKPIV_OBJ_RETIRED1: u32 = 0x005f_c10d;
pub const YKPIV_OBJ_RETIRED2: u32 = 0x005f_c10e;
pub const YKPIV_OBJ_RETIRED3: u32 = 0x005f_c10f;
pub const YKPIV_OBJ_RETIRED4: u32 = 0x005f_c110;
pub const YKPIV_OBJ_RETIRED5: u32 = 0x005f_c111;
pub const YKPIV_OBJ_RETIRED6: u32 = 0x005f_c112;
pub const YKPIV_OBJ_RETIRED7: u32 = 0x005f_c113;
pub const YKPIV_OBJ_RETIRED8: u32 = 0x005f_c114;
pub const YKPIV_OBJ_RETIRED9: u32 = 0x005f_c115;
pub const YKPIV_OBJ_RETIRED10: u32 = 0x005f_c116;
pub const YKPIV_OBJ_RETIRED11: u32 = 0x005f_c117;
pub const YKPIV_OBJ_RETIRED12: u32 = 0x005f_c118;
pub const YKPIV_OBJ_RETIRED13: u32 = 0x005f_c119;
pub const YKPIV_OBJ_RETIRED14: u32 = 0x005f_c11a;
pub const YKPIV_OBJ_RETIRED15: u32 = 0x005f_c11b;
pub const YKPIV_OBJ_RETIRED16: u32 = 0x005f_c11c;
pub const YKPIV_OBJ_RETIRED17: u32 = 0x005f_c11d;
pub const YKPIV_OBJ_RETIRED18: u32 = 0x005f_c11e;
pub const YKPIV_OBJ_RETIRED19: u32 = 0x005f_c11f;
pub const YKPIV_OBJ_RETIRED20: u32 = 0x005f_c120;

// Internal object IDs

pub const YKPIV_OBJ_ADMIN_DATA: u32 = 0x005f_ff00;
pub const YKPIV_OBJ_ATTESTATION: u32 = 0x005f_ff01;
pub const YKPIV_OBJ_MSCMAP: u32 = 0x005f_ff10;
pub const YKPIV_OBJ_MSROOTS1: u32 = 0x005f_ff11;
pub const YKPIV_OBJ_MSROOTS2: u32 = 0x005f_ff12;
pub const YKPIV_OBJ_MSROOTS3: u32 = 0x005f_ff13;
pub const YKPIV_OBJ_MSROOTS4: u32 = 0x005f_ff14;
pub const YKPIV_OBJ_MSROOTS5: u32 = 0x005f_ff15;

pub const YKPIV_OBJ_MAX_SIZE: usize = 3072;

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
