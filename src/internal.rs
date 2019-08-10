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

extern {
    fn DES_ecb3_encrypt(
        input : *mut [u8; 8],
        output : *mut [u8; 8],
        ks1 : *mut DES_ks,
        ks2 : *mut DES_ks,
        ks3 : *mut DES_ks,
        enc : i32
    );
    fn DES_is_weak_key(key : *mut [u8; 8]) -> i32;
    fn DES_set_key_unchecked(
        key : *mut [u8; 8], schedule : *mut DES_ks
    );
    fn PKCS5_PBKDF2_HMAC_SHA1(
        pass : *const u8,
        passlen : i32,
        salt : *const u8,
        saltlen : i32,
        iter : i32,
        keylen : i32,
        out : *mut u8
    ) -> i32;
    fn RAND_bytes(buf : *mut u8, num : i32) -> i32;
    static mut _DefaultRuneLocale : Struct1;
    fn __maskrune(arg1 : i32, arg2 : usize) -> i32;
    fn __swbuf(arg1 : i32, arg2 : *mut __sFILE) -> i32;
    fn __tolower(arg1 : i32) -> i32;
    fn __toupper(arg1 : i32) -> i32;
    fn fclose(arg1 : *mut __sFILE) -> i32;
    fn feof(arg1 : *mut __sFILE) -> i32;
    fn fgets(
        arg1 : *mut u8, arg2 : i32, arg3 : *mut __sFILE
    ) -> *mut u8;
    fn fopen(
        __filename : *const u8, __mode : *const u8
    ) -> *mut __sFILE;
    fn free(arg1 : *mut ::std::os::raw::c_void);
    fn getenv(arg1 : *const u8) -> *mut u8;
    fn malloc(__size : usize) -> *mut ::std::os::raw::c_void;
    fn memcpy(
        __dst : *mut ::std::os::raw::c_void,
        __src : *const ::std::os::raw::c_void,
        __n : usize
    ) -> *mut ::std::os::raw::c_void;
    fn memset(
        __b : *mut ::std::os::raw::c_void, __c : i32, __len : usize
    ) -> *mut ::std::os::raw::c_void;
    fn snprintf(
        __str : *mut u8, __size : usize, __format : *const u8, ...
    ) -> i32;
    fn sscanf(arg1 : *const u8, arg2 : *const u8, ...) -> i32;
    fn strcasecmp(arg1 : *const u8, arg2 : *const u8) -> i32;
    fn strcmp(__s1 : *const u8, __s2 : *const u8) -> i32;
    fn strlen(__s : *const u8) -> usize;
}

enum Union6 {
}

enum __sFILEX {
}

#[no_mangle]
pub unsafe extern fn isascii(mut _c : i32) -> i32 {
    (_c & !0x7fi32 == 0i32) as (i32)
}

#[derive(Copy)]
#[repr(C)]
pub struct Struct3 {
    pub __min : i32,
    pub __max : i32,
    pub __map : i32,
    pub __types : *mut u32,
}

impl Clone for Struct3 {
    fn clone(&self) -> Self { *self }
}

#[derive(Copy)]
#[repr(C)]
pub struct Struct2 {
    pub __nranges : i32,
    pub __ranges : *mut Struct3,
}

impl Clone for Struct2 {
    fn clone(&self) -> Self { *self }
}

#[derive(Copy)]
#[repr(C)]
pub struct Struct4 {
    pub __name : [u8; 14],
    pub __mask : u32,
}

impl Clone for Struct4 {
    fn clone(&self) -> Self { *self }
}

#[derive(Copy)]
#[repr(C)]
pub struct Struct1 {
    pub __magic : [u8; 8],
    pub __encoding : [u8; 32],
    pub __sgetrune : unsafe extern fn(*const u8, usize, *mut *const u8) -> i32,
    pub __sputrune : unsafe extern fn(i32, *mut u8, usize, *mut *mut u8) -> i32,
    pub __invalid_rune : i32,
    pub __runetype : [u32; 256],
    pub __maplower : [i32; 256],
    pub __mapupper : [i32; 256],
    pub __runetype_ext : Struct2,
    pub __maplower_ext : Struct2,
    pub __mapupper_ext : Struct2,
    pub __variable : *mut ::std::os::raw::c_void,
    pub __variable_len : i32,
    pub __ncharclasses : i32,
    pub __charclasses : *mut Struct4,
}

impl Clone for Struct1 {
    fn clone(&self) -> Self { *self }
}

#[no_mangle]
pub unsafe extern fn __istype(mut _c : i32, mut _f : usize) -> i32 {
    if isascii(_c) != 0 {
        !(_DefaultRuneLocale.__runetype[
              _c as (usize)
          ] as (usize) & _f == 0) as (i32)
    } else {
        !(__maskrune(_c,_f) == 0) as (i32)
    }
}

#[no_mangle]
pub unsafe extern fn __isctype(mut _c : i32, mut _f : usize) -> i32 {
    if _c < 0i32 || _c >= 256i32 {
        0i32
    } else {
        !(_DefaultRuneLocale.__runetype[
              _c as (usize)
          ] as (usize) & _f == 0) as (i32)
    }
}

#[no_mangle]
pub unsafe extern fn __wcwidth(mut _c : i32) -> i32 {
    let mut _x : u32;
    if _c == 0i32 {
        0i32
    } else {
        _x = __maskrune(_c,0xe0000000usize | 0x40000usize) as (u32);
        (if _x as (usize) & 0xe0000000usize != 0usize {
             ((_x as (usize) & 0xe0000000usize) >> 30i32) as (i32)
         } else if _x as (usize) & 0x40000usize != 0usize {
             1i32
         } else {
             -1i32
         })
    }
}

#[no_mangle]
pub unsafe extern fn isalnum(mut _c : i32) -> i32 {
    __istype(_c,(0x100isize | 0x400isize) as (usize))
}

#[no_mangle]
pub unsafe extern fn isalpha(mut _c : i32) -> i32 {
    __istype(_c,0x100usize)
}

#[no_mangle]
pub unsafe extern fn isblank(mut _c : i32) -> i32 {
    __istype(_c,0x20000usize)
}

#[no_mangle]
pub unsafe extern fn iscntrl(mut _c : i32) -> i32 {
    __istype(_c,0x200usize)
}

#[no_mangle]
pub unsafe extern fn isdigit(mut _c : i32) -> i32 {
    __isctype(_c,0x400usize)
}

#[no_mangle]
pub unsafe extern fn isgraph(mut _c : i32) -> i32 {
    __istype(_c,0x800usize)
}

#[no_mangle]
pub unsafe extern fn islower(mut _c : i32) -> i32 {
    __istype(_c,0x1000usize)
}

#[no_mangle]
pub unsafe extern fn isprint(mut _c : i32) -> i32 {
    __istype(_c,0x40000usize)
}

#[no_mangle]
pub unsafe extern fn ispunct(mut _c : i32) -> i32 {
    __istype(_c,0x2000usize)
}

#[no_mangle]
pub unsafe extern fn isspace(mut _c : i32) -> i32 {
    __istype(_c,0x4000usize)
}

#[no_mangle]
pub unsafe extern fn isupper(mut _c : i32) -> i32 {
    __istype(_c,0x8000usize)
}

#[no_mangle]
pub unsafe extern fn isxdigit(mut _c : i32) -> i32 {
    __isctype(_c,0x10000usize)
}

#[no_mangle]
pub unsafe extern fn toascii(mut _c : i32) -> i32 { _c & 0x7fi32 }

#[no_mangle]
pub unsafe extern fn tolower(mut _c : i32) -> i32 { __tolower(_c) }

#[no_mangle]
pub unsafe extern fn toupper(mut _c : i32) -> i32 { __toupper(_c) }

#[no_mangle]
pub unsafe extern fn digittoint(mut _c : i32) -> i32 {
    __maskrune(_c,0xfusize)
}

#[no_mangle]
pub unsafe extern fn ishexnumber(mut _c : i32) -> i32 {
    __istype(_c,0x10000usize)
}

#[no_mangle]
pub unsafe extern fn isideogram(mut _c : i32) -> i32 {
    __istype(_c,0x80000usize)
}

#[no_mangle]
pub unsafe extern fn isnumber(mut _c : i32) -> i32 {
    __istype(_c,0x400usize)
}

#[no_mangle]
pub unsafe extern fn isphonogram(mut _c : i32) -> i32 {
    __istype(_c,0x200000usize)
}

#[no_mangle]
pub unsafe extern fn isrune(mut _c : i32) -> i32 {
    __istype(_c,0xfffffff0usize)
}

#[no_mangle]
pub unsafe extern fn isspecial(mut _c : i32) -> i32 {
    __istype(_c,0x100000usize)
}

#[derive(Copy)]
#[repr(C)]
pub struct __sbuf {
    pub _base : *mut u8,
    pub _size : i32,
}

impl Clone for __sbuf {
    fn clone(&self) -> Self { *self }
}

#[derive(Copy)]
#[repr(C)]
pub struct __sFILE {
    pub _p : *mut u8,
    pub _r : i32,
    pub _w : i32,
    pub _flags : i16,
    pub _file : i16,
    pub _bf : __sbuf,
    pub _lbfsize : i32,
    pub _cookie : *mut ::std::os::raw::c_void,
    pub _close : unsafe extern fn(*mut ::std::os::raw::c_void) -> i32,
    pub _read : unsafe extern fn(*mut ::std::os::raw::c_void, *mut u8, i32) -> i32,
    pub _seek : unsafe extern fn(*mut ::std::os::raw::c_void, isize, i32) -> isize,
    pub _write : unsafe extern fn(*mut ::std::os::raw::c_void, *const u8, i32) -> i32,
    pub _ub : __sbuf,
    pub _extra : *mut __sFILEX,
    pub _ur : i32,
    pub _ubuf : [u8; 3],
    pub _nbuf : [u8; 1],
    pub _lb : __sbuf,
    pub _blksize : i32,
    pub _offset : isize,
}

impl Clone for __sFILE {
    fn clone(&self) -> Self { *self }
}

#[no_mangle]
pub unsafe extern fn __sputc(
    mut _c : i32, mut _p : *mut __sFILE
) -> i32 {
    if {
           (*_p)._w = (*_p)._w - 1;
           (*_p)._w
       } >= 0i32 || (*_p)._w >= (*_p)._lbfsize && (_c as (u8) as (i32) != b'\n' as (i32)) {
        ({
             let _rhs = _c;
             let _lhs
                 = &mut *{
                             let _old = (*_p)._p;
                             (*_p)._p = (*_p)._p.offset(1isize);
                             _old
                         };
             *_lhs = _rhs as (u8);
             *_lhs
         }) as (i32)
    } else {
        __swbuf(_c,_p)
    }
}

#[no_mangle]
pub static mut szLOG_SOURCE
    : *const u8
    = (*b"YubiKey PIV Library\0").as_ptr();

#[derive(Clone, Copy)]
#[repr(i32)]
pub enum Enum5 {
    DES_OK = 0i32,
    DES_INVALID_PARAMETER = -1i32,
    DES_BUFFER_TOO_SMALL = -2i32,
    DES_MEMORY_ERROR = -3i32,
    DES_GENERAL_ERROR = -4i32,
}

#[derive(Copy)]
#[repr(C)]
pub struct DES_ks {
    pub ks : [Union6; 16],
}

impl Clone for DES_ks {
    fn clone(&self) -> Self { *self }
}

#[derive(Copy)]
#[repr(C)]
pub struct des_key {
    pub ks1 : DES_ks,
    pub ks2 : DES_ks,
    pub ks3 : DES_ks,
}

impl Clone for des_key {
    fn clone(&self) -> Self { *self }
}

#[no_mangle]
pub unsafe extern fn des_import_key(
    type_ : i32,
    mut keyraw : *const u8,
    keyrawlen : usize,
    mut key : *mut *mut des_key
) -> Enum5 {
    let mut _currentBlock;
    let mut rc : Enum5 = Enum5::DES_OK;
    let mut cb_expectedkey : usize = (8i32 * 3i32) as (usize);
    let mut key_tmp : [u8; 8];
    let mut cb_keysize : usize = 8usize;
    if type_ == 1i32 {
        cb_expectedkey = (8i32 * 3i32) as (usize);
        cb_keysize = 8usize;
        if cb_keysize > ::std::mem::size_of::<[u8; 8]>() {
            rc = Enum5::DES_MEMORY_ERROR;
            _currentBlock = 15;
        } else if keyraw.is_null() {
            rc = Enum5::DES_INVALID_PARAMETER;
            _currentBlock = 15;
        } else if keyrawlen != cb_expectedkey {
            rc = Enum5::DES_INVALID_PARAMETER;
            _currentBlock = 15;
        } else if key.is_null() {
            rc = Enum5::DES_INVALID_PARAMETER;
            _currentBlock = 15;
        } else if {
                      *key = malloc(::std::mem::size_of::<des_key>()) as (*mut des_key);
                      *key
                  }.is_null(
                  ) {
            rc = Enum5::DES_MEMORY_ERROR;
            _currentBlock = 15;
        } else {
            memset(
                *key as (*mut ::std::os::raw::c_void),
                0i32,
                ::std::mem::size_of::<des_key>()
            );
            memcpy(
                key_tmp.as_mut_ptr() as (*mut ::std::os::raw::c_void),
                keyraw as (*const ::std::os::raw::c_void),
                cb_keysize
            );
            DES_set_key_unchecked(
                &mut key_tmp as (*mut [u8; 8]),
                &mut (**key).ks1 as (*mut DES_ks)
            );
            memcpy(
                key_tmp.as_mut_ptr() as (*mut ::std::os::raw::c_void),
                keyraw.offset(
                    cb_keysize as (isize)
                ) as (*const ::std::os::raw::c_void),
                cb_keysize
            );
            DES_set_key_unchecked(
                &mut key_tmp as (*mut [u8; 8]),
                &mut (**key).ks2 as (*mut DES_ks)
            );
            memcpy(
                key_tmp.as_mut_ptr() as (*mut ::std::os::raw::c_void),
                keyraw.offset(
                    2usize.wrapping_mul(cb_keysize) as (isize)
                ) as (*const ::std::os::raw::c_void),
                cb_keysize
            );
            DES_set_key_unchecked(
                &mut key_tmp as (*mut [u8; 8]),
                &mut (**key).ks3 as (*mut DES_ks)
            );
            _currentBlock = 17;
        }
    } else {
        rc = Enum5::DES_INVALID_PARAMETER;
        _currentBlock = 15;
    }
    if _currentBlock == 15 {
        if !key.is_null() {
            des_destroy_key(*key);
            *key = 0i32 as (*mut ::std::os::raw::c_void) as (*mut des_key);
        }
    }
    rc
}

#[no_mangle]
pub unsafe extern fn des_destroy_key(mut key : *mut des_key) -> Enum5 {
    if !key.is_null() {
        free(key as (*mut ::std::os::raw::c_void));
    }
    Enum5::DES_OK
}

#[no_mangle]
pub unsafe extern fn des_encrypt(
    mut key : *mut des_key,
    mut in_ : *const u8,
    inlen : usize,
    mut out : *mut u8,
    mut outlen : *mut usize
) -> Enum5 {
    let mut rc : Enum5 = Enum5::DES_OK;
    if key.is_null() || outlen.is_null(
                        ) || *outlen < inlen || in_.is_null() || out.is_null() {
        rc = Enum5::DES_INVALID_PARAMETER;
    } else {
        DES_ecb3_encrypt(
            in_ as (*mut [u8; 8]),
            out as (*mut [u8; 8]),
            &mut (*key).ks1 as (*mut DES_ks),
            &mut (*key).ks2 as (*mut DES_ks),
            &mut (*key).ks3 as (*mut DES_ks),
            1i32
        );
    }
    rc
}

#[no_mangle]
pub unsafe extern fn des_decrypt(
    mut key : *mut des_key,
    mut in_ : *const u8,
    inlen : usize,
    mut out : *mut u8,
    mut outlen : *mut usize
) -> Enum5 {
    let mut rc : Enum5 = Enum5::DES_OK;
    if key.is_null() || outlen.is_null(
                        ) || *outlen < inlen || in_.is_null() || out.is_null() {
        rc = Enum5::DES_INVALID_PARAMETER;
    } else {
        DES_ecb3_encrypt(
            in_ as (*mut [u8; 8]),
            out as (*mut [u8; 8]),
            &mut (*key).ks1 as (*mut DES_ks),
            &mut (*key).ks2 as (*mut DES_ks),
            &mut (*key).ks3 as (*mut DES_ks),
            0i32
        );
    }
    rc
}

#[no_mangle]
pub unsafe extern fn yk_des_is_weak_key(
    mut key : *const u8, cb_key : usize
) -> bool {
    cb_key;
    DES_is_weak_key(key as (*mut [u8; 8])) != 0
}

#[derive(Clone, Copy)]
#[repr(i32)]
pub enum Enum7 {
    PRNG_OK = 0i32,
    PRNG_GENERAL_ERROR = -1i32,
}

#[no_mangle]
pub unsafe extern fn _ykpiv_prng_generate(
    mut buffer : *mut u8, cb_req : usize
) -> Enum7 {
    let mut rc : Enum7 = Enum7::PRNG_OK;
    if -1i32 == RAND_bytes(buffer,cb_req as (i32)) {
        rc = Enum7::PRNG_GENERAL_ERROR;
    }
    rc
}

#[derive(Clone, Copy)]
#[repr(i32)]
pub enum Enum8 {
    PKCS5_OK = 0i32,
    PKCS5_GENERAL_ERROR = -1i32,
}

#[no_mangle]
pub unsafe extern fn pkcs5_pbkdf2_sha1(
    mut password : *const u8,
    cb_password : usize,
    mut salt : *const u8,
    cb_salt : usize,
    mut iterations : usize,
    mut key : *const u8,
    cb_key : usize
) -> Enum8 {
    let mut rc : Enum8 = Enum8::PKCS5_OK;
    PKCS5_PBKDF2_HMAC_SHA1(
        password,
        cb_password as (i32),
        salt,
        cb_salt as (i32),
        iterations as (i32),
        cb_key as (i32),
        key as (*mut u8)
    );
    rc
}

#[no_mangle]
pub unsafe extern fn _strip_ws(mut sz : *mut u8) -> *mut u8 {
    let mut psz_head : *mut u8 = sz;
    let mut psz_tail
        : *mut u8
        = sz.offset(strlen(sz as (*const u8)) as (isize)).offset(-1isize);
    'loop1: loop {
        if isspace(*psz_head as (i32)) == 0 {
            break;
        }
        psz_head = psz_head.offset(1isize);
    }
    'loop2: loop {
        if !(psz_tail >= psz_head && (isspace(*psz_tail as (i32)) != 0)) {
            break;
        }
        *{
             let _old = psz_tail;
             psz_tail = psz_tail.offset(-1isize);
             _old
         } = b'\0';
    }
    psz_head
}

#[derive(Clone, Copy)]
#[repr(i32)]
pub enum _setting_source_t {
    SETTING_SOURCE_USER,
    SETTING_SOURCE_ADMIN,
    SETTING_SOURCE_DEFAULT,
}

#[derive(Copy)]
#[repr(C)]
pub struct _setting_bool_t {
    pub value : bool,
    pub source : _setting_source_t,
}

impl Clone for _setting_bool_t {
    fn clone(&self) -> Self { *self }
}

#[no_mangle]
pub unsafe extern fn _get_bool_config(
    mut sz_setting : *const u8
) -> _setting_bool_t {
    let mut _currentBlock;
    let mut setting
        : _setting_bool_t
        = _setting_bool_t {
              value: false,
              source: _setting_source_t::SETTING_SOURCE_DEFAULT
          };
    let mut sz_line : [u8; 256];
    let mut psz_name : *mut u8 = 0i32 as (*mut u8);
    let mut psz_value : *mut u8 = 0i32 as (*mut u8);
    let mut sz_name : [u8; 256];
    let mut sz_value : [u8; 256];
    let mut pf : *mut __sFILE = 0i32 as (*mut __sFILE);
    if !{
            pf = fopen(
                     (*b"/etc/yubico/yubikeypiv.conf\0").as_ptr(),
                     (*b"r\0").as_ptr()
                 );
            pf
        }.is_null(
        ) {
        _currentBlock = 1;
    } else {
        _currentBlock = 10;
    }
    'loop1: loop {
        if _currentBlock == 1 {
            if feof(pf) == 0 {
                if fgets(
                       sz_line.as_mut_ptr(),
                       ::std::mem::size_of::<[u8; 256]>() as (i32),
                       pf
                   ).is_null(
                   ) {
                    _currentBlock = 1;
                    continue;
                }
                if sz_line[0usize] as (i32) == b'#' as (i32) {
                    _currentBlock = 1;
                    continue;
                }
                if sz_line[0usize] as (i32) == b'\r' as (i32) {
                    _currentBlock = 1;
                    continue;
                }
                if sz_line[0usize] as (i32) == b'\n' as (i32) {
                    _currentBlock = 1;
                    continue;
                }
                if !(sscanf(
                         sz_line.as_mut_ptr() as (*const u8),
                         (*b"%255[^=]=%255s\0").as_ptr(),
                         sz_name.as_mut_ptr(),
                         sz_value.as_mut_ptr()
                     ) == 2i32) {
                    _currentBlock = 1;
                    continue;
                }
                psz_name = _strip_ws(sz_name.as_mut_ptr());
                if !(strcasecmp(psz_name as (*const u8),sz_setting) == 0) {
                    _currentBlock = 1;
                    continue;
                }
                psz_value = _strip_ws(sz_value.as_mut_ptr());
                setting.source = _setting_source_t::SETTING_SOURCE_ADMIN;
                setting.value = strcmp(
                                    psz_value as (*const u8),
                                    (*b"1\0").as_ptr()
                                ) == 0 || strcasecmp(
                                              psz_value as (*const u8),
                                              (*b"true\0").as_ptr()
                                          ) == 0;
            }
            fclose(pf);
            _currentBlock = 10;
        } else {
            return setting;
        }
    }
}

#[no_mangle]
pub unsafe extern fn _get_bool_env(
    mut sz_setting : *const u8
) -> _setting_bool_t {
    let mut setting
        : _setting_bool_t
        = _setting_bool_t {
              value: false,
              source: _setting_source_t::SETTING_SOURCE_DEFAULT
          };
    let mut psz_value
        : *mut u8
        = 0i32 as (*mut ::std::os::raw::c_void) as (*mut u8);
    let mut sz_name : [u8; 256];
    snprintf(
        sz_name.as_mut_ptr(),
        ::std::mem::size_of::<[u8; 256]>().wrapping_sub(1usize),
        (*b"%s%s\0").as_ptr(),
        (*b"YUBIKEY_PIV_\0").as_ptr(),
        sz_setting
    );
    psz_value = getenv(sz_name.as_mut_ptr() as (*const u8));
    if !psz_value.is_null() {
        setting.source = _setting_source_t::SETTING_SOURCE_USER;
        setting.value = strcmp(
                            psz_value as (*const u8),
                            (*b"1\0").as_ptr()
                        ) == 0 || strcasecmp(
                                      psz_value as (*const u8),
                                      (*b"true\0").as_ptr()
                                  ) == 0;
    }
    setting
}

#[no_mangle]
pub unsafe extern fn setting_get_bool(
    mut sz_setting : *const u8, mut def : bool
) -> _setting_bool_t {
    let mut setting
        : _setting_bool_t
        = _setting_bool_t {
              value: def,
              source: _setting_source_t::SETTING_SOURCE_DEFAULT
          };
    setting = _get_bool_config(sz_setting);
    if setting.source as (i32) == _setting_source_t::SETTING_SOURCE_DEFAULT as (i32) {
        setting = _get_bool_env(sz_setting);
    }
    if setting.source as (i32) == _setting_source_t::SETTING_SOURCE_DEFAULT as (i32) {
        setting.value = def;
    }
    setting
}
