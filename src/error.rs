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

#[derive(Clone, Copy)]
#[repr(i32)]
pub enum Enum2 {
    YKPIV_OK = 0i32,
    YKPIV_MEMORY_ERROR = -1i32,
    YKPIV_PCSC_ERROR = -2i32,
    YKPIV_SIZE_ERROR = -3i32,
    YKPIV_APPLET_ERROR = -4i32,
    YKPIV_AUTHENTICATION_ERROR = -5i32,
    YKPIV_RANDOMNESS_ERROR = -6i32,
    YKPIV_GENERIC_ERROR = -7i32,
    YKPIV_KEY_ERROR = -8i32,
    YKPIV_PARSE_ERROR = -9i32,
    YKPIV_WRONG_PIN = -10i32,
    YKPIV_INVALID_OBJECT = -11i32,
    YKPIV_ALGORITHM_ERROR = -12i32,
    YKPIV_PIN_LOCKED = -13i32,
    YKPIV_ARGUMENT_ERROR = -14i32,
    YKPIV_RANGE_ERROR = -15i32,
    YKPIV_NOT_SUPPORTED = -16i32,
}

#[derive(Copy)]
#[repr(C)]
pub struct Struct1 {
    pub rc: Enum2,
    pub name: *const u8,
    pub description: *const u8,
}

impl Clone for Struct1 {
    fn clone(&self) -> Self {
        *self
    }
}

static mut errors: *const Struct1 = Enum2::YKPIV_OK as (*const Struct1);

#[no_mangle]
pub unsafe extern "C" fn ykpiv_strerror(mut err: Enum2) -> *const u8 {
    static mut unknown: *const u8 = (*b"Unknown ykpiv error\0").as_ptr();
    let mut p: *const u8;
    if -(err as (i32)) < 0i32
        || -(err as (i32))
            >= ::std::mem::size_of::<*const Struct1>()
                .wrapping_div(::std::mem::size_of::<Struct1>()) as (i32)
    {
        unknown
    } else {
        p = (*errors.offset(-(err as (i32)) as (isize))).description;
        if p.is_null() {
            p = unknown;
        }
        p
    }
}

#[no_mangle]
pub unsafe extern "C" fn ykpiv_strerror_name(mut err: Enum2) -> *const u8 {
    if -(err as (i32)) < 0i32
        || -(err as (i32))
            >= ::std::mem::size_of::<*const Struct1>()
                .wrapping_div(::std::mem::size_of::<Struct1>()) as (i32)
    {
        0i32 as (*mut ::std::os::raw::c_void) as (*const u8)
    } else {
        (*errors.offset(-(err as (i32)) as (isize))).name
    }
}
