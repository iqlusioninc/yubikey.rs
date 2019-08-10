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

extern "C" {
    fn strcmp(__s1: *const u8, __s2: *const u8) -> i32;
    fn strcspn(__s: *const u8, __charset: *const u8) -> usize;
    fn strncmp(__s1: *const u8, __s2: *const u8, __n: usize) -> i32;
    fn strspn(__s: *const u8, __charset: *const u8) -> usize;
}

unsafe extern "C" fn my_strverscmp(mut s1: *const u8, mut s2: *const u8) -> i32 {
    let mut _currentBlock;
    static mut digits: *const u8 = (*b"0123456789\0").as_ptr();
    let mut p1: usize;
    let mut p2: usize;
    p1 = strcspn(s1, digits);
    p2 = strcspn(s2, digits);
    'loop1: loop {
        if !(p1 == p2
            && (*s1.offset(p1 as (isize)) as (i32) != b'\0' as (i32))
            && (*s2.offset(p2 as (isize)) as (i32) != b'\0' as (i32)))
        {
            _currentBlock = 2;
            break;
        }
        let mut ret: i32;
        let mut lz1: i32;
        let mut lz2: i32;
        if {
            ret = strncmp(s1, s2, p1);
            ret
        } != 0i32
        {
            _currentBlock = 37;
            break;
        }
        s1 = s1.offset(p1 as (isize));
        s2 = s2.offset(p2 as (isize));
        lz1 = {
            lz2 = 0i32;
            lz2
        };
        if *s1 as (i32) == b'0' as (i32) {
            lz1 = 1i32;
        }
        if *s2 as (i32) == b'0' as (i32) {
            lz2 = 1i32;
        }
        if lz1 > lz2 {
            _currentBlock = 36;
            break;
        }
        if lz1 < lz2 {
            _currentBlock = 35;
            break;
        }
        if lz1 == 1i32 {
            _currentBlock = 11;
        } else {
            _currentBlock = 23;
        }
        'loop11: loop {
            if _currentBlock == 11 {
                if *s1 as (i32) == b'0' as (i32) && (*s2 as (i32) == b'0' as (i32)) {
                    s1 = s1.offset(1isize);
                    s2 = s2.offset(1isize);
                    _currentBlock = 11;
                } else {
                    p1 = strspn(s1, digits);
                    p2 = strspn(s2, digits);
                    if p1 == 0usize && (p2 > 0usize) {
                        _currentBlock = 33;
                        break 'loop1;
                    }
                    if p2 == 0usize && (p1 > 0usize) {
                        _currentBlock = 32;
                        break 'loop1;
                    }
                    if *s1 as (i32) != *s2 as (i32)
                        && (*s1 as (i32) != b'0' as (i32))
                        && (*s2 as (i32) != b'0' as (i32))
                    {
                        if p1 < p2 {
                            _currentBlock = 31;
                            break 'loop1;
                        }
                        if p1 > p2 {
                            _currentBlock = 30;
                            break 'loop1;
                        } else {
                            _currentBlock = 23;
                        }
                    } else {
                        if p1 < p2 {
                            ret = strncmp(s1, s2, p1);
                        } else if p1 > p2 {
                            ret = strncmp(s1, s2, p2);
                        }
                        if ret != 0i32 {
                            _currentBlock = 20;
                            break 'loop1;
                        } else {
                            _currentBlock = 23;
                        }
                    }
                }
            } else {
                p1 = strspn(s1, digits);
                p2 = strspn(s2, digits);
                if p1 < p2 {
                    _currentBlock = 29;
                    break 'loop1;
                } else {
                    break;
                }
            }
        }
        if p1 > p2 {
            _currentBlock = 28;
            break;
        }
        if {
            ret = strncmp(s1, s2, p1);
            ret
        } != 0i32
        {
            _currentBlock = 27;
            break;
        }
        s1 = s1.offset(p1 as (isize));
        s2 = s2.offset(p2 as (isize));
        p1 = strcspn(s1, digits);
        p2 = strcspn(s2, digits);
    }
    if _currentBlock == 2 {
        strcmp(s1, s2)
    } else if _currentBlock == 20 {
        ret
    } else if _currentBlock == 27 {
        ret
    } else if _currentBlock == 28 {
        1i32
    } else if _currentBlock == 29 {
        -1i32
    } else if _currentBlock == 30 {
        -1i32
    } else if _currentBlock == 31 {
        1i32
    } else if _currentBlock == 32 {
        -1i32
    } else if _currentBlock == 33 {
        1i32
    } else if _currentBlock == 35 {
        1i32
    } else if _currentBlock == 36 {
        -1i32
    } else {
        ret
    }
}

#[no_mangle]
pub unsafe extern "C" fn ykpiv_check_version(mut req_version: *const u8) -> *const u8 {
    if req_version.is_null() || my_strverscmp(req_version, (*b"@VERSION@\0").as_ptr()) <= 0i32 {
        (*b"@VERSION@\0").as_ptr()
    } else {
        0i32 as (*mut ::std::os::raw::c_void) as (*const u8)
    }
}
