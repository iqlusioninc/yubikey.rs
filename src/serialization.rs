//! Serialization functions

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

use crate::{consts::*, ObjectId};

// TODO(tarcieri): refactor these into better serializers/message builders

/// Set length
pub(crate) fn set_length(buffer: &mut [u8], length: usize) -> usize {
    if length < 0x80 {
        buffer[0] = length as u8;
        1
    } else if length < 0x100 {
        buffer[0] = 0x81;
        buffer[1] = length as u8;
        2
    } else {
        buffer[0] = 0x82;
        buffer[1] = ((length >> 8) & 0xff) as u8;
        buffer[2] = (length & 0xff) as u8;
        3
    }
}

/// Parse length tag, returning the size of the length tag itself as the
/// returned value, and setting the len parameter to the parsed length.
pub(crate) fn get_length(buffer: &[u8], len: &mut usize) -> usize {
    if buffer[0] < 0x81 {
        *len = buffer[0] as usize;
        1
    } else if (buffer[0] & 0x7f) == 1 {
        *len = buffer[1] as usize;
        2
    } else if (buffer[0] & 0x7f) == 2 {
        let tmp = buffer[1] as usize;
        *len = (tmp << 8) + buffer[2] as usize;
        3
    } else {
        0
    }
}

/// Is length valid?
pub(crate) fn has_valid_length(buffer: &[u8], len: usize) -> bool {
    (buffer[0] < 0x81 && len > 0)
        || ((buffer[0] & 0x7f) == 1 && len > 1)
        || ((buffer[0] & 0x7f == 2) && (len > 2))
}

/// Set an object ID header value in the given buffer, returning a mutable
/// slice immediately after the header.
///
/// Panics if the buffer is too small to contain the header.
pub(crate) fn set_object(object_id: ObjectId, mut buffer: &mut [u8]) -> &mut [u8] {
    buffer[0] = 0x5c;

    if object_id == YKPIV_OBJ_DISCOVERY {
        buffer[1] = 1;
        buffer[2] = YKPIV_OBJ_DISCOVERY as u8;
        buffer = &mut buffer[3..];
    } else if object_id > 0xffff && object_id <= 0x00ff_ffff {
        buffer[1] = 3;
        buffer[2] = ((object_id >> 16) & 0xff) as u8;
        buffer[3] = ((object_id >> 8) & 0xff) as u8;
        buffer[4] = (object_id & 0xff) as u8;
        buffer = &mut buffer[5..];
    }

    buffer
}
