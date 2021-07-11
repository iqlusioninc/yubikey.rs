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

use crate::{Buffer, Error, ObjectId, Result, CB_OBJ_TAG_MIN};

pub const OBJ_DISCOVERY: u32 = 0x7e;

// TODO(tarcieri): refactor these into better serializers/message builders

/// A Type-Length-Value object that has been parsed from a buffer.
pub(crate) struct Tlv<'a> {
    pub(crate) tag: u8,
    pub(crate) value: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// Parses a `Tlv` from a buffer, returning the remainder of the buffer.
    pub(crate) fn parse(buffer: &'a [u8]) -> Result<(&'a [u8], Self)> {
        if buffer.len() < CB_OBJ_TAG_MIN || !has_valid_length(&buffer[1..], buffer.len() - 1) {
            return Err(Error::SizeError);
        }

        let tag = buffer[0];

        let mut len = 0;
        let offset = 1 + get_length(&buffer[1..], &mut len);

        let (value, buffer) = buffer[offset..].split_at(len);

        Ok((buffer, Tlv { tag, value }))
    }

    /// Takes a [`Buffer`] containing a single `Tlv` with the given tag, and returns a
    /// `Buffer` containing only the value part of the `Tlv`.
    pub(crate) fn parse_single(mut buffer: Buffer, tag: u8) -> Result<Buffer> {
        if buffer.len() < CB_OBJ_TAG_MIN || !has_valid_length(&buffer[1..], buffer.len() - 1) {
            return Err(Error::SizeError);
        }

        if tag != buffer[0] {
            return Err(Error::GenericError);
        };

        let mut len = 0;
        let offset = 1 + get_length(&buffer[1..], &mut len);

        buffer.copy_within(offset..offset + len, 0);
        buffer.truncate(len);
        Ok(buffer)
    }

    /// Writes a TLV to the given buffer.
    pub(crate) fn write(buffer: &mut [u8], tag: u8, value: &[u8]) -> Result<usize> {
        if buffer.len() < CB_OBJ_TAG_MIN {
            return Err(Error::SizeError);
        }
        buffer[0] = tag;

        let offset = 1 + set_length(&mut buffer[1..], value.len())?;

        if buffer.len() < offset + value.len() {
            return Err(Error::SizeError);
        }
        buffer[offset..offset + value.len()].copy_from_slice(value);

        Ok(offset + value.len())
    }

    /// Writes a TLV to the given buffer.
    ///
    /// `value` is guaranteed to be called with a mutable slice of length `length`.
    pub(crate) fn write_as<Gen>(
        buffer: &mut [u8],
        tag: u8,
        length: usize,
        value: Gen,
    ) -> Result<usize>
    where
        Gen: FnOnce(&mut [u8]),
    {
        if buffer.len() < CB_OBJ_TAG_MIN {
            return Err(Error::SizeError);
        }
        buffer[0] = tag;

        let offset = 1 + set_length(&mut buffer[1..], length)?;

        if buffer.len() < offset + length {
            return Err(Error::SizeError);
        }
        value(&mut buffer[offset..offset + length]);

        Ok(offset + length)
    }
}

/// Set length
pub(crate) fn set_length(buffer: &mut [u8], length: usize) -> Result<usize> {
    if length < 0x80 {
        if buffer.is_empty() {
            Err(Error::SizeError)
        } else {
            buffer[0] = length as u8;
            Ok(1)
        }
    } else if length < 0x100 {
        if buffer.len() < 2 {
            Err(Error::SizeError)
        } else {
            buffer[0] = 0x81;
            buffer[1] = length as u8;
            Ok(2)
        }
    } else if buffer.len() < 3 {
        Err(Error::SizeError)
    } else {
        buffer[0] = 0x82;
        buffer[1] = ((length >> 8) & 0xff) as u8;
        buffer[2] = (length & 0xff) as u8;
        Ok(3)
    }
}

/// Parse length tag, returning the size of the length tag itself as the
/// returned value, and setting the len parameter to the parsed length.
pub(crate) fn get_length(buffer: &[u8], len: &mut usize) -> usize {
    // This is not valid ASN.1 (0x80 is the indefinite length marker).
    // See comment in key::generate for more context.
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

    if object_id == OBJ_DISCOVERY {
        buffer[1] = 1;
        buffer[2] = OBJ_DISCOVERY as u8;
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
