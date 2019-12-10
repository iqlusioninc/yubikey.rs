//! YubiKey Device Metadata

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

use crate::{
    error::Error, serialization::*, transaction::Transaction, Buffer, TAG_ADMIN, TAG_PROTECTED,
};

#[cfg(feature = "untested")]
use crate::{CB_OBJ_MAX, CB_OBJ_TAG_MAX};

#[cfg(feature = "untested")]
use zeroize::Zeroizing;

pub const OBJ_ADMIN_DATA: u32 = 0x005f_ff00;
pub const OBJ_PRINTED: u32 = 0x005f_c109;

/// Get metadata item
pub(crate) fn get_item(mut data: &[u8], tag: u8) -> Result<&[u8], Error> {
    while !data.is_empty() {
        let (remaining, tlv) = Tlv::parse(data)?;
        data = remaining;

        if tlv.tag == tag {
            // found tag
            return Ok(tlv.value);
        }
    }

    Err(Error::GenericError)
}

/// Set metadata item
#[cfg(feature = "untested")]
pub(crate) fn set_item(
    data: &mut [u8],
    pcb_data: &mut usize,
    cb_data_max: usize,
    tag: u8,
    p_item: &[u8],
) -> Result<(), Error> {
    let mut cb_temp: usize = 0;
    let mut tag_temp: u8 = 0;
    let mut cb_len: usize = 0;
    let cb_item = p_item.len();

    let mut offset = 0;

    while offset < *pcb_data {
        tag_temp = data[offset];
        offset += 1;

        cb_len = get_length(&data[offset..], &mut cb_temp);
        offset += cb_len;

        if tag_temp == tag {
            break;
        }

        offset += cb_temp;
    }

    if tag_temp != tag {
        if cb_item == 0 {
            // We've been asked to delete an existing item that isn't in the blob
            return Ok(());
        }

        // We did not find an existing tag, append
        *pcb_data += Tlv::write(&mut data[*pcb_data..], tag, p_item)?;

        return Ok(());
    }

    // Found tag

    // Check length, if it matches, overwrite
    if cb_temp == cb_item {
        data[offset..offset + cb_item].copy_from_slice(p_item);
        return Ok(());
    }

    // Length doesn't match, expand/shrink to fit
    let next_offset = offset + cb_temp;
    // Must be signed to have negative offsets
    let cb_moved: isize = (cb_item as isize - cb_temp as isize)
        + if cb_item != 0 {
            get_length_size(cb_item) as isize
        } else {
            // For tag, if deleting
            -1
        }
        // Accounts for different length encoding
        - cb_len as isize;

    // If length would cause buffer overflow, return error
    if (*pcb_data as isize + cb_moved) as usize > cb_data_max {
        return Err(Error::GenericError);
    }

    // Move remaining data
    data.copy_within(
        next_offset..*pcb_data,
        (next_offset as isize + cb_moved) as usize,
    );
    *pcb_data = (*pcb_data as isize + cb_moved) as usize;

    // Re-encode item and insert
    if cb_item != 0 {
        offset -= cb_len;
        offset += set_length(&mut data[offset..], cb_item)?;
        data[offset..offset + cb_item].copy_from_slice(p_item);
    }

    Ok(())
}

/// Read metadata
pub(crate) fn read(txn: &Transaction<'_>, tag: u8) -> Result<Buffer, Error> {
    let obj_id = match tag {
        TAG_ADMIN => OBJ_ADMIN_DATA,
        TAG_PROTECTED => OBJ_PRINTED,
        _ => return Err(Error::InvalidObject),
    };

    let data = txn.fetch_object(obj_id)?;
    Tlv::parse_single(data, tag)
}

/// Write metadata
#[cfg(feature = "untested")]
pub(crate) fn write(txn: &Transaction<'_>, tag: u8, data: &[u8]) -> Result<(), Error> {
    if data.len() > CB_OBJ_MAX - CB_OBJ_TAG_MAX {
        return Err(Error::GenericError);
    }

    let obj_id = match tag {
        TAG_ADMIN => OBJ_ADMIN_DATA,
        TAG_PROTECTED => OBJ_PRINTED,
        _ => return Err(Error::InvalidObject),
    };

    if data.is_empty() {
        // Deleting metadata
        return txn.save_object(obj_id, &[]);
    }

    let mut buf = Zeroizing::new(vec![0u8; CB_OBJ_MAX]);
    let len = Tlv::write(&mut buf, tag, data)?;

    txn.save_object(obj_id, &buf[..len])
}

/// Get the size of a length tag for the given length
#[cfg(feature = "untested")]
fn get_length_size(length: usize) -> usize {
    if length < 0x80 {
        1
    } else if length < 0xff {
        2
    } else {
        3
    }
}
