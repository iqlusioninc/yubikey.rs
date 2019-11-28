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

use crate::{consts::*, error::Error, serialization::*, transaction::Transaction, Buffer};
use zeroize::Zeroizing;

/// Get metadata item
pub(crate) fn get_item(data: &[u8], tag: u8) -> Result<&[u8], Error> {
    let mut cb_temp: usize = 0;
    let mut offset = 0;

    while offset < data.len() {
        let tag_temp = data[offset];
        offset += 1;

        if !has_valid_length(&data[offset..], data.len() - 1) {
            return Err(Error::SizeError);
        }

        offset += get_length(&data[offset..], &mut cb_temp);

        if tag_temp == tag {
            // found tag
            break;
        }

        offset += cb_temp;
    }

    if offset < data.len() {
        Ok(&data[offset..offset + cb_temp])
    } else {
        Err(Error::GenericError)
    }
}

/// Set metadata item
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
        offset = *pcb_data;
        cb_len = get_length_size(cb_item);

        // If length would cause buffer overflow, return error
        if (*pcb_data + cb_len + cb_item) > cb_data_max {
            return Err(Error::GenericError);
        }

        data[offset] = tag;
        offset += 1;
        offset += set_length(&mut data[offset..], cb_item);
        data[offset..offset + cb_item].copy_from_slice(p_item);

        *pcb_data += 1 + cb_len + cb_item;

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
        offset += set_length(&mut data[offset..], cb_item);
        data[offset..offset + cb_item].copy_from_slice(p_item);
    }

    Ok(())
}

/// Read metadata
pub(crate) fn read(txn: &Transaction<'_>, tag: u8) -> Result<Buffer, Error> {
    let obj_id = match tag {
        TAG_ADMIN => YKPIV_OBJ_ADMIN_DATA,
        TAG_PROTECTED => YKPIV_OBJ_PRINTED,
        _ => return Err(Error::InvalidObject),
    };

    let mut data = txn.fetch_object(obj_id)?;

    if data.len() < CB_OBJ_TAG_MIN {
        return Err(Error::GenericError);
    }

    if tag != data[0] {
        return Err(Error::GenericError);
    }

    let mut pcb_data = 0;
    let offset = 1 + get_length(&data[1..], &mut pcb_data);

    if pcb_data > data.len() - offset {
        return Err(Error::GenericError);
    }

    data.copy_within(offset..offset + pcb_data, 0);
    data.truncate(pcb_data);
    Ok(data)
}

/// Write metadata
pub(crate) fn write(
    txn: &Transaction<'_>,
    tag: u8,
    data: &[u8],
    max_size: usize,
) -> Result<(), Error> {
    let mut buf = Zeroizing::new(vec![0u8; CB_OBJ_MAX]);

    if data.len() > max_size - CB_OBJ_TAG_MAX {
        return Err(Error::GenericError);
    }

    let obj_id = match tag {
        TAG_ADMIN => YKPIV_OBJ_ADMIN_DATA,
        TAG_PROTECTED => YKPIV_OBJ_PRINTED,
        _ => return Err(Error::InvalidObject),
    };

    if data.is_empty() {
        // Deleting metadata
        return txn.save_object(obj_id, &[]);
    }

    buf[0] = tag;
    let mut offset = set_length(&mut buf[1..], data.len());
    buf[offset..(offset + data.len())].copy_from_slice(data);
    offset += data.len();

    txn.save_object(obj_id, &buf[..offset])
}

/// Get the size of a length tag for the given length
fn get_length_size(length: usize) -> usize {
    if length < 0x80 {
        1
    } else if length < 0xff {
        2
    } else {
        3
    }
}
