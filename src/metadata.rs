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
use std::{ptr, slice};
use zeroize::Zeroizing;

/// Get metadata item
pub(crate) fn get_item(data: &[u8], tag: u8) -> Result<&[u8], Error> {
    let mut p_temp: *const u8 = data.as_ptr();
    let mut cb_temp: usize = 0;
    let mut tag_temp: u8;

    unsafe {
        while p_temp < data.as_ptr().add(data.len()) {
            tag_temp = *p_temp;
            p_temp = p_temp.add(1);

            let p_slice = slice::from_raw_parts(
                p_temp,
                data.as_ptr() as usize + data.len() - p_temp as usize,
            );

            if !has_valid_length(
                p_slice,
                data.as_ptr().add(data.len()) as usize - p_temp as usize,
            ) {
                return Err(Error::SizeError);
            }

            p_temp = p_temp.add(get_length(p_slice, &mut cb_temp));

            if tag_temp == tag {
                // found tag
                break;
            }

            p_temp = p_temp.add(cb_temp);
        }

        if p_temp < data.as_ptr().add(data.len()) {
            return Ok(slice::from_raw_parts(p_temp, cb_temp));
        }
    }

    Err(Error::GenericError)
}

/// Set metadata item
pub(crate) fn set_item(
    data: &mut [u8],
    pcb_data: &mut usize,
    cb_data_max: usize,
    tag: u8,
    p_item: &[u8],
) -> Result<(), Error> {
    let mut p_temp: *mut u8 = data.as_mut_ptr();
    let mut cb_temp: usize = 0;
    let mut tag_temp: u8 = 0;
    let mut cb_len: usize = 0;
    let cb_item = p_item.len();
    // Must be signed to have negative offsets
    let cb_moved: isize;
    let p_next: *mut u8;

    while p_temp < data[*pcb_data..].as_mut_ptr() {
        unsafe {
            tag_temp = *p_temp;
            p_temp = p_temp.add(1);

            cb_len = get_length(
                slice::from_raw_parts(
                    p_temp,
                    data.as_mut_ptr() as usize + data.len() - p_temp as usize,
                ),
                &mut cb_temp,
            );
            p_temp = p_temp.add(cb_len);

            if tag_temp == tag {
                break;
            }

            p_temp = p_temp.add(cb_temp);
        }
    }

    if tag_temp != tag {
        if cb_item == 0 {
            // We've been asked to delete an existing item that isn't in the blob
            return Ok(());
        }

        unsafe {
            p_temp = data.as_mut_ptr().add(*pcb_data);
            cb_len = get_length_size(cb_item);

            if (*pcb_data + cb_len + cb_item) > cb_data_max {
                return Err(Error::GenericError);
            }

            *p_temp = tag;
            p_temp = p_temp.add(1);
            p_temp = p_temp.add(set_length(
                slice::from_raw_parts_mut(
                    p_temp,
                    data.as_ptr() as usize + data.len() - p_temp as usize,
                ),
                cb_item,
            ));

            ptr::copy(p_item.as_ptr(), p_temp, cb_item);
        }

        *pcb_data += 1 + cb_len + cb_item;

        return Ok(());
    }

    if cb_temp == cb_item {
        unsafe {
            ptr::copy(p_item.as_ptr(), p_temp, cb_item);
        }

        return Ok(());
    }

    p_next = unsafe { p_temp.add(cb_temp) };
    cb_moved = (cb_item as isize - cb_temp as isize)
        + if cb_item != 0 {
            get_length_size(cb_item) as isize
        } else {
            -1
        }
        - cb_len as isize;

    if (*pcb_data + cb_moved as usize) > cb_data_max {
        return Err(Error::GenericError);
    }

    unsafe {
        ptr::copy(
            p_next,
            p_next.offset(cb_moved),
            *pcb_data - p_next as usize - data.as_ptr() as usize,
        );
    }

    *pcb_data += cb_moved as usize;

    if cb_item != 0 {
        unsafe {
            p_temp = p_temp.offset(-(cb_len as isize));
            p_temp = p_temp.add(set_length(
                slice::from_raw_parts_mut(
                    p_temp,
                    data.as_ptr() as usize + data.len() - p_temp as usize,
                ),
                cb_item,
            ));
            ptr::copy(p_item.as_ptr(), p_temp, cb_item);
        }
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

    unsafe {
        ptr::copy(data.as_ptr().add(offset), data.as_mut_ptr(), pcb_data);
    }

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
