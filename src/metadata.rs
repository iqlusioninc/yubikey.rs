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

use std::marker::PhantomData;
use zeroize::Zeroizing;

use crate::{serialization::*, transaction::Transaction, Buffer, Error, Result};

#[cfg(feature = "untested")]
use crate::consts::{CB_OBJ_MAX, CB_OBJ_TAG_MAX};

#[cfg(feature = "untested")]
use std::iter;

const TAG_ADMIN: u8 = 0x80;
const TAG_PROTECTED: u8 = 0x88;
pub const OBJ_ADMIN_DATA: u32 = 0x005f_ff00;
pub const OBJ_PRINTED: u32 = 0x005f_c109;

pub(crate) trait MetadataType: private::Sealed {}

/// A type variable corresponding to PIN-protected metadata.
pub(crate) enum Protected {}
impl MetadataType for Protected {}

/// A type variable corresponding to administrative metadata.
pub(crate) enum Admin {}
impl MetadataType for Admin {}

/// Metadata stored in a YubiKey.
pub(crate) struct Metadata<T: MetadataType> {
    inner: Buffer,
    _marker: PhantomData<T>,
}

/// PIN-protected metadata stored in a YubiKey.
pub(crate) type ProtectedData = Metadata<Protected>;
/// Administrative metadata stored in a YubiKey.
pub(crate) type AdminData = Metadata<Admin>;

impl<T: MetadataType> Default for Metadata<T> {
    fn default() -> Self {
        Metadata {
            inner: Zeroizing::new(vec![]),
            _marker: PhantomData,
        }
    }
}

impl<T: MetadataType> Metadata<T> {
    /// Read metadata
    pub(crate) fn read(txn: &Transaction<'_>) -> Result<Self> {
        let data = txn.fetch_object(T::obj_id())?;
        Ok(Metadata {
            inner: Tlv::parse_single(data, T::tag())?,
            _marker: PhantomData,
        })
    }

    /// Write metadata
    #[cfg(feature = "untested")]
    #[cfg_attr(docsrs, doc(cfg(feature = "untested")))]
    pub(crate) fn write(&self, txn: &Transaction<'_>) -> Result<()> {
        if self.inner.len() > CB_OBJ_MAX - CB_OBJ_TAG_MAX {
            return Err(Error::GenericError);
        }

        if self.inner.is_empty() {
            return Self::delete(txn);
        }

        let mut buf = Zeroizing::new(vec![0u8; CB_OBJ_MAX]);
        let len = Tlv::write(&mut buf, T::tag(), &self.inner)?;

        txn.save_object(T::obj_id(), &buf[..len])
    }

    /// Delete metadata
    #[cfg(feature = "untested")]
    #[cfg_attr(docsrs, doc(cfg(feature = "untested")))]
    pub(crate) fn delete(txn: &Transaction<'_>) -> Result<()> {
        txn.save_object(T::obj_id(), &[])
    }

    /// Get metadata item
    pub(crate) fn get_item(&self, tag: u8) -> Result<&[u8]> {
        let mut data = &self.inner[..];

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
    #[cfg_attr(docsrs, doc(cfg(feature = "untested")))]
    pub(crate) fn set_item(&mut self, tag: u8, item: &[u8]) -> Result<()> {
        let mut cb_temp: usize = 0;
        let mut tag_temp: u8 = 0;
        let mut cb_len: usize = 0;

        let mut offset = 0;

        while offset < self.inner.len() {
            tag_temp = self.inner[offset];
            offset += 1;

            cb_len = get_length(&self.inner[offset..], &mut cb_temp);
            offset += cb_len;

            if tag_temp == tag {
                break;
            }

            offset += cb_temp;
        }

        if tag_temp != tag {
            if item.is_empty() {
                // We've been asked to delete an existing item that isn't in the blob
                return Ok(());
            }

            // We did not find an existing tag, append
            assert_eq!(offset, self.inner.len());
            self.inner
                .extend(iter::repeat(0).take(1 + get_length_size(item.len()) + item.len()));
            Tlv::write(&mut self.inner[offset..], tag, item)?;

            return Ok(());
        }

        // Found tag

        // Check length, if it matches, overwrite
        if cb_temp == item.len() {
            self.inner[offset..offset + item.len()].copy_from_slice(item);
            return Ok(());
        }

        // Length doesn't match, expand/shrink to fit
        let next_offset = offset + cb_temp;
        // Must be signed to have negative offsets
        let cb_moved: isize = (item.len() as isize - cb_temp as isize)
            + if item.is_empty() {
                // For tag, if deleting
                -1
            } else {
                get_length_size(item.len()) as isize
            }
            // Accounts for different length encoding
            - cb_len as isize;

        // If length would cause buffer overflow, return error
        if (self.inner.len() as isize + cb_moved) as usize > CB_OBJ_MAX {
            return Err(Error::GenericError);
        }

        // Move remaining data
        let orig_len = self.inner.len();
        if cb_moved > 0 {
            self.inner.extend(iter::repeat(0).take(cb_moved as usize));
        }
        self.inner.copy_within(
            next_offset..orig_len,
            (next_offset as isize + cb_moved) as usize,
        );
        self.inner
            .resize((orig_len as isize + cb_moved) as usize, 0);

        // Re-encode item and insert
        if !item.is_empty() {
            offset -= cb_len;
            offset += set_length(&mut self.inner[offset..], item.len())?;
            self.inner[offset..offset + item.len()].copy_from_slice(item);
        }

        Ok(())
    }
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

mod private {
    use super::*;
    pub trait Sealed {
        fn tag() -> u8;
        fn obj_id() -> u32;
    }
    impl Sealed for Protected {
        fn tag() -> u8 {
            TAG_PROTECTED
        }
        fn obj_id() -> u32 {
            OBJ_PRINTED
        }
    }
    impl Sealed for Admin {
        fn tag() -> u8 {
            TAG_ADMIN
        }
        fn obj_id() -> u32 {
            OBJ_ADMIN_DATA
        }
    }
}
