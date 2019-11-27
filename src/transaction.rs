//! YubiKey PC/SC transactions

use crate::{
    apdu::{Ins, APDU},
    error::Error,
    yubikey::*,
};
#[cfg(feature = "untested")]
use crate::{
    apdu::{Response, StatusWords},
    consts::*,
    mgm::MgmKey,
    serialization::*,
    Buffer, ObjectId,
};
use log::{error, trace};
use std::convert::TryInto;
#[cfg(feature = "untested")]
use std::ptr;
#[cfg(feature = "untested")]
use zeroize::Zeroizing;

/// Exclusive transaction with the YubiKey's PC/SC card.
pub(crate) struct Transaction<'tx> {
    inner: pcsc::Transaction<'tx>,
}

impl<'tx> Transaction<'tx> {
    /// Create a new transaction with the given card
    pub fn new(card: &'tx mut pcsc::Card) -> Result<Self, Error> {
        Ok(Transaction {
            inner: card.transaction()?,
        })
    }

    /// Get an attribute of the card or card reader.
    pub fn get_attribute<'buf>(
        &self,
        attribute: pcsc::Attribute,
        buffer: &'buf mut [u8],
    ) -> Result<&'buf [u8], Error> {
        Ok(self.inner.get_attribute(attribute, buffer)?)
    }

    /// Transmit a single serialized APDU to the card this transaction is open
    /// with and receive a response.
    ///
    /// This is a wrapper for the raw `SCardTransmit` function and operates on
    /// single APDU messages at a time. For larger messages that need to be
    /// split into multiple APDUs, use the [`Transaction::transfer_data`]
    /// method instead.
    pub fn transmit(&self, send_buffer: &[u8], recv_len: usize) -> Result<Vec<u8>, Error> {
        trace!(">>> {:?}", send_buffer);

        let mut recv_buffer = vec![0u8; recv_len];

        let len = self
            .inner
            .transmit(send_buffer, recv_buffer.as_mut())?
            .len();

        recv_buffer.truncate(len);
        Ok(recv_buffer)
    }

    /// Select application.
    pub fn select_application(&self) -> Result<(), Error> {
        let response = APDU::new(Ins::SelectApplication)
            .p1(0x04)
            .data(&AID)
            .transmit(self, 0xFF)
            .map_err(|e| {
                error!("failed communicating with card: '{}'", e);
                e
            })?;

        if !response.is_success() {
            error!(
                "failed selecting application: {:04x}",
                response.status_words().code()
            );
            return Err(Error::GenericError);
        }

        Ok(())
    }

    /// Get the version of the PIV application installed on the YubiKey
    pub fn get_version(&self) -> Result<Version, Error> {
        // get version from device
        let response = APDU::new(Ins::GetVersion).transmit(self, 261)?;

        if !response.is_success() {
            return Err(Error::GenericError);
        }

        if response.data().len() < 3 {
            return Err(Error::SizeError);
        }

        Ok(Version::new(response.data()[..3].try_into().unwrap()))
    }

    /// Get YubiKey device serial number
    pub fn get_serial(&self, version: Version) -> Result<Serial, Error> {
        let yk_applet = [0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x01];

        let response = if version.major < 5 {
            // get serial from neo/yk4 devices using the otp applet
            let sw = APDU::new(Ins::SelectApplication)
                .p1(0x04)
                .data(&yk_applet)
                .transmit(self, 0xFF)?
                .status_words();

            if !sw.is_success() {
                error!("failed selecting yk application: {:04x}", sw.code());
                return Err(Error::GenericError);
            }

            let resp = APDU::new(0x01).p1(0x10).transmit(self, 0xFF)?;

            if !resp.is_success() {
                error!(
                    "failed retrieving serial number: {:04x}",
                    resp.status_words().code()
                );
                return Err(Error::GenericError);
            }

            // reselect the PIV applet
            let sw = APDU::new(Ins::SelectApplication)
                .p1(0x04)
                .data(&AID)
                .transmit(self, 0xFF)?
                .status_words();

            if !sw.is_success() {
                error!("failed selecting application: {:04x}", sw.code());
                return Err(Error::GenericError);
            }

            resp
        } else {
            // get serial from yk5 and later devices using the f8 command
            let resp = APDU::new(Ins::GetSerial).transmit(self, 0xFF)?;

            if !resp.is_success() {
                error!(
                    "failed retrieving serial number: {:04x}",
                    resp.status_words().code()
                );
                return Err(Error::GenericError);
            }

            resp
        };

        response.data()[..4]
            .try_into()
            .map(|serial| Serial::from(u32::from_be_bytes(serial)))
            .map_err(|_| Error::SizeError)
    }

    /// Verify device PIN.
    #[cfg(feature = "untested")]
    pub fn verify_pin(&self, pin: &[u8]) -> Result<(), Error> {
        // TODO(tarcieri): allow unpadded (with `0xFF`) PIN shorter than CB_PIN_MAX?
        if pin.len() != CB_PIN_MAX {
            return Err(Error::SizeError);
        }

        let response = APDU::new(Ins::Verify)
            .params(0x00, 0x80)
            .data(pin)
            .transmit(self, 261)?;

        match response.status_words() {
            StatusWords::Success => Ok(()),
            StatusWords::AuthBlockedError => Err(Error::WrongPin { tries: 0 }),
            StatusWords::Other(sw) if sw >> 8 == 0x63 => Err(Error::WrongPin { tries: sw & 0xf }),
            _ => Err(Error::GenericError),
        }
    }

    /// Change the PIN
    #[cfg(feature = "untested")]
    pub fn change_pin(&self, action: i32, current_pin: &[u8], new_pin: &[u8]) -> Result<(), Error> {
        let mut templ = [0, Ins::ChangeReference.code(), 0, 0x80];
        let mut indata = Zeroizing::new([0u8; 16]);

        if current_pin.len() > CB_PIN_MAX || new_pin.len() > CB_PIN_MAX {
            return Err(Error::SizeError);
        }

        if action == CHREF_ACT_UNBLOCK_PIN {
            templ[1] = Ins::ResetRetry.code();
        } else if action == CHREF_ACT_CHANGE_PUK {
            templ[3] = 0x81;
        }

        unsafe {
            ptr::copy(current_pin.as_ptr(), indata.as_mut_ptr(), current_pin.len());

            if current_pin.len() < CB_PIN_MAX {
                ptr::write_bytes(
                    indata.as_mut_ptr().add(current_pin.len()),
                    0xff,
                    CB_PIN_MAX - current_pin.len(),
                );
            }

            ptr::copy(
                new_pin.as_ptr(),
                indata.as_mut_ptr().offset(8),
                new_pin.len(),
            );

            if new_pin.len() < CB_PIN_MAX {
                ptr::write_bytes(
                    indata.as_mut_ptr().offset(8).add(new_pin.len()),
                    0xff,
                    CB_PIN_MAX - new_pin.len(),
                );
            }
        }

        let status_words = self
            .transfer_data(&templ, indata.as_ref(), 0xFF)?
            .status_words();

        match status_words {
            StatusWords::Success => Ok(()),
            StatusWords::AuthBlockedError => Err(Error::PinLocked),
            StatusWords::Other(sw) if sw >> 8 == 0x63 => Err(Error::WrongPin { tries: sw & 0xf }),
            _ => {
                error!(
                    "failed changing pin, token response code: {:x}.",
                    status_words.code()
                );
                Err(Error::GenericError)
            }
        }
    }

    /// Set the management key (MGM).
    #[cfg(feature = "untested")]
    pub fn set_mgm_key(&self, new_key: &MgmKey, touch: Option<u8>) -> Result<(), Error> {
        let p2 = match touch.unwrap_or_default() {
            0 => 0xff,
            1 => 0xfe,
            _ => {
                return Err(Error::GenericError);
            }
        };

        let mut data = [0u8; DES_LEN_3DES + 3];
        data[0] = YKPIV_ALGO_3DES;
        data[1] = YKPIV_KEY_CARDMGM;
        data[2] = DES_LEN_3DES as u8;
        data[3..3 + DES_LEN_3DES].copy_from_slice(new_key.as_ref());

        let status_words = APDU::new(Ins::SetMgmKey)
            .params(0xff, p2)
            .data(&data)
            .transmit(self, 261)?
            .status_words();

        if !status_words.is_success() {
            return Err(Error::GenericError);
        }

        Ok(())
    }

    /// Perform a YubiKey operation which requires authentication.
    ///
    /// This is the common backend for all public key encryption and signing
    /// operations.
    // TODO(tarcieri): refactor this to be less gross/coupled.
    #[cfg(feature = "untested")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn authenticated_command(
        &self,
        sign_in: &[u8],
        algorithm: u8,
        key: u8,
        decipher: bool,
    ) -> Result<Buffer, Error> {
        let in_len = sign_in.len();
        let mut indata = [0u8; 1024];
        let templ = [0, Ins::Authenticate.code(), algorithm, key];
        let mut len: usize = 0;

        match algorithm {
            YKPIV_ALGO_RSA1024 | YKPIV_ALGO_RSA2048 => {
                let key_len = if algorithm == YKPIV_ALGO_RSA1024 {
                    128
                } else {
                    256
                };

                if in_len != key_len {
                    return Err(Error::SizeError);
                }
            }
            YKPIV_ALGO_ECCP256 | YKPIV_ALGO_ECCP384 => {
                let key_len = if algorithm == YKPIV_ALGO_ECCP256 {
                    32
                } else {
                    48
                };

                if (!decipher && (in_len > key_len)) || (decipher && (in_len != (key_len * 2) + 1))
                {
                    return Err(Error::SizeError);
                }
            }
            _ => return Err(Error::AlgorithmError),
        }

        let bytes = if in_len < 0x80 {
            1
        } else if in_len < 0xff {
            2
        } else {
            3
        };

        indata[0] = 0x7c;
        let mut offset = 1 + set_length(&mut indata[1..], in_len + bytes + 3);
        indata[offset] = 0x82;
        indata[offset + 1] = 0x00;
        indata[offset + 2] =
            if (algorithm == YKPIV_ALGO_ECCP256 || algorithm == YKPIV_ALGO_ECCP384) && decipher {
                0x85
            } else {
                0x81
            };

        offset += 3;
        offset += set_length(&mut indata[offset..], in_len);
        indata[offset..(offset + in_len)].copy_from_slice(sign_in);
        offset += in_len;

        let response = self
            .transfer_data(&templ, &indata[..offset], 1024)
            .map_err(|e| {
                error!("sign command failed to communicate: {}", e);
                e
            })?;

        if !response.is_success() {
            error!("failed sign command with code {:x}", response.code());

            if response.status_words() == StatusWords::SecurityStatusError {
                return Err(Error::AuthenticationError);
            } else {
                return Err(Error::GenericError);
            }
        }

        let data = response.data();

        // skip the first 7c tag
        if data[0] != 0x7c {
            error!("failed parsing signature reply (0x7c byte)");
            return Err(Error::ParseError);
        }

        let mut offset = 1 + get_length(&data[1..], &mut len);

        // skip the 82 tag
        if data[offset] != 0x82 {
            error!("failed parsing signature reply (0x82 byte)");
            return Err(Error::ParseError);
        }

        offset += 1;
        offset += get_length(&data[offset..], &mut len);
        Ok(Buffer::new(data[offset..(offset + len)].into()))
    }

    /// Send/receive large amounts of data to/from the YubiKey, splitting long
    /// messages into smaller APDU-sized messages (using the provided APDU
    /// template to construct them), and then sending those via
    /// [`Transaction::transmit`].
    #[cfg(feature = "untested")]
    pub fn transfer_data(
        &self,
        templ: &[u8],
        in_data: &[u8],
        max_out: usize,
    ) -> Result<Response, Error> {
        let mut in_offset = 0;
        let mut out_data = vec![];
        let mut sw = 0;

        loop {
            let mut this_size = 0xff;

            let cla = if in_offset + 0xff < in_data.len() {
                0x10
            } else {
                this_size = in_data.len() - in_offset;
                templ[0]
            };

            trace!("going to send {} bytes in this go", this_size);

            let response = APDU::new(templ[1])
                .cla(cla)
                .params(templ[2], templ[3])
                .data(&in_data[in_offset..(in_offset + this_size)])
                .transmit(self, 261)?;

            if !response.is_success() && (response.status_words().code() >> 8 != 0x61) {
                // TODO(tarcieri): is this really OK?
                return Ok(Response::new(sw.into(), out_data));
            }

            sw = response.status_words().code();

            if !out_data.is_empty() && (out_data.len() - response.data().len() > max_out) {
                error!(
                    "output buffer too small: wanted to write {}, max was {}",
                    out_data.len() - response.data().len(),
                    max_out
                );

                return Err(Error::SizeError);
            }

            out_data.extend_from_slice(&response.data()[..response.data().len()]);

            in_offset += this_size;
            if in_offset >= in_data.len() {
                break;
            }
        }

        while sw >> 8 == 0x61 {
            trace!(
                "The card indicates there is {} bytes more data for us",
                sw & 0xff
            );

            let response = APDU::new(Ins::GetResponseApdu).transmit(self, 261)?;
            sw = response.status_words().code();

            if sw != StatusWords::Success.code() && (sw >> 8 != 0x61) {
                return Ok(Response::new(sw.into(), vec![]));
            }

            if out_data.len() + response.data().len() > max_out {
                error!(
                    "output buffer too small: wanted to write {}, max was {}",
                    out_data.len() + response.data().len(),
                    max_out
                );

                return Err(Error::SizeError);
            }

            out_data.extend_from_slice(&response.data()[..response.data().len()]);
        }

        Ok(Response::new(sw.into(), out_data))
    }

    /// Fetch an object
    #[cfg(feature = "untested")]
    pub fn fetch_object(&self, object_id: ObjectId) -> Result<Buffer, Error> {
        let mut indata = [0u8; 5];
        let templ = [0, Ins::GetData.code(), 0x3f, 0xff];

        let mut inlen = indata.len();
        let indata_remaining = set_object(object_id, &mut indata);
        inlen -= indata_remaining.len();

        let response = self.transfer_data(&templ, &indata[..inlen], CB_BUF_MAX)?;

        if !response.is_success() {
            return Err(Error::GenericError);
        }

        let data = Buffer::new(response.data().into());
        let mut outlen = 0;

        if data.len() < 2 || !has_valid_length(&data[1..], data.len() - 1) {
            return Err(Error::SizeError);
        }

        let offs = get_length(&data[1..], &mut outlen);

        if offs == 0 {
            return Err(Error::SizeError);
        }

        if outlen + offs + 1 != data.len() {
            error!(
                "invalid length indicated in object: total len is {} but indicated length is {}",
                data.len(),
                outlen
            );

            return Err(Error::SizeError);
        }

        Ok(Zeroizing::new(
            data[(1 + offs)..(1 + offs + outlen)].to_vec(),
        ))
    }

    /// Save an object
    #[cfg(feature = "untested")]
    pub fn save_object(&self, object_id: ObjectId, indata: &[u8]) -> Result<(), Error> {
        let templ = [0, Ins::PutData.code(), 0x3f, 0xff];

        // TODO(tarcieri): replace with vector
        let mut data = [0u8; CB_BUF_MAX];

        if indata.len() > CB_OBJ_MAX {
            return Err(Error::SizeError);
        }

        let mut len = data.len();
        let mut data_remaining = set_object(object_id, &mut data);

        data_remaining[0] = 0x53;
        data_remaining = &mut data_remaining[1..];

        let offset = set_length(data_remaining, indata.len());
        data_remaining = &mut data_remaining[offset..];
        data_remaining[..indata.len()].copy_from_slice(indata);

        data_remaining = &mut data_remaining[indata.len()..];
        len -= data_remaining.len();

        let status_words = self
            .transfer_data(&templ, &data[..len], 255)?
            .status_words();

        match status_words {
            StatusWords::Success => Ok(()),
            StatusWords::SecurityStatusError => Err(Error::AuthenticationError),
            _ => Err(Error::GenericError),
        }
    }
}
