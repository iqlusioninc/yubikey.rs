//! Application Protocol Data Unit (APDU)

use crate::{error::Error, response::Response, transaction::Transaction, Buffer};
use std::fmt::{self, Debug};
use zeroize::{Zeroize, Zeroizing};

/// Size of a serialized APDU (5 byte header + 255 bytes data)
pub const APDU_SIZE: usize = 260;

/// Application Protocol Data Unit (APDU).
///
/// These messages are packets used to communicate with the YubiKey using the
/// Chip Card Interface Device (CCID) protocol.
#[derive(Clone)]
pub(crate) struct APDU {
    /// Instruction class - indicates the type of command, e.g. interindustry or proprietary
    cla: u8,

    /// Instruction code - indicates the specific command, e.g. "write data"
    ins: u8,

    /// Instruction parameter 1 for the command, e.g. offset into file at which to write the data
    p1: u8,

    /// Instruction parameter 2 for the command
    p2: u8,

    /// Length of command - encodes the number of bytes of command data to follow
    lc: u8,

    /// Command data
    data: [u8; 255],
}

impl APDU {
    /// Create a new APDU with the given instruction code
    pub fn new(ins: u8) -> Self {
        let mut apdu = Self::default();
        apdu.ins = ins;
        apdu
    }

    /// Set this APDU's class
    pub fn cla(&mut self, value: u8) -> &mut Self {
        self.cla = value;
        self
    }

    /// Set this APDU's first parameter only
    pub fn p1(&mut self, value: u8) -> &mut Self {
        self.p1 = value;
        self
    }

    /// Set both parameters for this APDU
    pub fn params(&mut self, p1: u8, p2: u8) -> &mut Self {
        self.p1 = p1;
        self.p2 = p2;
        self
    }

    /// Set the command data for this APDU.
    ///
    /// Panics if the byte slice is more than 255 bytes!
    pub fn data(&mut self, bytes: impl AsRef<[u8]>) -> &mut Self {
        assert_eq!(self.lc, 0, "APDU command already set!");

        let bytes = bytes.as_ref();

        assert!(
            bytes.len() <= self.data.len(),
            "APDU command data too large: {}-bytes",
            bytes.len()
        );

        self.lc = bytes.len() as u8;
        self.data[..bytes.len()].copy_from_slice(bytes);

        self
    }

    /// Transmit this APDU using the given card transaction
    pub fn transmit(&self, txn: &Transaction<'_>, recv_len: usize) -> Result<Response, Error> {
        let response_bytes = txn.transmit(&self.to_bytes(), recv_len)?;
        Ok(Response::from_bytes(response_bytes))
    }

    /// Consume this APDU and return a self-zeroizing buffer
    pub fn to_bytes(&self) -> Buffer {
        let mut bytes = Vec::with_capacity(APDU_SIZE);
        bytes.push(self.cla);
        bytes.push(self.ins);
        bytes.push(self.p1);
        bytes.push(self.p2);
        bytes.push(self.lc);
        bytes.extend_from_slice(self.data.as_ref());

        Zeroizing::new(bytes)
    }
}

impl Debug for APDU {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "APDU {{ cla: {}, ins: {}, p1: {}, p2: {}, lc: {}, data: {:?} }}",
            self.cla,
            self.ins,
            self.p1,
            self.p2,
            self.lc,
            &self.data[..]
        )
    }
}

impl Default for APDU {
    fn default() -> Self {
        Self {
            cla: 0,
            ins: 0,
            p1: 0,
            p2: 0,
            lc: 0,
            data: [0u8; 255],
        }
    }
}

impl Drop for APDU {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for APDU {
    fn zeroize(&mut self) {
        self.cla.zeroize();
        self.ins.zeroize();
        self.p1.zeroize();
        self.p2.zeroize();
        self.lc.zeroize();
        self.data.zeroize();
    }
}
