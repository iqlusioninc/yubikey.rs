//! Application Protocol Data Unit (APDU)

use zeroize::Zeroize;

/// Application Protocol Data Unit (APDU).
///
/// These messages are packets used to communicate with the YubiKey using the
/// Chip Card Interface Device (CCID) protocol.
#[derive(Clone)]
pub struct APDU {
    /// Instruction class - indicates the type of command, e.g. interindustry or proprietary
    pub cla: u8,

    /// Instruction code - indicates the specific command, e.g. "write data"
    pub ins: u8,

    /// Instruction parameter 1 for the command, e.g. offset into file at which to write the data
    pub p1: u8,

    /// Instruction parameter 2 for the command
    pub p2: u8,

    /// Length of command - encodes the number of bytes of command data to follow
    pub lc: u8,

    /// Command data
    pub data: [u8; 255],
}

impl APDU {
    /// Get a const pointer to this APDU
    // TODO(tarcieri): eliminate pointers and use all safe references
    pub(crate) fn as_ptr(&self) -> *const APDU {
        self
    }

    /// Get a mut pointer to this APDU
    // TODO(tarcieri): eliminate pointers and use all safe references
    pub(crate) fn as_mut_ptr(&mut self) -> *mut APDU {
        self
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
