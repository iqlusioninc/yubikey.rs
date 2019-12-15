//! Enums representing key policies.

use crate::{error::Error, serialization::Tlv};

/// Specifies how often the PIN needs to be entered for access to the credential in a
/// given slot. This policy must be set upon key generation or importation, and cannot be
/// changed later.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PinPolicy {
    /// Use the default PIN policy for the slot. See the slot's documentation for details.
    Default,

    /// The end user PIN is **NOT** required to perform private key operations.
    Never,

    /// The end user PIN is required to perform any private key operations. Once the
    /// correct PIN has been provided, multiple private key operations may be performed
    /// without additional cardholder consent.
    Once,

    /// The end user PIN is required to perform any private key operations. The PIN must
    /// be submitted immediately before each operation to ensure cardholder participation.
    Always,
}

impl From<PinPolicy> for u8 {
    fn from(policy: PinPolicy) -> u8 {
        match policy {
            PinPolicy::Default => 0,
            PinPolicy::Never => 1,
            PinPolicy::Once => 2,
            PinPolicy::Always => 3,
        }
    }
}

impl PinPolicy {
    /// Writes the `PinPolicy` in the format the YubiKey expects during key generation or
    /// importation.
    pub(crate) fn write(self, buf: &mut [u8]) -> Result<usize, Error> {
        match self {
            PinPolicy::Default => Ok(0),
            _ => Tlv::write(buf, 0xaa, &[self.into()]),
        }
    }
}

/// Specifies under what conditions a physical touch on the metal contact is required, in
/// addition to the [`PinPolicy`]. This policy must be set upon key generation or
/// importation, and cannot be changed later.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TouchPolicy {
    /// Use the default touch policy for the slot.
    Default,

    /// A physical touch is **NOT** required to perform private key operations.
    Never,

    /// A physical touch is required to perform any private key operations. The metal
    /// contact must be touched during each operation to ensure cardholder participation.
    Always,

    /// A physical touch is required to perform any private key operations. Each touch
    /// is cached for 15 seconds, during which time multiple private key operations may be
    /// performed without additional cardholder interaction. After 15 seconds the cached
    /// touch is cleared, and further operations require another physical touch.
    Cached,
}

impl From<TouchPolicy> for u8 {
    fn from(policy: TouchPolicy) -> u8 {
        match policy {
            TouchPolicy::Default => 0,
            TouchPolicy::Never => 1,
            TouchPolicy::Always => 2,
            TouchPolicy::Cached => 3,
        }
    }
}

impl TouchPolicy {
    /// Writes the `TouchPolicy` in the format the YubiKey expects during key generation
    /// or importation.
    pub(crate) fn write(self, buf: &mut [u8]) -> Result<usize, Error> {
        match self {
            TouchPolicy::Default => Ok(0),
            _ => Tlv::write(buf, 0xab, &[self.into()]),
        }
    }
}
